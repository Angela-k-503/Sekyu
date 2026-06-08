import { argon2id } from 'https://cdn.jsdelivr.net/npm/hash-wasm@4.11.0/+esm';
import { cryptoSession } from './cryptoSession.js';

// GLOBAL STATE & LIFECYCLE TRACKERS
let sessionTimeoutId = null;
let tokenExpirationTime = null;

// DATA TYPE & HEX CONVERSION UTILITIES
const toHex = (buf) => Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');

const fromHex = hexString => {
    if (!hexString || typeof hexString !== 'string' || hexString.length % 2 !== 0) {
        console.error("fromHex error: Invalid hex string.");
        return new Uint8Array(0);
    }
    const view = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < view.length; i++) {
        view[i] = parseInt(hexString.substr(i * 2, 2), 16);
    }
    return view;
};

async function hashMatchRef(str) {
    const msgUint8 = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// CORE CRYPTOGRAPHIC PIPELINES
async function deriveKeysAndTokens(password, customSalt) {
    const salt = customSalt ? fromHex(customSalt) : crypto.getRandomValues(new Uint8Array(16));
    
    const rawhash = await argon2id({
        password: password,
        salt: salt,
        parallelism: 4,
        iterations: 5,
        memorySize: 65536,
        hashLength: 32,
        outputType: 'binary'
    });

    const kek = await crypto.subtle.importKey(       
        "raw",
        rawhash,
        "AES-GCM",
        false,
        ["wrapKey", "unwrapKey"]
    );

    return {
        saltHex: toHex(salt),
        hashHex: toHex(rawhash),
        kek,
    };
}

async function secureWrapDEK(kek, dekObject) {
    const wrappingIv = crypto.getRandomValues(new Uint8Array(12));

    const wrappedDekBuffer = await crypto.subtle.wrapKey(
        "raw",
        dekObject,
        kek,
        { 
            name: "AES-GCM", 
            iv: wrappingIv 
        }
    );

    const wrappedDekBytes = new Uint8Array(wrappedDekBuffer);
    const combinedPayload = new Uint8Array(wrappingIv.length + wrappedDekBytes.length);
    
    combinedPayload.set(wrappingIv, 0);
    combinedPayload.set(wrappedDekBytes, wrappingIv.length);

    return toHex(combinedPayload);
}

async function decryptDEK(encryptedDekHex, kek, isExtractable = false) {
    const encryptedDekBytes = fromHex(encryptedDekHex);

    const iv = encryptedDekBytes.slice(0, 12);
    const encryptedBytes = encryptedDekBytes.slice(12);

    try {
        const importedKey = await crypto.subtle.unwrapKey(
            "raw",
            encryptedBytes,
            kek,
            { name: "AES-GCM", iv },
            "AES-GCM",
            isExtractable,
            ["encrypt", "decrypt"]
        );

        return importedKey;

    } catch (err) {
        console.error("DEK Unwrapping failed. Invalid key or compromised ciphertext tag.", err);
        throw new Error("Integrity check failed: Unwrapping rejected.");
    }
}

async function encryptVaultPassword(plainTextPassword, dek) {
    if (!(dek instanceof CryptoKey)) {
        throw new TypeError("Expected DEK to be a valid CryptoKey object");
    }
    
    const plainTextBytes = new TextEncoder().encode(plainTextPassword);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        dek, 
        plainTextBytes
    );

    const ciphertextBytes = new Uint8Array(encryptedBuffer);

    const ciphertext = new Uint8Array(iv.length + ciphertextBytes.length);
    ciphertext.set(iv, 0);
    ciphertext.set(ciphertextBytes, iv.length);

    return toHex(ciphertext);
}

async function decryptVaultPassword(dek, ciphertextHex) {
    const ciphertextBytes = fromHex(ciphertextHex);

    const iv = ciphertextBytes.slice(0, 12);
    const encryptedBytes = ciphertextBytes.slice(12);

    try {
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            dek,
            encryptedBytes
        );

        return new Uint8Array(decryptedBuffer);

    } catch (err) {
        console.error("Decryption failed. Invalid key or compromised ciphertext tag.1", err);
        throw new Error("Integrity check failed: Decryption rejected.");
    }
}


// NETWORK BOUNDARY & ROUTING INTERCEPTORS
async function secureFetch(url, options = {}) {
    if (tokenExpirationTime && Date.now() >= tokenExpirationTime) {
        await handleForcedLogout();
        throw new Error("Session expired client-side");
    }

    const headers = { ...(options.headers || {}) };
    const csrfToken = getCookie('csrf_access_token');
    if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
    }

    const response = await fetch(url, {
        ...options,
        credentials: 'include',
        headers
    });

    if (response.status === 401) {
        const payload = await response.json().catch(() => ({}));
        const serverErrorMessage = payload.error || "Session unauthorized or expired.";
        await handleForcedLogout();
        throw new Error(serverErrorMessage);
    }

    return response;
}

// UNIFIED TERMINATION & SESSION CLEANUP
function startSessionCountdown(durationInMinutes) {
    const durationInMs = durationInMinutes * 60 * 1000;
    const absoluteExpiryTime = Date.now() + durationInMs;

    // Persist timestamp state across client-side memory reloads
    sessionStorage.setItem('tokenExpirationTime', absoluteExpiryTime);
    tokenExpirationTime = absoluteExpiryTime;

    if (sessionTimeoutId) clearTimeout(sessionTimeoutId);
    
    sessionTimeoutId = setTimeout(async () => {
        sessionTimeoutId = null;
        alert("Your 15-minute security session has ended. Please log in again.");
        const logOutBtn = document.getElementById('logOutBtn');
        if (logOutBtn) {
            const logOutUrl = logOutBtn.getAttribute('data-url');
            if (logOutUrl) {
                try {
                    await secureFetch(logOutUrl, { 
                        method: 'DELETE', 
                        credentials: 'include' 
                    });
                } catch (err) {
                    console.warn("Could not reach backend to invalidate token on timeout:", err);
                }
            }
        }

        await handleForcedLogout();
        
    }, durationInMs);
}

async function handleForcedLogout() {

    cryptoSession.clearSession();
    sessionStorage.removeItem('tokenExpirationTime');
    tokenExpirationTime = null;

    if (sessionTimeoutId) {
        clearTimeout(sessionTimeoutId);
        sessionTimeoutId = null;
    }

    const container = document.getElementById('vaultEntriesContainer');
    if (container) {
        container.textContent = ""; 
        
        const placeholderDiv = document.createElement('div');
        placeholderDiv.className = 'mb-3 no-entries-placeholder';
        
        const textPara = document.createElement('p');
        textPara.textContent = 'No saved login credentials yet.';
        
        placeholderDiv.appendChild(textPara);
        container.appendChild(placeholderDiv);
    }

    document.querySelectorAll('.modal.show').forEach(m => { const inst = bootstrap.Modal.getInstance(m); if (inst) inst.hide(); });
    document.querySelectorAll('.modal-backdrop').forEach(b => b.remove());

    document.getElementById("loginForm")?.reset();
    document.getElementById("registerForm")?.reset();
    document.getElementById("entryForm")?.reset();
    document.getElementById("verifyPasswordForm")?.reset();
    document.getElementById("patchPasswordForm")?.reset();
    document.getElementById("entryUpdateForm")?.reset();

    const errorsToClear = [
        'loginError', 'registerError', 'createVaultError', 
        'verifyError', 'patchError', 'globalVerifyError'
    ];
    errorsToClear.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '';
    });


    const authSection = document.getElementById('authSection');
    const appDashboard = document.getElementById('appDashboard');
    if (authSection) authSection.classList.remove('d-none');
    if (appDashboard) appDashboard.classList.add('d-none');

    const logOutBtn = document.getElementById('logOutBtn');
    if (logOutBtn) {
        logOutBtn.disabled = false;
    }
}

// PASSWORD STRENGTH & GENERATION ENGINES
function runSecureGenerator(length, includeSpecials) {
    const alphas = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    const specials = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let pool = alphas + numbers;
    if (includeSpecials) pool += specials;

    let password = "";
    const maxValidByte = Math.floor(256 / pool.length) * pool.length;
    
    // Process character selection byte-by-byte safely
    while (password.length < length) {
        const randBytes = new Uint8Array(1);
        window.crypto.getRandomValues(randBytes);
        const val = randBytes[0];
        
        // Rejection sampling removes modulo bias
        if (val < maxValidByte) {
            password += pool.charAt(val % pool.length);
        }
    }
    return password;
}

function initializePasswordGenerator(elements) {
    const { slider, box, tickContainer, passwordInput, fieldset, generateBtn, specialsCheckbox } = elements;

    if (!slider || !box || !passwordInput || !generateBtn) return;

    if (tickContainer && tickContainer.children.length === 0) {
        for (let i = 8; i <= 32; i += 4) {
            const mark = document.createElement('span');
            mark.textContent = i;
            tickContainer.appendChild(mark);
        }
    }

    slider.addEventListener('input', (e) => {
        box.value = e.target.value;
    });

    box.addEventListener('input', (e) => {
        let val = parseInt(e.target.value, 10) || 8;
        if (val > 32) val = 32; 
        if (val < 8) val = 8;
        slider.value = val;
    });


    generateBtn.addEventListener('click', () => {
        const currentPassword = passwordInput.value || "";

        if (currentPassword.trim().length > 0) {
            const confirmOverwrite = confirm("Are you sure? This will overwrite the password you already entered.");
            if (!confirmOverwrite) return; 
        }

        const length = parseInt(box.value, 10) || 16;
        const includeSpecials = specialsCheckbox ? specialsCheckbox.checked : true;
        
        passwordInput.value = runSecureGenerator(length, includeSpecials);

        passwordInput.dispatchEvent(new Event('input'));
    });
}

function checkStrength(inputElement) {
    if (!inputElement) return;

    const parentContainer = inputElement.parentElement;
    if (!parentContainer) return;

    const strengthText = parentContainer.querySelector('.strength-text');
    if (!strengthText) return;

    const pw = inputElement.value;

    if (!pw || !pw.trim()) {
        strengthText.innerText = ""; 
        return;
    }

    let score = 0;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;

    if (score <= 1) {
        strengthText.innerText = "(weak)";
        strengthText.className = "strength-text ms-1 fw-bold text-danger";
    } else if (score === 2) {
        strengthText.innerText = "(medium)";
        strengthText.className = "strength-text ms-1 fw-bold text-warning";
    } else if (score >= 3) {
        strengthText.innerText = "(strong)";
        strengthText.className = "strength-text ms-1 fw-bold text-success";
    }
}

// VAULT DISPLAY AND PRESENTATION LAYER
async function decryptAndPopulateDashboard(entries, clearContainer = true) {
    const container = document.getElementById('vaultEntriesContainer');
    const template = document.getElementById('entryTemplate');
    if (!container || !template) return;

    if (clearContainer) {
        while (container.firstChild) {
            container.removeChild(container.firstChild);
        }
    } else {
        const placeholder = container.querySelector('.no-entries-placeholder');
        if (placeholder) placeholder.remove();
    }

    if (!entries || entries.length === 0) {
        container.textContent = '';

        const placeholderDiv = document.createElement('div');
        placeholderDiv.className = 'mb-3 no-entries-placeholder';
        
        const textPara = document.createElement('p');
        textPara.className = 'text-muted m-0';
        textPara.textContent = 'No saved login credentials yet.';
        
        placeholderDiv.appendChild(textPara);
        container.appendChild(placeholderDiv);
        return;
    }

    entries.forEach(entry => {
        const clone = template.content.cloneNode(true);
        const uniqueModalId = `updateEntryModal_${entry.id}`;
        const modalContainer = clone.querySelector('.entry-modal-container');
        const editTriggerBtn = clone.querySelector('.btn-edit-trigger');
        
        if (modalContainer && editTriggerBtn) {
            modalContainer.id = uniqueModalId;
            editTriggerBtn.setAttribute('data-bs-target', `#${uniqueModalId}`);
            modalContainer.setAttribute('data-entry-id', entry.id);
        }

        clone.querySelector('.entry-website').textContent = entry.website;
        clone.querySelector('.entry-username').textContent = entry.username;
        clone.querySelector('.entry-website-title-span').textContent = entry.website;

        const passwordDisplay = clone.querySelector('.entry-password-display');
        passwordDisplay.setAttribute('data-ciphertext', entry.ciphertext);

        clone.querySelector('.btn-delete-action')?.setAttribute('data-entry-id', entry.id);
        clone.querySelector('.btn-save-modal-action')?.setAttribute('data-entry-id', entry.id);

        initializePasswordGenerator({
            slider: clone.querySelector('.template-slider'),
            box: clone.querySelector('.template-box'),
            tickContainer: clone.querySelector('.template-tick-container'),
            passwordInput: clone.querySelector('.field-password'), 
            fieldset: clone.querySelector('.template-generator-options'),
            generateBtn: clone.querySelector('.template-generate-trigger'),
            specialsCheckbox: clone.querySelector('.template-specials')
        });

        const updatedPasswordField = clone.querySelector('.field-password');
        if (updatedPasswordField) {
            updatedPasswordField.addEventListener('input', (e) => {
                checkStrength(e.target);
            });
        }

        container.appendChild(clone);
    });
}

// HANDLE TRANSITION FROM AUTH UI TO VAULT UI
async function initializeAndLoadDashboard(payload) {
    try {
        const { masterUsername, entries } = payload;

        const welcomeSpan = document.querySelector('.display-current-username');
        const profileModalStrong = document.getElementById('modalUsername');
        
        if (welcomeSpan) welcomeSpan.textContent = masterUsername || "User";
        if (profileModalStrong) profileModalStrong.textContent = masterUsername || "Unknown";

        const authSection = document.getElementById('authSection');
        const appDashboard = document.getElementById('appDashboard');
        
        if (authSection) authSection.classList.add('d-none');
        if (appDashboard) appDashboard.classList.remove('d-none');

        await decryptAndPopulateDashboard(entries, true);
        
    } catch (error) {
        console.error("Failed to initialize dashboard layout:", error);
    }
}

// FORCE RE-AUTHENTICATION
async function openVerificationModal(reasonText = "Authentication required.") {
    return new Promise((resolve, reject) => {
        let wasResolved = false; 

        const reasonEl = document.getElementById('globalVerifyReasonText');
        if (reasonEl) reasonEl.textContent = reasonText;

        const modalEl = document.getElementById('globalVerifyModal');
        const verifyForm = document.getElementById('globalVerifyForm');
        const passwordInput = document.getElementById('globalCurrentPassword');
        const errorEl = document.getElementById('globalVerifyError');

        if (errorEl) errorEl.textContent = "";
        if (passwordInput) passwordInput.value = "";

        const bootstrapModal = new bootstrap.Modal(modalEl);
        bootstrapModal.show();

        async function handleSubmit(e) {
            e.preventDefault();
            if (errorEl) errorEl.textContent = "";

            const masterPassword = passwordInput?.value || "";

            if (!masterPassword.trim()) {
                if (errorEl) errorEl.textContent = "Password field cannot be empty.";
                return;
            }

            try {

                const targetUrl = document.getElementById('globalVerifySubmitBtn')?.getAttribute('data-url');
                if (!targetUrl) {
                    if (errorEl) errorEl.textContent = "Session configuration lost. Please refresh the page.";
                    console.error("DOM Routing Error: Verification modal form action endpoint is missing or undefined.");
                    return;
                }

                const accountRes = await secureFetch(targetUrl, { 
                    method: "GET", 
                    headers: { 'Content-Type': 'application/json' }
                });

                const payload = await accountRes.json();
                if (!accountRes.ok) errorEl.textContent = payload.error || "Failed to locate account attributes.";

                const { kek } = await deriveKeysAndTokens(masterPassword, payload.salt);
                const activeDEK = await decryptDEK(payload.wrapped_dek, kek);

                cryptoSession.setSession(activeDEK);
                passwordInput.value = "";
                errorEl.textContent = "";
                
                wasResolved = true;
                verifyForm.removeEventListener('submit', handleSubmit);
                
                bootstrapModal.hide();
                resolve(activeDEK);

            } catch (err) {
                console.error("Re-verification failed:", err);
                if (errorEl) errorEl.textContent = "Incorrect master password. Please try again.";
                if (passwordInput) passwordInput.select();
            }
        }

        verifyForm.addEventListener('submit', handleSubmit);

        modalEl.addEventListener('hidden.bs.modal', () => {
            verifyForm.removeEventListener('submit', handleSubmit);
            if (!wasResolved) {
                reject(new Error("Verification cancelled by user."));
            }
        }, { once: true });
    });
}

async function togglePasswordVisibility(btn) {
    const vaultCard = btn.closest('.vault-entry-card');
    if (!vaultCard) return;

    const passwordDisplay = vaultCard.querySelector('.entry-password-display');
    const icon = btn.querySelector('svg');
    if (!passwordDisplay || !icon) return; 

    const eyeIconHtml = `
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
        <circle cx="12" cy="12" r="3"></circle>
    `;
    const eyeOffIconHtml = `
        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
        <line x1="1" y1="1" x2="23" y2="23"></line>
    `;

    if (passwordDisplay.type === "password") {
        document.querySelectorAll('.entry-password-display').forEach(el => {
            if (el.type !== "password") {
                el.value = "••••••••••••";
                el.type = "password";

                const associatedCard = el.closest('.vault-entry-card');
                if (associatedCard) {
                    const companionBtn = associatedCard.querySelector('.action-toggle-visibility');
                    if (companionBtn) {
                        const companionIcon = companionBtn.querySelector('svg');
                        if (companionIcon) companionIcon.innerHTML = eyeIconHtml;
                    }
                }
            }
        });

        const ciphertext = passwordDisplay.getAttribute('data-ciphertext');
        let activeDEK = cryptoSession.getDEK(); 

        if (!activeDEK) {
            try {
                activeDEK = await openVerificationModal("Confirm your master password to view this secret.");
            } catch (modalCancel) {
                console.warn("View authorization bypassed by user.");
                return;
            }
        }

        let plainBuffer = null;
        let decryptedPlaintext = null;

        try {
            plainBuffer = await decryptVaultPassword(activeDEK, ciphertext); 
            decryptedPlaintext = new TextDecoder().decode(plainBuffer);
            passwordDisplay.value = decryptedPlaintext;
            passwordDisplay.type = "text";
            icon.innerHTML = eyeOffIconHtml;
            
        } catch (err) {
            console.error("Decryption error:", err);
            alert("Failed to decrypt password.");
        } finally {
            if (plainBuffer) {
                plainBuffer.fill(0);
                plainBuffer = null;
            }
            decryptedPlaintext = null;
            activeDEK = null;
        }

    } else {
        passwordDisplay.value = "••••••••••••";
        passwordDisplay.type = "password";
        icon.innerHTML = eyeIconHtml;
    }
}

async function copyToClipboard(btn) {
    const vaultCard = btn.closest('.vault-entry-card');
    if (!vaultCard) return;

    const passwordDisplay = vaultCard.querySelector('.entry-password-display');
    if (!passwordDisplay) return;

    if (btn.disabled) return;

    const ciphertext = passwordDisplay.getAttribute('data-ciphertext');
    let activeDEK = cryptoSession.getDEK();

    if (!activeDEK) {
        try {
            activeDEK = await openVerificationModal("Confirm your master password to view this secret.");
        } catch (modalCancel) {
            console.warn("View authorization bypassed by user.");
            return;
        }
    }

    let plainBuffer;
    let plainPassword = null;
    const originalHTML = btn.innerHTML;

    try {
        if (btn) btn.disabled = true;

        plainBuffer = await decryptVaultPassword(activeDEK, ciphertext);
        plainPassword = new TextDecoder().decode(plainBuffer);
        
        await navigator.clipboard.writeText(plainPassword);

        btn.setAttribute('title', 'Copied!');
        btn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-check text-success" viewBox="0 0 16 16">
                <path d="M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425z"/>
            </svg>
        `;

        setTimeout(() => {
            if (btn && document.body.contains(btn)) {
                btn.innerHTML = originalHTML;
                btn.setAttribute('title', 'Copy Password');
                btn.disabled = false;
            }
        }, 2000);
    } catch (err) {
        console.error("Clipboard copy operation failure:", err);
        alert("Failed to copy password securely.");
        if (btn) btn.disabled = false;
    } finally {
        if (plainBuffer) {
            plainBuffer.fill(0);
            plainBuffer = null;
        }
        plainPassword = null;
        activeDEK = null;
    }
}

// DELETE EXISTING VAULT ENTRY BY ID
async function deleteEntry(btn, id) {
    if (!confirm("Are you sure you want to delete this vault entry?")) return;

    if (btn.disabled) return;

    const entryCard = btn.closest('.vault-entry-card');
    const restUrl = `/entries/${id}`;

    try {

        if (btn) btn.disabled = true;

        const res = await secureFetch(restUrl, { method: "DELETE" });

        if (res.ok) {
            if (entryCard) {
                entryCard.remove();
            }

            const container = document.getElementById('vaultEntriesContainer');
            if (container) {
                const remainingCards = container.querySelectorAll('.vault-entry-card');
                
                if (remainingCards.length === 0) {
                    container.textContent = '';
                    
                    const placeholderDiv = document.createElement('div');
                    placeholderDiv.className = 'mb-3 no-entries-placeholder';
                    
                    const textPara = document.createElement('p');
                    textPara.className = 'text-muted m-0';
                    textPara.textContent = 'No saved login credentials yet.';
                    
                    placeholderDiv.appendChild(textPara);
                    container.appendChild(placeholderDiv);
                }
            }
            return;
        }
        
        let errorMessage = "The server rejected the deletion request.";
        try {
            const data = await res.json();
            if (data && data.error) errorMessage = data.error;
        } catch (jsonErr) {
            // Suppress JSON parsing errors
        } 
        throw new Error(errorMessage);
    } catch (err) {
        console.error("Deletion lifecycle failure:", err);
        alert(err.message || "Network Error: System was unable to process deletion request.");
        if (btn) btn.disabled = false;
    }
}

// UPDATE EXISTING VAULT ENTRY BY ID
async function submitUpdateForm(btn, id) {
    const modalContent = btn.closest('.modal-content');
    if (!modalContent) return;

    const fieldError = modalContent.querySelector('.field-error');
    if (fieldError) fieldError.textContent = "";

    // Target checkboxes
    const shouldUpdateUser = modalContent.querySelector('.toggle-update-username')?.checked;
    const shouldUpdatePass = modalContent.querySelector('.toggle-update-password')?.checked;

    if (!shouldUpdateUser && !shouldUpdatePass) {
        if (fieldError) fieldError.textContent = "Please select at least one option to update.";
        return;
    }

    const usernameField = modalContent.querySelector('.field-username');
    const passwordField = modalContent.querySelector('.field-password');

    let requestBody = {};
    let usernameInput = "";
    let encryptedHex = null;
    let activeDEK = null;
    let passwordInput = "";

    if (shouldUpdateUser) {
        usernameInput = usernameField.value.trim();
        if (!usernameInput || !usernameInput.trim()) {
            if (fieldError) fieldError.textContent = "Username field cannot be empty.";
            return;
        }
        if (usernameInput.length > 255) {
            if (fieldError) fieldError.textContent = "Username cannot be longer than 255 characters.";
            return;
        }
        requestBody.new_username = usernameInput;
    }

    if (shouldUpdatePass) {
        passwordInput = passwordField.value;
        if (!passwordInput || !passwordInput.trim()) {
            if (fieldError) fieldError.textContent = "Password field cannot be empty.";
            return;
        }
        if (passwordInput.length < 8 || passwordInput.length > 32) {
            if (fieldError) fieldError.textContent = "Password must be between 8 and 32 characters.";
            return;
        }

        activeDEK = cryptoSession.getDEK();
        if (!activeDEK) {
            try {
                activeDEK = await openVerificationModal("Confirm your master password to save changes.");
            } catch (modalCancel) {
                console.warn("Update authorization bypassed by user.");
                return;
            }
        }

        encryptedHex = await encryptVaultPassword(passwordInput, activeDEK);

        if (passwordField) passwordField.value = "";
        passwordInput = "";

        requestBody.new_ciphertext = encryptedHex;
    }

    try {
        if (btn) btn.disabled = true;

        const restUrl = `/entries/${id}`;
        const response = await secureFetch(restUrl, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(requestBody)
        });

        if (response.ok) {
            alert("Entry successfully updated!");

            if (fieldError) fieldError.textContent = "";

            if (usernameField) {
                usernameField.value = "";
                usernameField.disabled = true;
            }

            if (passwordField) {
                passwordField.value = "";
                passwordField.disabled = true;
            }
            
            const uCheck = modalContent.querySelector('.toggle-update-username');
            const pCheck = modalContent.querySelector('.toggle-update-password');
            if (uCheck) { uCheck.checked = false; usernameField.disabled = true; }
            if (pCheck) { 
                pCheck.checked = false; 
                passwordField.disabled = true;
                const genWrapper = modalContent.querySelector('.template-generator-wrapper');
                if (genWrapper) { genWrapper.style.opacity = "0.5"; genWrapper.style.pointerEvents = "none"; }
            }

            passwordField?.dispatchEvent(new Event('input'));

            const openModalElement = btn.closest('.modal');
            const modalInstance = bootstrap.Modal.getInstance(openModalElement);
            if (modalInstance) modalInstance.hide();

            const entryCard = btn.closest('.vault-entry-card');
            if (entryCard) {
                if (shouldUpdateUser) {
                    const userDisplay = entryCard.querySelector('.entry-username');
                    if (userDisplay) userDisplay.textContent = usernameInput;
                    
                    const internalUserField = entryCard.querySelector('.field-username');
                    if (internalUserField) internalUserField.value = usernameInput;
                }
                
                if (shouldUpdatePass) {
                    const passwordDisplay = entryCard.querySelector('.entry-password-display');
                    if (passwordDisplay) {
                        passwordDisplay.setAttribute('data-ciphertext', encryptedHex);
                        passwordDisplay.value = "••••••••••••";
                        passwordDisplay.type = "password";
                    }
                }
            }
        } else {
            let serverErrorMsg = "Unknown server error.";
            try {
                const errData = await response.json();
                if (errData && errData.error) serverErrorMsg = errData.error;
            } catch (jsonErr) {
                // Keep the default fallback message if JSON extraction hits an empty body
            }
            if (fieldError) fieldError.textContent = serverErrorMsg;
        }
    } catch (err) {
        console.error("Update request processing failed:", err);
        alert("Network error occurred during record modification.");
    } finally {
        if (btn) btn.disabled = false;
        encryptedHex = null;
        activeDEK = null;
        passwordInput = null;
        requestBody = null;
    }
}

// Helper function to extract a specific cookie's value by its name
function getCookie(name) { 
    const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)')); 
    return match ? match[2] : null; 
}

// SIGN IN ACTIONS
const loginBtn = document.getElementById('loginBtn');
if (loginBtn) {
    const loginError = document.getElementById('loginError');
    loginBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        
        const loginUrl = loginBtn.getAttribute('data-url');
        if (!loginUrl) {
            loginError.textContent = "An unexpected error occurred. Please refresh the page.";
            return;
        }

        const usernameField = document.getElementById('loginUsername');
        const passwordField = document.getElementById('loginPassword');
        if (!usernameField || !passwordField) return;

        const username = usernameField.value || "";
        let password = passwordField.value || "";
        if (!username.trim() || !password.trim()) {
            loginError.textContent = "Please fill out all fields.";
            return; 
        }

        if (username.length > 255) {
            loginError.textContent = "Username cannot be longer than 255 characters.";
            return;
        }

        if (password.length < 8 || password.length > 32) {
            loginError.textContent = "Password must be between 8 and 32 characters.";
            return; 
        }

        try {
            loginBtn.disabled = true;

            let res = await fetch(loginUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },    
                body: JSON.stringify({ session_username: username })
            });

            let payload = await res.json();

            if (!res.ok) {
                loginError.textContent = "Login failed: " + (payload.error || "Unknown server error.");
                return;
            }

            if (passwordField) passwordField.value = "";

            const { hashHex, kek } = await deriveKeysAndTokens(password, payload.salt);
            password = null;
            
            let activeDEK;
            try {
                activeDEK = await decryptDEK(payload.wrapped_dek, kek);
            } catch (dekError) {
                loginError.textContent = "Invalid username or password.";
                return;
            }

            res = await fetch(loginUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    session_username: username, 
                    session_hash: hashHex 
                })
            });
            
            payload = await res.json();

            if (res.ok) {
                startSessionCountdown(15);
                cryptoSession.setSession(activeDEK);
                if (loginError) loginError.textContent = "";

                const logOutBtn = document.getElementById('logOutBtn');
                if (logOutBtn) logOutBtn.disabled = false;
                
                const entriesData = await secureFetch("/entries", { method: "GET" });
                if (entriesData.ok) {
                    payload = await entriesData.json();
                    await initializeAndLoadDashboard(payload);
                    document.getElementById("loginForm")?.reset();
                } else {
                    let fetchErrorMsg = "Authenticated successfully, but failed to retrieve secure vault entries.";
                    try {
                        const errPayload = await entriesData.json();
                        if (errPayload && errPayload.error) fetchErrorMsg = errPayload.error;
                    } catch (jsonErr) {

                    }
                    if (loginError) loginError.textContent = fetchErrorMsg;
                }
            } else {
                loginError.textContent = "Login failed: " + (payload?.error || "Invalid username or password");
                return;
            }
        } catch (globalError) {
            console.error(globalError);
            alert("A network or system error occurred. Please try again.");
        } finally {
            if (loginBtn) loginBtn.disabled = false;
        }
    });
}

// REGISTRATION ACTIONS
const registerBtn = document.getElementById('registerBtn');
if (registerBtn) {
    const registerError = document.getElementById('registerError');
    registerBtn.addEventListener('click', async (e) => {
        e.preventDefault();

        const registerUrl = registerBtn.getAttribute('data-url');
        if(!registerUrl) {
            registerError.textContent = "An unexpected error occurred. Please refresh the page.";
            return;
        }

        const usernameField = document.getElementById('registerUsername');
        const passwordField = document.getElementById('registerPassword');
        const confField = document.getElementById('registerConfirm');
        if (!usernameField || !passwordField || !confField) return;
        
        const username = usernameField.value || "";
        let password = passwordField.value || "";
        let conf = confField.value || "";
        if (!username.trim() || !password.trim() || !conf.trim()) {
            registerError.textContent = "Please fill out all fields.";
            return; 
        }

        if (username.length > 255) {
            registerError.textContent = "Username cannot be longer than 255 characters.";
            return;
        }

        if (password.length < 8 || password.length > 32) {
            registerError.textContent = "Password must be between 8 and 32 characters.";
            return; 
        }

        if (password !== conf) {
            registerError.textContent = "Password mismatch.";
            return;
        }

        let registrationSuccessful = false;

        try {
            registerBtn.disabled = true;

            if (passwordField) passwordField.value = "";
            if (confField) confField.value = "";

            let keyData = await deriveKeysAndTokens(password);
            let kek = keyData.kek;
            let hashHex = keyData.hashHex;
            let saltHex = keyData.saltHex;

            password = null;
            conf = null;

            let secureDEK = await crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );

            const wrapped_dek = await secureWrapDEK(kek, secureDEK);

            kek = null;
            keyData.kek = null; 
            keyData = null;

            const res = await fetch(registerUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username: username, 
                    user_hash: hashHex, 
                    user_salt: saltHex,  
                    wrapped_dek: wrapped_dek
                })
            });

            hashHex = null;
            saltHex = null;

            if (res.ok) {
                registrationSuccessful = true;

                startSessionCountdown(15);
                cryptoSession.setSession(secureDEK);

                secureDEK = null;

                if (registerError) registerError.textContent = "";

                const entriesData = await secureFetch("/entries", { method: "GET" });
                if (entriesData.ok) {
                    const payload = await entriesData.json();
                    await initializeAndLoadDashboard(payload);
                    document.getElementById("registerForm")?.reset();
                } else {
                    let fetchErrorMsg = "Account created, but failed to load initial vault data.";
                    try {
                        const errPayload = await entriesData.json();
                        if (errPayload && errPayload.error) fetchErrorMsg = errPayload.error;
                    } catch (jsonErr) {
                        // fallback if response body is empty
                    }
                    if (registerError) registerError.textContent = fetchErrorMsg;
                    registrationSuccessful = false;
                    return;
                }
            } else {
                secureDEK = null;
                const payload = await res.json();
                if (registerError)registerError.textContent = "Registration failed: " + (payload?.error || "Unknown server error.");
                return;
            }
        } catch (globalError) {
            console.error("Registration pipeline error:", globalError);
            alert("A network or system error occurred. Please try again.");
        } finally {
            if (registerBtn && !registrationSuccessful) {
                registerBtn.disabled = false;
            }
        }
    });
}

// LOG OUT ACTIONS
const logOutBtn = document.getElementById('logOutBtn');
if (logOutBtn) {
    logOutBtn.addEventListener('click', async (e) => {
        e.preventDefault();

        logOutBtn.disabled = true;

        let logOutUrl = logOutBtn.getAttribute('data-url');
        
        if (logOutUrl) {
            try {
                const response = await secureFetch(logOutUrl, { 
                    method: 'DELETE', 
                    credentials: 'include' 
                });

                if (!response.ok) {
                    console.warn("Token was likely already expired on arrival.");
                }
            } catch (err) {
                console.error("Network error during logout notice:", err);
            }
        }
        logOutUrl = null;

        await handleForcedLogout(); 
    });
}

// NEW ENTRY ACTIONS
const createVaultBtn = document.getElementById('createVaultBtn');
if (createVaultBtn) {
    const createVaultError = document.getElementById("createVaultError");
    createVaultBtn.addEventListener('click', async (e) => {
        e.preventDefault();

        const createVaultUrl = createVaultBtn.getAttribute('data-url');
        if (!createVaultUrl) {
            if (createVaultError) createVaultError.textContent = "An unexpected error occurred. Please refresh the page.";
            return;
        }
        const websiteField = document.getElementById('createVaultWebsite');
        const usernameField = document.getElementById('createVaultUsername');
        const passwordField = document.getElementById('createVaultPassword');
        if (!websiteField || !usernameField || !passwordField) return;

        const website = websiteField.value || "";
        const username = usernameField.value || "";
        let password = passwordField.value || "";
        if (!username.trim() || !password.trim() || !website.trim()) {
            if (createVaultError) createVaultError.textContent = "Please fill out all fields.";
            return; 
        }

        if (website.length > 2048) {
            if (createVaultError) createVaultError.textContent = "Website URL cannot be longer than 2048 characters.";
            return;
        }

        if (username.length > 255) {
            if (createVaultError) createVaultError.textContent = "Username cannot be longer than 255 characters.";
            return;
        }

        if (password.length < 8 || password.length > 32) {
            if (createVaultError) createVaultError.textContent = "Password must be between 8 and 32 characters.";
            return; 
        }

        let dek = null;
        let ciphertext = null;
        let requestBody = null;
        let creationSuccessful = false;

        try {
            if (createVaultBtn) createVaultBtn.disabled = true;

            dek = cryptoSession.getDEK();
            if (!dek) {
                try {
                    dek = await openVerificationModal("Unable to save. Refreshing the page locked your secure data container. Please log in again to re-authenticate and save your data.");
                } catch (modalCancel) {
                    console.warn("View authorization bypassed by user.");
                    throw new Error("Authorization cancelled by user."); 
                }
            }

            ciphertext = await encryptVaultPassword(password, dek);
            if (passwordField) passwordField.value = "";
            password = "";

            requestBody = {
                vault_website: website,
                vault_username: username,
                vault_ciphertext: ciphertext
            };

            const res = await secureFetch(createVaultUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody)
            });

            if (res.ok) {
                creationSuccessful = true;
                alert("Login entry successfully submitted!");

                if (usernameField) usernameField.value = "";
                if (websiteField) websiteField.value = "";

                const entry = await res.json();
                const container = document.getElementById('vaultEntriesContainer');
                const template = document.getElementById('entryTemplate');
                if (!container || !template) return;

                const placeholder = container.querySelector('.no-entries-placeholder');
                if (placeholder) placeholder.remove();

                let clone = template.content.cloneNode(true);
                const uniqueModalId = `updateEntryModal_${entry.id}`;
                let modalContainer = clone.querySelector('.entry-modal-container');
                let editTriggerBtn = clone.querySelector('.btn-edit-trigger');
                
                if (modalContainer && editTriggerBtn) {
                    modalContainer.id = uniqueModalId;
                    editTriggerBtn.setAttribute('data-bs-target', `#${uniqueModalId}`);
                    modalContainer.setAttribute('data-entry-id', entry.id);
                }

                clone.querySelector('.entry-website').textContent = entry.website;
                clone.querySelector('.entry-username').textContent = entry.username;
                clone.querySelector('.entry-website-title-span').textContent = entry.website;
                clone.querySelector('.field-username').value = entry.username;
                clone.querySelector('.entry-password-display').setAttribute('data-ciphertext', entry.ciphertext);

                clone.querySelector('.btn-delete-action')?.setAttribute('data-entry-id', entry.id);
                clone.querySelector('.btn-save-modal-action')?.setAttribute('data-entry-id', entry.id);

                initializePasswordGenerator({
                    slider: clone.querySelector('.template-slider'),
                    box: clone.querySelector('.template-box'),
                    tickContainer: clone.querySelector('.template-tick-container'),
                    passwordInput: clone.querySelector('.field-password'), 
                    fieldset: clone.querySelector('.template-generator-options'),
                    generateBtn: clone.querySelector('.template-generate-trigger'),
                    specialsCheckbox: clone.querySelector('.template-specials')
                });

                let updatedPasswordField = clone.querySelector('.field-password');
                if (updatedPasswordField) {
                    updatedPasswordField.addEventListener('input', (e) => {
                        checkStrength(e.target);
                    });
                }

                container.prepend(clone);

                clone = null;
                modalContainer = null;
                editTriggerBtn = null;
                updatedPasswordField = null;
            } else {
                const errPayload = await res.json().catch(() => ({}));
                if (createVaultError) {
                    createVaultError.textContent = "Registration failed: " + (errPayload?.error || "Unknown server error.");
                }
                return;
            }
            document.getElementById("entryForm")?.reset();
            if (createVaultError) createVaultError.textContent = "";

            passwordField?.dispatchEvent(new Event('input')); 

            const createModalEl = document.getElementById('addEntry'); 
            if (createModalEl) {
                const modalInstance = bootstrap.Modal.getInstance(createModalEl);
                if (modalInstance) {
                    modalInstance.hide();
                }
            }
        } catch (globalError) {
            console.error(globalError);
            alert("A network or system error occurred. Please try again.");
        } finally {
            if (createVaultBtn && !creationSuccessful) {
                createVaultBtn.disabled = false;
            }
            ciphertext = null;
            dek = null;
            requestBody = null;
        }
    });
}

// PROFILE & ACCOUNT SECURITY SETTINGS
// Handle Master Password Change Verification
const verifyPwBtn = document.getElementById('verifyPwBtn');
if (verifyPwBtn) {
    const baseUrl = verifyPwBtn.getAttribute('data-url');
    const passwordInput = document.getElementById('currentPassword');
    const verifyForm = document.getElementById('verifyPasswordForm');
    const verifyError = document.getElementById('verifyError');

    verifyPwBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        if (!baseUrl) {
            if (verifyError) verifyError.textContent = "An unexpected error occurred. Please refresh the page.";
            return;
        }

        let currentPasswordVal = passwordInput?.value || "";

        if (!currentPasswordVal.trim()) {
            if (verifyError) verifyError.textContent = "Password field cannot be empty.";
            return; 
        }

        let verificationSuccessful = false;

        try {
            verifyPwBtn.disabled = true;
            
            let accountRes = await secureFetch(baseUrl, { 
                method: "GET",
                headers: { 'Content-Type': 'application/json'}
            });

            if (!accountRes.ok) {
                const errorParams = await accountRes.json().catch(() => ({}));
                if (verifyError) verifyError.textContent = errorParams.error || "Failed to retrieve security configuration.";
                verifyForm?.reset();
                return;
            }

            const vaultParams = await accountRes.json();

            let keyData = await deriveKeysAndTokens(currentPasswordVal, vaultParams.salt);
            let hashHex = keyData.hashHex;
            let kek = keyData.kek;

            currentPasswordVal = null;
            if (passwordInput) passwordInput.value = "";

            accountRes = await secureFetch(baseUrl, {
                method: "POST",
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ current_hash: hashHex })
            });

            hashHex = null;

            if (!accountRes.ok) {

                kek = null;
                keyData.kek = null;
                keyData.hashHex = null;
                keyData = null;

                const payload = await accountRes.json().catch(() => ({}));
                if (verifyError) verifyError.textContent = payload.error || "Verification failed.";
                verifyForm?.reset();
                return;
            }
            
            cryptoSession.clearSession(); 
            const activeDEK = await decryptDEK(vaultParams.wrapped_dek, kek, true);
            cryptoSession.setSession(activeDEK);

            kek = null;
            keyData.kek = null;
            keyData.hashHex = null;
            keyData = null;
            
            verificationSuccessful = true;
            verifyForm?.reset();
            if (verifyError) verifyError.textContent = "";

            const modalElement1 = document.getElementById('verifyPasswordModal');
            const modalElement2 = document.getElementById('changePasswordModal');
            
            const modal1 = modalElement1 ? bootstrap.Modal.getInstance(modalElement1) : null;
            const modal2 = modalElement2 ? bootstrap.Modal.getOrCreateInstance(modalElement2) : null;
            
            if (modal1) modal1.hide();
            if (modal2) modal2.show();
            
        } catch (err) {
            console.error(err);
            if (err instanceof TypeError || err.message.includes('fetch')) {
                alert("A network or system error occurred. Please try again.");
            } else {
                alert(err.message);
            }
        } finally {            
            if (verifyPwBtn && !verificationSuccessful) {
                verifyPwBtn.disabled = false;
            }
        }
    });
}

// Handle Master Password Change
const updateNewPwBtn = document.getElementById('updateNewPwBtn');
if (updateNewPwBtn) {
    const baseUrl = updateNewPwBtn.getAttribute('data-url');
    const patchForm = document.getElementById('patchPasswordForm');
    const newPasswordInput = document.getElementById('newPassword');
    const newConfInput = document.getElementById('newConf');
    const patchError = document.getElementById('patchError');
    updateNewPwBtn.addEventListener('click', async (e) => {
        e.preventDefault();

        if (!baseUrl) {
            if (patchError) patchError.textContent = "An unexpected error occurred. Please refresh the page.";
            return;
        }

        let newPwVal = newPasswordInput?.value || "";
        let newConfVal = newConfInput?.value || "";

        if (!newPwVal.trim() || !newConfVal.trim()) {
            if (patchError) patchError.textContent = "All fields cannot be empty.";
            return;
        }

        if (newPwVal.length < 8 || newPwVal.length > 32) {
            patchError.textContent = "Password must be between 8 and 32 characters.";
            return; 
        }

        if (newPwVal !== newConfVal) {
            if (patchError) patchError.textContent = "Password mismatch.";
            if (newConfInput) {
                newConfInput.value = "";
                newConfInput.focus();
            }
            return;
        }

        let patchSuccessful = false;

        try {
            updateNewPwBtn.disabled = true;

            const activeDEK = cryptoSession.getDEK();
            if (!activeDEK) {
                alert("Password change can't be completed due to refreshing the page or the attempt took too long.");
                patchForm?.reset();
                if (patchError) patchError.textContent = "";

                const verifyModalEl = document.getElementById('verifyPasswordModal');
                const changeModalEl = document.getElementById('changePasswordModal');
                const modal1 = verifyModalEl ? bootstrap.Modal.getOrCreateInstance(verifyModalEl) : null;
                const modal2 = changeModalEl ? bootstrap.Modal.getOrCreateInstance(changeModalEl) : null;
                
                if (modal2) modal2.hide();
                if (modal1) modal1.show();
                return;
            }
            
            let keyData = await deriveKeysAndTokens(newPwVal);
            let saltHex = keyData.saltHex;
            let hashHex = keyData.hashHex;
            let kek = keyData.kek;

            newPwVal = null;
            newConfVal = null;
            if (newPasswordInput) newPasswordInput.value = "";
            if (newConfInput) newConfInput.value = "";

            const wrapped_dek = await secureWrapDEK(kek, activeDEK);

            kek = null;
            keyData.kek = null;
            keyData.hashHex = null;
            keyData = null;

            const accountRes = await secureFetch(baseUrl, {
                method: "PATCH",
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    new_salt: saltHex,
                    new_hash: hashHex,
                    new_wrapped_dek: wrapped_dek
                })
            });

            saltHex = null;
            hashHex = null;

            if (!accountRes.ok) {
                const payload = await accountRes.json().catch(() => ({}));
                if (patchError) patchError.textContent = payload.error || "Failed to update password.";
                patchForm?.reset();
                newPasswordInput?.focus();
                return;
            }
            patchSuccessful = true;
            patchForm.reset();
            if (patchError) patchError.textContent = "";

            alert("Master password updated successfully!");
            const currentChangeModal = document.getElementById('changePasswordModal');

            const modalSuccess = currentChangeModal ? bootstrap.Modal.getInstance(currentChangeModal) : null;
            if (modalSuccess) modalSuccess.hide();
        } catch (err) {
            console.error("PATCH error:", err);
            alert("A network or system error occurred. Please try again.");
        } finally {
            if (updateNewPwBtn && !patchSuccessful) {
                updateNewPwBtn.disabled = false;
            }
        }
    });
}


// DOM INITIALIZATION LIFECYCLE HOOKS
document.addEventListener("DOMContentLoaded", async () => {
    const clearAuthForms = () => {
        document.getElementById('loginForm')?.reset();
        document.getElementById('registerForm')?.reset();
    };

    document.getElementById('register-tab')?.addEventListener('click', clearAuthForms);
    document.getElementById('login-tab')?.addEventListener('click', clearAuthForms);

    document.addEventListener('change', (e) => {
        if (!e.target) return;

        if (e.target.classList.contains('toggle-update-username')) {
            const form = e.target.closest('form');
            if (!form) return;
            const userField = form.querySelector('.field-username');
            if (userField) {
                userField.disabled = !e.target.checked;
                if (userField.disabled) userField.value = "";
            }
        }
        
        if (e.target.classList.contains('toggle-update-password')) {
            const form = e.target.closest('form');
            if (!form) return;

            const passField = form.querySelector('.field-password');
            const genWrapper = form.querySelector('.template-generator-wrapper');
            const genTrigger = form.querySelector('.template-generate-trigger');
            const genFieldset = form.querySelector('.template-generator-options');

            if (passField) {
                passField.disabled = !e.target.checked;
                if (passField.disabled) passField.value = "";
            }
            
            // Toggle Generator Box Visuals & Access
            if (genWrapper && genTrigger && genFieldset) {
                if (e.target.checked) {
                    genWrapper.style.opacity = "1";
                    genWrapper.style.pointerEvents = "auto";
                    genTrigger.disabled = false;
                    genFieldset.disabled = false;
                } else {
                    genWrapper.style.opacity = "0.5";
                    genWrapper.style.pointerEvents = "none";
                    genTrigger.disabled = true;
                    genFieldset.disabled = true;
                }
            }
        }
    });

    // Create Vault Password Strength Listener
    const createPasswordInput = document.getElementById('createVaultPassword');
    if (createPasswordInput) {
        createPasswordInput.addEventListener('input', function() {
            checkStrength(this);
        });
    }
    
    initializePasswordGenerator({
        slider: document.getElementById('staticSlider'),
        box: document.getElementById('staticBox'),
        tickContainer: document.getElementById('staticTickContainer'),
        passwordInput: document.getElementById('createVaultPassword'),
        fieldset: document.getElementById('staticGeneratorOptions'),
        generateBtn: document.getElementById('staticGenerateBtn'),
        specialsCheckbox: document.getElementById('staticSpecials')
    });

    // Create Vault Cancel Listener
    const cancelVaultBtn = document.getElementById('cancelCreateVaultBtn');

    if (cancelVaultBtn) {
        cancelVaultBtn.addEventListener('click', function() {
            const modal = this.closest('.modal');
            if (!modal) return;

            const form = modal.querySelector('form');
            if (form) {
                form.reset();
                
                const strengthBadges = modal.querySelectorAll('.strength-text');
                strengthBadges.forEach(badge => {
                    badge.innerText = "";
                    badge.className = "strength-text ms-1 fw-bold text-lowercase text-muted";
                });
            }
        });
    }

    // Close modal listener
    document.addEventListener('hidden.bs.modal', (event) => {
        const closingModal = event.target;
        if (!closingModal) return;
        
        const form = closingModal.querySelector('form');
        if (form) {
            form.reset(); 
            form.classList.remove('was-validated');
        }

        closingModal.querySelectorAll('.field-username, .field-password').forEach(input => {
            if (input) {
                input.value = "";
                input.disabled = true;
            }
        });

        closingModal.querySelectorAll('.toggle-update-username, .toggle-update-password').forEach(checkbox => {
            if (checkbox) checkbox.checked = false;
        });

        closingModal.querySelectorAll('.template-generator-wrapper').forEach(wrapper => {
            if (wrapper) {
                wrapper.style.opacity = "0.5";
                wrapper.style.pointerEvents = "none";
            }
        });

        closingModal.querySelectorAll('.template-generate-trigger, .template-generator-options').forEach(el => {
            if (el) el.disabled = true;
        });

        closingModal.querySelectorAll('.strength-text').forEach(badge => {
            if (badge) {
                badge.innerText = "";
                badge.className = "strength-text ms-1 fw-bold text-lowercase text-muted";
            }
        });

        closingModal.querySelectorAll('.text-danger, .field-error, #verifyError, #patchError').forEach(errorContainer => {
            errorContainer.textContent = '';
        });
    });
    
    // Global Dashboard Action Router
    const appDashboard = document.getElementById('appDashboard');
    if (appDashboard) {
        appDashboard.addEventListener('click', async (event) => {
            if (!event.target) return;

            const toggleBtn = event.target.closest('.action-toggle-visibility');
            // Handle Password Visibility Toggle
            if (toggleBtn) {
                event.preventDefault();
                await togglePasswordVisibility(toggleBtn);
                return;
            }

            // Handle Secure Clipboard Operations
            const copyBtn = event.target.closest('.action-copy');
            if (copyBtn) {
                event.preventDefault();
                await copyToClipboard(copyBtn); 
                return;
            }

            // Handle Vault Record Deletion Sequences
            const deleteBtn = event.target.closest('.btn-delete-action');
            if (deleteBtn) {
                event.preventDefault();
                const entryId = deleteBtn.getAttribute('data-entry-id');
                if (!entryId) return;
                await deleteEntry(deleteBtn, entryId);
                return;
            }

            // Handle Modal Form Submissions for Entry Modifications
            const saveBtn = event.target.closest('.btn-save-modal-action');
            if (saveBtn) {
                event.preventDefault();
                const entryId = saveBtn.getAttribute('data-entry-id');
                await submitUpdateForm(saveBtn, entryId);
                return;
            }
        });
    }
    
    // This acts as a defensive guard  to prevent unauthorized rendering if a local state slips out of sync.
    if (appDashboard && !appDashboard.classList.contains('d-none')) {
        const savedExpiry = sessionStorage.getItem('tokenExpirationTime');
        
        // Safety check: Kick user out if the expiration timestamp is missing completely
        if (!savedExpiry) {
            console.warn("Dashboard container is active but expiration token is missing. Forcing logout sequence...");
            await handleForcedLogout();
            return;
        }
        
        const remainingTimeInMs = parseInt(savedExpiry, 10) - Date.now();

        // Evaluate token lifecycle relative to absolute dead boundary
        if (remainingTimeInMs <= 0) {
            console.warn("Persisted session timer has passed absolute dead boundary.");
            await handleForcedLogout();
            return;
        } else {
            // Re-sync local timer instance and spin up the visual countdown UI
            tokenExpirationTime = parseInt(savedExpiry, 10);
            const remainingMinutes = remainingTimeInMs / (60 * 1000);
            startSessionCountdown(remainingMinutes);
        }

        // Hydrate UI panels with secure server-side records
        try {
            const entriesData = await secureFetch("/entries", { method: "GET" });
            if (!entriesData.ok) {
                throw new Error(`Server returned network status code: ${entriesData.status}`);
            }        

            const payload = await entriesData.json().catch(() => null);
            if (!payload) {
                throw new Error("Invalid or empty payload response string stream.");
            }

            await initializeAndLoadDashboard(payload);
        } catch (err) {
            // Fail-secure behavior: Any API fetch failure or tampering triggers an automated wipe
            console.error("Silent sync failure on refresh:", err);
            await handleForcedLogout();
        }
    }
});
