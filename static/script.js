// Line 1: Use the CDN link for hash-wasm (No downloads required)
import { argon2id } from 'https://cdn.jsdelivr.net/npm/hash-wasm@4.11.0/+esm';

// Line 2: Point directly to the root static folder file mapping
import { cryptoSession } from './cryptoSession.js';

// ========================================================
// 1. GLOBAL STATE & LIFECYCLE TRACKERS
// ========================================================
let sessionTimeoutId = null;
let tokenExpirationTime = null;

// ========================================================
// 2. DATA TYPE & HEX CONVERSION UTILITIES
// ========================================================
const toHex = (buf) => Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');

const fromHex = hexString => {
    if (!hexString || typeof hexString !== 'string') {
        console.error("🚫 fromHex error: Received an invalid or undefined hex string string value!");
        console.trace();// was removed
        return new Uint8Array(0);
    }
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
};

// ========================================================
// 3. CORE CRYPTOGRAPHIC PIPELINES
// ========================================================
async function deriveKeysAndTokens(password, customSalt) {
    const salt = customSalt ? fromHex(customSalt) : crypto.getRandomValues(new Uint8Array(16));
    
    const rawhash = await argon2id({
        password: password,
        salt: salt,
        parallelism: 1,
        iterations: 3,
        memorySize: 65536,
        hashLength: 32,
        outputType: 'binary'
    });

    const kek = await crypto.subtle.importKey(       
        "raw",
        rawhash,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"]
    );

    return {
        saltHex: toHex(salt),
        hashHex: toHex(rawhash),
        kek,
    }
}


async function encryptDEK(kek, rawDekBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 3. Perform standard AES-GCM encryption
    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        kek,
        rawDekBytes
    );

    const encryptedBytes = new Uint8Array(encryptedBuffer);

    // 4. Combine IV (12 bytes) + Ciphertext into a single container array
    const encryptedDek= new Uint8Array(iv.length + encryptedBytes.length);
    encryptedDek.set(iv, 0);
    encryptedDek.set(encryptedBytes, iv.length);

    // 5. Convert to a standard hex string for backend storage
    return toHex(encryptedDek);
}

async function decryptDEK(encryptedDekHex, kek, isExtractable = false) {
    const encryptedDekBytes = fromHex(encryptedDekHex);

    const iv = encryptedDekBytes.slice(0, 12);
    const encryptedBytes = encryptedDekBytes.slice(12);

    try {
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            kek,
            encryptedBytes
        );

        const rawDekBytes = new Uint8Array(decryptedBuffer);

        return await crypto.subtle.importKey(
            "raw",
            rawDekBytes,
            "AES-GCM",
            isExtractable, 
            ["encrypt", "decrypt"]
        );

    } catch (err) {
        console.error(
            "Decryption failed. Invalid key or compromised ciphertext tag.",
            err
        );

        throw new Error(
            "Integrity check failed: Decryption rejected."
        );
    }
}

async function encryptVaultPassword(plainTextPassword, dek) {
    
    const plainTextBytes = new TextEncoder().encode(plainTextPassword);

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedBuffer = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        dek, // Your functional DEK CryptoKey object
        plainTextBytes
    );

    const ciphertextBytes = new Uint8Array(encryptedBuffer);

    const ciphertext = new Uint8Array(iv.length + ciphertextBytes.length);
    ciphertext.set(iv, 0);
    ciphertext.set(ciphertextBytes, iv.length);

    // 5. Convert to a standard Hex string to safely transmit via JSON.
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
        console.error(
            "Decryption failed. Invalid key or compromised ciphertext tag.1",
            err
        );

        throw new Error(
            "Integrity check failed: Decryption rejected."
        );
    }
}

// ========================================================
// 4. NETWORK BOUNDARY & ROUTING INTERCEPTORS
// ========================================================
async function secureFetch(url, options = {}) {

    if (tokenExpirationTime &&
        Date.now() >= tokenExpirationTime) {

        handleForcedLogout();
        throw new Error("Session expired client-side");
    }

    const headers = {
        ...(options.headers || {})
    };

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
        handleForcedLogout();
        throw new Error("Unauthorized");
    }

    return response;
}

// ========================================================
// 5. UNIFIED TERMINATION & SESSION CLEANUP
// ========================================================
function startSessionCountdown(durationInMinutes) {
    const durationInMs = durationInMinutes * 60 * 1000;
    tokenExpirationTime = Date.now() + durationInMs;
    if (sessionTimeoutId) clearTimeout(sessionTimeoutId);
    
    sessionTimeoutId = setTimeout(async () => {
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

        // 2. Trigger your visual cleanup and UI reset
        handleForcedLogout();
        
    }, durationInMs);
}

function handleForcedLogout() {
    cryptoSession.clearSession();
    tokenExpirationTime = null;
    if (sessionTimeoutId) {
        clearTimeout(sessionTimeoutId);
        sessionTimeoutId = null;
    }

    const container = document.getElementById('vaultEntriesContainer');
    if (container) container.innerHTML = '<div class="mb-3 no-entries-placeholder"><p>No saved login credentials yet.</p></div>';

    document.querySelectorAll('.modal.show').forEach(m => { const inst = bootstrap.Modal.getInstance(m); if (inst) inst.hide(); });
    document.querySelectorAll('.modal-backdrop').forEach(b => b.remove());

    document.getElementById("loginForm").reset();
    document.getElementById("registerForm").reset();
    document.getElementById("entryForm").reset();
    document.getElementById("verifyPasswordForm").reset();
    document.getElementById("patchPasswordForm").reset();
    document.getElementById("entry-update-form").reset();

    

    const authSection = document.getElementById('authSection');
    const appDashboard = document.getElementById('appDashboard');
    if (authSection) authSection.classList.remove('d-none');
    if (appDashboard) appDashboard.classList.add('d-none');
}

// ========================================================
// 6. PASSWORD STRENGTH & GENERATION ENGINES
// ========================================================
function runSecureGenerator(length, includeSpecials) {
    const alphas = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    const specials = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let pool = alphas + numbers;
    if (includeSpecials) pool += specials;

    let password = "";
    const randValues = new Uint32Array(length);
    window.crypto.getRandomValues(randValues);

    for (let i = 0; i < length; i++) {
        password += pool.charAt(randValues[i] % pool.length);
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

    passwordInput.addEventListener('input', (e) => {
        if (fieldset) {
            fieldset.disabled = (e.target.value.trim().length > 0);
        }
    });

    generateBtn.addEventListener('click', () => {
        const length = parseInt(box.value, 10) || 16;
        const includeSpecials = specialsCheckbox ? specialsCheckbox.checked : true;
        
        passwordInput.value = runSecureGenerator(length, includeSpecials);
        if (fieldset) fieldset.disabled = false;

        passwordInput.dispatchEvent(new Event('input'));
    });
}

function checkStrength(pw) {
    const strengthText = document.getElementById('strength-text');
    if (!strengthText) return;

    if (!pw) {
        strengthText.innerText = "Password";
        return;
    }

    let score = 0;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;

    if (score <= 1) strengthText.innerText = "Strength: Weak";
    else if (score === 2) strengthText.innerText = "Strength: Medium";
    else if (score >= 3) strengthText.innerText = "Strength: Strong";
}

// ========================================================
// 7. VAULT DISPLAY AND PRESENTATION LAYER
// ========================================================
async function decryptAndPopulateDashboard(entries, clearContainer = true) {
    
    console.log("decryptAndPopulateDashboard called");
    console.log("entries:", entries);
    console.log("entries type:", typeof entries);
    console.log("Is Array?", Array.isArray(entries));
    console.log("Length:", entries?.length);

    const container = document.getElementById('vaultEntriesContainer');
    const template = document.getElementById('entryTemplate');
    if (!container || !template) return;

    if (clearContainer) {
        container.innerHTML = '';
    } else {
        const placeholder = container.querySelector('.no-entries-placeholder');
        if (placeholder) placeholder.remove();
    }

    if (!entries || entries.length === 0) {
        container.innerHTML = '<div class="mb-3 no-entries-placeholder"><p>No saved login credentials yet.</p></div>';
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
        clone.querySelector('.field-username').value = entry.username;

        const passwordDisplay = clone.querySelector('.entry-password-display');
        passwordDisplay.setAttribute('data-ciphertext', entry.ciphertext);

        const deleteBtn = clone.querySelector('.btn-delete-action');
        if (deleteBtn) {
            deleteBtn.setAttribute('onclick', `deleteEntry(this, '${entry.id}')`);
        }

        const saveModalBtn = clone.querySelector('.btn-save-modal-action');
        if (saveModalBtn) {
            saveModalBtn.setAttribute('onclick', `submitUpdateForm(this, '${entry.id}')`);
        }

        initializePasswordGenerator({
            slider: clone.querySelector('.template-slider'),
            box: clone.querySelector('.template-box'),
            tickContainer: clone.querySelector('.template-tick-container'),
            passwordInput: clone.querySelector('.field-password'), 
            fieldset: clone.querySelector('.template-generator-options'),
            generateBtn: clone.querySelector('.template-generate-trigger'),
            specialsCheckbox: clone.querySelector('.template-specials')
        });

        container.appendChild(clone);
    });
}

async function initializeAndLoadDashboard(payload) {
    try {
        // 1. Extract data from the server payload
        const { masterUsername, entries } = payload;

        // 2. Inject the master username into the required DOM elements
        const welcomeSpan = document.querySelector('.display-current-username');
        const profileModalStrong = document.getElementById('modalUsername');
        
        if (welcomeSpan) welcomeSpan.textContent = masterUsername || "User";
        if (profileModalStrong) profileModalStrong.textContent = masterUsername || "Unknown";

        // 3. Handle UI transitions (Hide Auth, Show Dashboard)
        const authSection = document.getElementById('authSection');
        const appDashboard = document.getElementById('appDashboard');
        
        if (authSection) authSection.classList.add('d-none');
        if (appDashboard) appDashboard.classList.remove('d-none');

        // 4. Pass the entries array to your existing population function
        // (This function already handles the empty state if entries is empty/undefined)
        await decryptAndPopulateDashboard(entries, true);
        
    } catch (error) {
        console.error("Failed to initialize dashboard layout:", error);
    }
}

/**
 * Global/Reusable Verification Gate
 * Pauses execution, prompts for the Master Password, fetches keys, and returns the activeDEK.
 * @param {string} reasonText - The custom message showing why the user needs to authenticate.
 * @returns {Promise<Uint8Array>} - Resolves with the raw decrypted activeDEK upon success.
 */
async function openVerificationModal(reasonText = "Authentication required.") {
    return new Promise((resolve, reject) => {
        // Track resolution state for the close event
        let wasResolved = false; 

        // 1. Update the UI message dynamically
        const reasonEl = document.getElementById('verifyReasonText');
        if (reasonEl) reasonEl.textContent = reasonText;

        const modalEl = document.getElementById('verifyPasswordModal');
        const verifyForm = document.getElementById('verifyPasswordForm');
        const passwordInput = document.getElementById('currentPassword');
        const errorEl = document.getElementById('verifyError');

        // Clear any old values or errors
        if (errorEl) errorEl.textContent = "";
        if (passwordInput) passwordInput.value = "";

        // Show the Bootstrap Modal programmatically
        const bootstrapModal = new bootstrap.Modal(modalEl);
        bootstrapModal.show();

        // 2. Define the ONE-TIME async submit handler
        async function handleSubmit(e) {
            e.preventDefault();
            if (errorEl) errorEl.textContent = "";

            const masterPassword = passwordInput.value;

            if (!masterPassword.trim()) {
                alert("Password field cannot be empty.");
                return;
            }

            try {
                // Step A: Reach out to the server dynamically to grab salt & wrapped_dek
                const accountRes = await secureFetch('/accounts', { 
                    method: "GET", 
                    headers: { 'Content-Type': 'application/json' }
                });
                if (!accountRes.ok) throw new Error("Could not download security parameters.");
                
                const vaultParams = await accountRes.json();

                const { kek } = await deriveKeysAndTokens(masterPassword, vaultParams.salt);
                
                // Step C: Attempt local DEK decryption
                const activeDEK = await decryptDEK(vaultParams.wrapped_dek, kek);

                // SUCCESS STATE 🎉
                cryptoSession.setSession(activeDEK);
                passwordInput.value = "";
                
                // Set flag and clean up event listeners
                wasResolved = true;
                verifyForm.removeEventListener('submit', handleSubmit);
                
                // Hide the visual frame and RESOLVE the promise with the key!
                bootstrapModal.hide();
                resolve(activeDEK);

            } catch (err) {
                console.error("Re-verification failed:", err);
                if (errorEl) errorEl.textContent = "Incorrect master password. Please try again.";
                if (passwordInput) passwordInput.select();
                // We DO NOT resolve or reject here, keeping the modal open so they can try again.
            }
        }

        // Bind the form submission
        verifyForm.addEventListener('submit', handleSubmit);

        // Cleanup if they manually click close/cancel
        modalEl.addEventListener('hidden.bs.modal', () => {
            verifyForm.removeEventListener('submit', handleSubmit);
            if (!wasResolved) {
                reject(new Error("Verification cancelled by user."));
            }
        }, { once: true });
    });
}

// ========================================================
// 8. REST VAULT ENTRIES: CORE ACTIONS (Shared globally via window)
// ========================================================
async function togglePasswordVisibility(btn) {
    // 1. Correctly locate the outer card wrapper based on your HTML class
    const vaultCard = btn.closest('.vault-entry-card');
    if (!vaultCard) return;

    const passwordDisplay = vaultCard.querySelector('.entry-password-display');
    const icon = btn.querySelector('svg');
    if (!passwordDisplay || !icon) return; 

    // Pre-defined SVG icons matching your styling rules
    const eyeIconHtml = `
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
        <circle cx="12" cy="12" r="3"></circle>
    `;
    const eyeOffIconHtml = `
        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
        <line x1="1" y1="1" x2="23" y2="23"></line>
    `;

    // MODE A: Reveal the hidden password
    if (passwordDisplay.textContent === "••••••••••••") {
        
        // Step 1: Securely reset all other open passwords across the entire screen
        document.querySelectorAll('.entry-password-display').forEach(el => {
            if (el.textContent !== "••••••••••••") {
                el.textContent = "••••••••••••";
                
                // Jump to the sibling container to locate the precise companion button
                const associatedCard = el.closest('.vault-entry-card');
                if (associatedCard) {
                    // Find the toggle button using its relative attribute location
                    const companionBtn = associatedCard.querySelector('button[onclick="togglePasswordVisibility(this)"]');
                    if (companionBtn) {
                        const companionIcon = companionBtn.querySelector('svg');
                        if (companionIcon) companionIcon.innerHTML = eyeIconHtml;
                    }
                }
            }
        });

        // Step 2: Extract encrypted value
        const ciphertext = passwordDisplay.getAttribute('data-ciphertext');
        let activeDEK = cryptoSession.getDEK(); 

        // Step 3: Handle authorization drops
        if (!activeDEK) {
            try {
                // Await pauses processing right here until the modal form resolves successfully
                activeDEK = await openVerificationModal("Confirm your master password to view this secret.");
            } catch (modalCancel) {
                console.warn("View authorization bypassed by user.");
                return; // Stop processing safely if they click cancel
            }
        }

        // Step 4: Run the decryption engine
        try {
            const plainBuffer = await decryptVaultPassword(activeDEK, ciphertext); 
            const plainPassword = new TextDecoder().decode(plainBuffer);
            
            passwordDisplay.textContent = plainPassword;
            icon.innerHTML = eyeOffIconHtml;
        } catch (err) {
            console.error("Decryption error:", err);
            alert("Failed to decrypt password.");
        }

    // MODE B: Mask the visible password
    } else {
        passwordDisplay.textContent = "••••••••••••";
        icon.innerHTML = eyeIconHtml;
    }
}

async function copyToClipboard(btn) {
    const container = btn.parentElement;
    const passwordDisplay = container.querySelector('.entry-password-display');
    
    if (!passwordDisplay) return;

    const ciphertext = passwordDisplay.getAttribute('data-ciphertext');
    let activeDEK = cryptoSession.getDEK();

    if (!activeDEK) {
        try {
            // Await pauses processing right here until the modal form resolves successfully
            activeDEK = await openVerificationModal("Confirm your master password to view this secret.");
        } catch (modalCancel) {
            console.warn("View authorization bypassed by user.");
            return; // Stop processing safely if they click cancel
        }
    }

    try {
        // FIX: Replaced non-existent yourDecryptFunction with correct decryption operation
        const plainBuffer = await decryptVaultPassword(activeDEK, ciphertext);
        const plainPassword = new TextDecoder().decode(plainBuffer);
        
        await navigator.clipboard.writeText(plainPassword);
        
        const originalHTML = btn.innerHTML;
        btn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-check" viewBox="0 0 16 16">
                <path d="M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425z"/>
            </svg>
        `;
        
        setTimeout(() => {
            btn.innerHTML = originalHTML;
        }, 2000);
    } catch (err) {
        console.error("Clipboard copy operation failure:", err);
    }
}

async function deleteEntry(btn, id) {
    if (!confirm("Are you sure you want to delete this vault entry?")) return;

    const entryCard = btn.closest('.vault-entry-card');
    const restUrl = `/entries/${id}`;

    try {
        const res = await secureFetch(restUrl, { method: "DELETE" });

        if (res.status === 204) {
            if (entryCard) {
                entryCard.remove();
                console.log(`[Vault] Entry #${id} cleanly deleted from layout context.`);
            }

            const container = document.getElementById('vaultEntriesContainer');
            if (container && container.children.length === 0) {
                container.innerHTML = '<div class="mb-3"><p>No saved login credentials yet.</p></div>';
            }
            return;
        }
        
        const data = await res.json();
        throw new Error(data.error || "The server rejected the deletion request.");
    } catch (err) {
        console.error("Deletion lifecycle failure:", err);
        alert(err.message || "Network Error: System was unable to process deletion request.");
    }
}

async function submitUpdateForm(btn, id) {
    const modalContent = btn.closest('.modal-content');
    const usernameInput = modalContent.querySelector('.field-username').value;
    const passwordInput = modalContent.querySelector('.field-password').value;

    if (!usernameInput.trim()) {
        alert("Username field cannot be empty.");
        return;
    }

    const restUrl = `/entries/${id}`;

    try {
        const response = await secureFetch(restUrl, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: usernameInput,
                password: passwordInput 
            })
        });

        if (response.ok) {
            alert("Entry successfully updated!");
            const openModalElement = btn.closest('.modal');
            const modalInstance = bootstrap.Modal.getInstance(openModalElement);
            if (modalInstance) modalInstance.hide();
        } else {
            const errData = await response.json();
            alert("Update failed: " + (errData.error || "Unknown server error."));
        }
    } catch (err) {
        console.error("Update request processing failed:", err);
        alert("Network error occurred during record modification.");
    }
}

window.togglePasswordVisibility = togglePasswordVisibility;
window.copyToClipboard = copyToClipboard;
window.deleteEntry = deleteEntry;
window.submitUpdateForm = submitUpdateForm;

// ========================================================
// 9. INTERACTIVE AUTH FLOW LISTENERS (LOGIN, REG, LOGOUT)
// ========================================================
// SIGN IN ACTIONS
const loginBtn = document.getElementById('loginBtn');
if (loginBtn) {
    const loginError = document.getElementById('loginError');
    loginBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        
        const loginUrl = loginBtn.getAttribute('data-url');
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;

        if (!username.trim() || !password.trim()) {
            loginError.textContent = "Please fill out all fields.";
            return; 
        }

        try {
            let res = await fetch(loginUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },    
                body: JSON.stringify({ session_username: username })
            });

            if (!res.ok) {
                loginError.textContent = "Invalid username or password."
                return;
            }

            let authParams = await res.json();

            const { hashHex, kek } = await deriveKeysAndTokens(password, authParams.salt);
            
            let activeDEK;
            try {
                activeDEK = await decryptDEK(authParams.wrapped_dek, kek);
            } catch (dekError) {
                loginError.textContent = "Invalid username or password."
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

            if (res.ok) {
                startSessionCountdown(15);

                cryptoSession.setSession(activeDEK);

                document.getElementById("loginForm").reset();
                loginError.textContent = "";
                
                const entriesData = await secureFetch("/entries", { method: "GET" });

                const payload = await entriesData.json();

                await initializeAndLoadDashboard(payload);

                console.log("🔒 Vault unlocked. Cryptographic assets locked into runtime memory.");
            } else {
                loginError.textContent = "Invalid username or password."
                return;
            }
            } catch (globalError) {
                console.error(globalError);
                throw globalError;
        }
    });
}

// REGISTRATION ACTIONS
const registerBtn = document.getElementById('registerBtn');
if (registerBtn) {
    registerBtn.addEventListener('click', async (e) => {
        e.preventDefault();

        const registerUrl = registerBtn.getAttribute('data-url');
        const username = document.getElementById('registerUsername').value;
        const password = document.getElementById('registerPassword').value;
        const conf = document.getElementById('registerConfirm').value;

        if (!username.trim() || !password.trim() || !conf.trim()) {
            document.getElementById("registerError").textContent = "Please fill out all fields.";
            return; 
        }

        if (password !== conf) {
            document.getElementById("registerError").textContent = "Password mismatch.";
            return;
        }

        try {
            const { saltHex, hashHex, kek } = await deriveKeysAndTokens(password);
            const rawDekBytes = crypto.getRandomValues(new Uint8Array(32));
            const wrapped_dek = await encryptDEK(kek, rawDekBytes)

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

            if (res.ok) {
                startSessionCountdown(15);

                cryptoSession.setSession(wrapped_dek);

                document.getElementById("registerForm").reset();
                document.getElementById("registerError").textContent = "";

                const entriesData = await secureFetch("/entries", { method: "GET" });

                const payload = await entriesData.json();

                await initializeAndLoadDashboard(payload);

                console.log("🔒 Vault unlocked. Cryptographic assets locked into runtime memory.");
            } else {
                const payload = await res.json();
                alert("Registration failed: " + (payload.error || "Unknown server error."));
            }
        } catch (globalError) {
            console.error("Registration pipeline error:", globalError);
            alert("An unexpected network or cryptographic error occurred.");
            document.getElementById("registerForm").reset();
            document.getElementById("registerError").textContent = "";
        }
    });
}

// LOG OUT ACTIONS
const logOutBtn = document.getElementById('logOutBtn');
if (logOutBtn) {
    logOutBtn.addEventListener('click', async (e) => {
        e.preventDefault();

        const logOutUrl = logOutBtn.getAttribute('data-url');
        
        if (logOutUrl) {
            try {
                const response = await secureFetch(logOutUrl, { 
                    method: 'DELETE', 
                    credentials: 'include' 
                });

                if (!response.ok) {
                    console.warn("Token was likely already expired on arrival.");
                } else {
                    console.log("Token successfully sent to blocklist.");
                }
            } catch (err) {
                console.error("Network error during logout notice:", err);
            }
        }
        handleForcedLogout(); 
    });
}

// NEW ENTRY ACTIONS
const createVaultBtn = document.getElementById('createVaultBtn');
if (createVaultBtn) {
    createVaultBtn.addEventListener('click', async (e) => {
        e.preventDefault();

        const createVaultUrl = createVaultBtn.getAttribute('data-url');
        const website = document.getElementById('createVaultWebsite').value;
        const username = document.getElementById('createVaultUsername').value;
        const password = document.getElementById('createVaultPassword').value;

        if (!username.trim() || !password.trim() || !website.trim()) {
            document.getElementById("createVaultError").textContent = "Please fill out all fields.";
            return; 
        }

        try {
            const dek = cryptoSession.getDEK();
            

            console.log("DEK:", dek);
            console.log("Uint8Array?", dek instanceof Uint8Array);

            const ciphertext = await encryptVaultPassword(password, dek);

            const res = await secureFetch(createVaultUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    vault_website: website,
                    vault_username: username,
                    vault_ciphertext: ciphertext
                })
            });

            if (res.ok) {

                const entry = await res.json();

                const container = document.getElementById('vaultEntriesContainer');
                const template = document.getElementById('entryTemplate');
                if (!container || !template) return;

                const placeholder = container.querySelector('.no-entries-placeholder');
                if (placeholder) placeholder.remove();

                const clone = template.content.cloneNode(true);
                
                // Set unique IDs using the 'id' (Primary Key) you got from the backend
                const uniqueModalId = `updateEntryModal_${entry.id}`;
                const modalContainer = clone.querySelector('.entry-modal-container');
                const editTriggerBtn = clone.querySelector('.btn-edit-trigger');
                
                if (modalContainer && editTriggerBtn) {
                    modalContainer.id = uniqueModalId;
                    editTriggerBtn.setAttribute('data-bs-target', `#${uniqueModalId}`);
                    modalContainer.setAttribute('data-entry-id', entry.id);
                }

                // Populate content
                clone.querySelector('.entry-website').textContent = entry.website;
                clone.querySelector('.entry-username').textContent = entry.username;
                clone.querySelector('.entry-website-title-span').textContent = entry.website;
                clone.querySelector('.field-username').value = entry.username;

                // Set ciphertext
                clone.querySelector('.entry-password-display').setAttribute('data-ciphertext', entry.ciphertext);

                // Set onclick actions using the primary key
                clone.querySelector('.btn-delete-action')?.setAttribute('onclick', `deleteEntry(this, '${entry.id}')`);
                clone.querySelector('.btn-save-modal-action')?.setAttribute('onclick', `submitUpdateForm(this, '${entry.id}')`);

                initializePasswordGenerator({
                    slider: clone.querySelector('.template-slider'),
                    box: clone.querySelector('.template-box'),
                    tickContainer: clone.querySelector('.template-tick-container'),
                    passwordInput: clone.querySelector('.field-password'), 
                    fieldset: clone.querySelector('.template-generator-options'),
                    generateBtn: clone.querySelector('.template-generate-trigger'),
                    specialsCheckbox: clone.querySelector('.template-specials')
                });

                container.appendChild(clone);
            } else {
                console.error("Failed to retrieve vault entries from REST API.");
            }
            document.getElementById("entryForm").reset();
            document.getElementById("createVaultError").textContent = "";
            document.getElementById('closeVaultModalBtn').click();
        } catch (globalError) {
            console.error("Login pipeline error:", globalError);
            alert("Invalid username or password");
        }
    });
}

// PROFILE & ACCOUNT SECURITY SETTINGS
const verifyPwBtn = document.getElementById('verifyPwBtn');
if (verifyPwBtn) {
    const baseUrl = verifyPwBtn.getAttribute('data-url');
    const passwordInput = document.getElementById('currentPassword');
    const verifyForm = document.getElementById('verifyPasswordForm');
    const verifyError = document.getElementById('verifyError');

    verifyPwBtn.addEventListener('click', async (e) => {
        e.preventDefault();

        if (!passwordInput.value.trim()) {
            alert("Password field cannot be empty.");
            return; 
        }

        try {
            // Step A: Reach out to the server dynamically to grab salt & wrapped_dek
            let accountRes = await secureFetch(baseUrl, { 
                method: "GET",
                headers: { 'Content-Type': 'application/json'}
            });
            if (!accountRes.ok) throw new Error("Could not download security parameters.");
            
            const vaultParams = await accountRes.json();

            const { hashHex, kek } = await deriveKeysAndTokens(passwordInput.value, vaultParams.salt);

            accountRes = await secureFetch(baseUrl, {
                method: "POST",
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ current_hash: hashHex })
            });
            if (!accountRes.ok) {
                const payload = await accountRes.json();
                alert(payload.error)
                verifyForm.reset();
                return;
            }
            
            cryptoSession.clearSession(); 
            const activeDEK = await decryptDEK(vaultParams.wrapped_dek, kek, true);
            cryptoSession.setSession(activeDEK);

            verifyForm.reset();
            const modal1 = bootstrap.Modal.getInstance(document.getElementById('verifyPasswordModal'));
            const modal2 = new bootstrap.Modal(document.getElementById('changePasswordModal'));
            if (modal1) modal1.hide();
            if (modal2) modal2.show();
            
        } catch (err) {
            console.error("POST error:", err);
            verifyError.textContent = "Network error. Try again.";
        }
    });
}

const updateNewPwBtn = document.getElementById('updateNewPwBtn');
if (updateNewPwBtn) {
    const baseUrl = updateNewPwBtn.getAttribute('data-url');
    const patchForm = document.getElementById('patchPasswordForm');
    const newPasswordInput = document.getElementById('newPassword');
    const newConfInput = document.getElementById('newConf');
    const patchError = document.getElementById('patchError');
    updateNewPwBtn.addEventListener('click', async (e) => {
        e.preventDefault();

        if (!newPasswordInput.value.trim() || !newConfInput.value.trim()) {
            patchError.textContent = "All fields cannot be empty.";
            return;
        }

        if (newPasswordInput.value !== newConfInput.value) {
            patchError.textContent = "Password mismatch.";
            return;
        }

        try {
            const activeDEK = cryptoSession.getDEK();
            if (!activeDEK) {
                alert("Password change can't be completed due to refreshing the page or the attempt took too long.");
                patchPasswordForm.reset();
                const modal1 = bootstrap.Modal.getInstance(document.getElementById('verifyPasswordModal'));
                const modal2 = new bootstrap.Modal(document.getElementById('changePasswordModal'));
                if (modal1) modal1.show();
                if (modal2) modal2.hide();
                return;
            }
            
            const { saltHex, hashHex, kek } = await deriveKeysAndTokens(newPasswordInput.value);

            const rawDekBytes = new Uint8Array(await crypto.subtle.exportKey("raw", activeDEK));

            const wrapped_dek = await encryptDEK(kek, rawDekBytes);

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

            if (!accountRes.ok) {
                const payload = await accountRes.json();
                patchError.textContent = payload.error || "Failed to update password.";
                return;
            }
            patchForm.reset()
            alert("Master password updated successfully!");
            const modal3 = bootstrap.Modal.getInstance(document.getElementById('changePasswordModal'));
            if (modal3) modal3.hide();
        } catch (err) {
            console.error("PATCH error:", err);
            patchError.textContent = "Network error. Try again.";
        }
    });
}


// ========================================================
// 9. DOM INITIALIZATION LIFECYCLE HOOKS
// ========================================================
document.addEventListener("DOMContentLoaded", async () => {

    const clearAuthForms = () => {
        document.getElementById('loginForm')?.reset();
        document.getElementById('registerForm')?.reset();
    };

    document.getElementById('register-tab')?.addEventListener('click', clearAuthForms);
    document.getElementById('login-tab')?.addEventListener('click', clearAuthForms);
    
    initializePasswordGenerator({
        slider: document.getElementById('staticSlider'),
        box: document.getElementById('staticBox'),
        tickContainer: document.getElementById('staticTickContainer'),
        passwordInput: document.getElementById('createVaultPassword'),
        fieldset: document.getElementById('staticGeneratorOptions'),
        generateBtn: document.getElementById('staticGenerateBtn'),
        specialsCheckbox: document.getElementById('staticSpecials')
    });

    document.addEventListener('hidden.bs.modal', (event) => {
        const closingModal = event.target;
        
        const form = closingModal.querySelector('form');
        
        if (form) {
            form.reset(); 
            form.classList.remove('was-validated');
        }
        closingModal.querySelectorAll('.text-danger').forEach(errorContainer => {
            errorContainer.textContent = '';
        });
    });
    
    const registerPwInput = document.getElementById('registerPassword');
    const createVaultPwInput = document.getElementById('createVaultPassword');
    
    if (registerPwInput) {
        registerPwInput.addEventListener('input', (e) => checkStrength(e.target.value));
    }
    if (createVaultPwInput) {
        createVaultPwInput.addEventListener('input', (e) => checkStrength(e.target.value));
    }

    const appDashboard = document.getElementById('appDashboard');
    
    // Check if the dashboard is already visible due to Jinja rendering
    if (appDashboard && !appDashboard.classList.contains('d-none')) {
        try {
            const entriesData = await secureFetch("/entries", { method: "GET" });
            const payload = await entriesData.json();
            
            // Re-hydrate everything from the server response
            await initializeAndLoadDashboard(payload);
        } catch (err) {
            console.error("Silent sync failure on refresh:", err);
        }
    }
});


function getCookie(name) { const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)')); return match ? match[2] : null; }
