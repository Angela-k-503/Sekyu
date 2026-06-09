# SEKYU
A Zero-Knowledge, Single-Page Application (SPA) Password Manager using **Flask** REST API. 


---
## Security Architecture Overview
**Frontend (Vanilla SPA):**
- Handles all cryptographic operations (Argon2id, AES-GCM)
- Manages application state in-memory only 
- Communicates with backend via REST (fetch API)

**Backend (Flask API):**
- Stores only encrypted vault payloads; has no access to plaintext data or cryptographic keys
- Enforces rate limiting via Flask-Limiter to mitigate abuse
- Stateless JWT authentication (15-minute expiry, no refresh tokens)
- Strict Content Security Policy (CSP) enforcing same-origin script execution and blocking third-party JavaScript, with WebAssembly enabled for Argon2id key derivation

**Crypto Layer:**
- Argon2id (WASM) for key derivation
- AES-256-GCM for vault encryption
- Zero-knowledge design (server cannot decrypt data)

---

## Architectural Trade-offs and Reflections

While this project is fully functional, implementing a Single-Page Application (SPA) natively inside Flask produced many challenges:

* **Jinja & Python Limitations:** SPA prevents full-page reloads which I thought a neat UX but I later realized that Flask's native asset rendering engine (Jinja) becomes useless after the very first page delivery.I'm unable to use clean server-side Python logic to pass variables or dynamically render different views, which was a huge shift in mindset.

* **The Maintenance Overhead:** The burden of UI state-management that shifted entirely to the client forces me to maintain a tedious and complex, zero-knowledge cryptographic workflow of manual tracking of elements, form resets, and cleaning up event listeners.

> **P.S.** Due to the Zero-Knowledge architecture and SPA implementation, I expected the frontend to handle both the presentation and the cryptographic data state. However, it didn't truly sink in until I was in too deep working on the project that the backend would actually become the easiest part! Because the Flask API was reduced to a stateless gateway whose only job is to authorize requests and persist encrypted data payloads, the backend stayed clean but the vanilla frontend quickly became a spaghetti mess to maintain.

---
**Important Notice: Zero-Knowledge:**
> [!CAUTION]
> Because this application is strictly Zero-Knowledge, the server has zero visibility into your cryptographic components. Lost or forgotten Master Passwords cannot be recovered or reset under any circumstance. If you lose your password, your vault is permanently locked.

---

## Demo Web Access
A live, production-ready version of the site is available to test. However, to keep hosting maintenance minimal, the live site is treated as a temporary sandbox for recruiters:

- Access the Live Production Demo: `https://bonn13.pythonanywhere.com/`
- Registration required: You can use fake credentials as the app only needs a unique username to create an isolated vault.
- 24-hour Data Purge: You are welcome to test all features, but please note that all database entries are automatically deleted every 24 hours at exactly 12:00 UTC. **Do not** store actual production passwords here!
- Host It Yourself: This project is fully open-source and production-ready. If you find this architecture promising and want permanent storage, I highly encourage you to clone the repository and host it locally or on your own server.

---

## Installation & Local Setup

### Prerequisites
* **Python 3.14** (Developed and tested natively on 3.14)

* **Side Note on OS Compatibility:** This project was developed and explicitly tested on Windows. While cross-platform practices were used in the Python backend (such as standard os libraries for file paths) and the frontend uses native web APIs, it has not been verified on macOS or Linux. The instructions below are optimized for a Windows development workflow.

### Quick Start
**1. Create a Virtual Environment**
```cmd
python -m venv venv .\venv\Scripts\activate
```

**2. Install Dependencies**
```bash
pip install -r requirements.txt
```

3. Configure Environment Variables
```bash
cp .env.example .env
```
> This application requires a secure, random string for JWT_SECRET_KEY to sign session tokens safely. What I did is generate a cryptographic token directly from the terminal using Python's native secrets module.
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```
> Copy the resulting output string, open your newly created `.env` file, and paste it next to `JWT_SECRET_KEY=`. You can reference `.env.example` to see what other variables are required.

4. Run the Server
```bash
python app.py
```
