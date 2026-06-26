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

* **Jinja & Python Limitations**: SPA prevents full-page reloads which I thought a neat UX but I later realized that Flask's native asset rendering engine (Jinja) becomes useless after the very first page delivery. I'm unable to use clean server-side Python logic to pass variables or dynamically render different views, which was a huge shift in mindset.

* **The Maintenance Overhead:** The burden of UI state-management that shifted entirely to the client forces me to maintain a tedious and complex, zero-knowledge cryptographic workflow of manual tracking of elements, form resets, and cleaning up event listeners.

* **The Web-Hosted Security Dilemma:** To mitigate script injections and XSS, I implemented a strict Content Security Policy (CSP). However, a major architectural realization was that even a perfect CSP cannot solve the "Origin Trust" problem on the web because a web-hosted SPA dynamically delivers its JavaScript bundle from the backend every session, a compromise of the Flask server or deployment pipeline allows an attacker to rewrite both the source code and the CSP headers simultaneously. Also, a standard browser tab lacks process isolation, meaning native tools (like Google Password Manager) can still attempt to sniff DOM inputs to intercept the Master Password.

> **P.S.** Due to the Zero-Knowledge architecture and SPA implementation, I expected the frontend to handle both the presentation and the cryptographic data state. However, it didn't truly sink in until I was in too deep working on the project that the backend would actually become the easiest part! Because the Flask API was reduced to a stateless, blind gateway whose only job is to authorize requests and persist encrypted data payloads, the backend stayed clean while the vanilla frontend became a complex maze to maintain. Ultimately, this project served as a major proof-of-concept; it highlighted that while web-hosted Flask apps are great for blind data vaulting, true production-grade zero-knowledge client logic ideally belongs isolated inside a dedicated Browser Extension framework to fully eliminate the Origin Trust Problem.
---

## Key Takeaways & Engineering Growth
Although a production-grade password manager is not something I would recommend deploying on a standard web architecture, building this end-to-end sandbox was an incredible engineering exercise. Stripping away the training wheels of high-level full-stack frameworks forced me to master the fundamental mechanics of secure app development:

### HTTP, Routing, and Session Architecture
* **State Control & Async Javascript:** By bypassing multi-page reloads, I gained a deep operational understanding of asynchronous JavaScript (async/await, fetch). Building this without heavy framework reliance (like React or Vue) forced me to manage the UI state completely from scratch.

* **Pure CRUD & HTTP Response Codes:** Strictly mapped API behaviors to real HTTP semantics. Managing states like 401 Unauthorized for failed master passwords or expired tokens gave me hands-on experience structuring standardized REST endpoints.

* **Stateless Auth with JWTs:** I learned how to securely issue, store, and transmit JSON Web Tokens to authenticate a client without requiring the Flask backend to maintain active session states in memory.

### Applied Cryptography (Zero-Knowledge)
* **Hashing vs. Encryption**: This project solidified exactly when to apply specific cryptographic operations. I mastered using Argon2 for one-way key derivation (transforming the master password into an authentication hash that the server can check without ever seeing the plaintext password).

* **CryptoKey Objects vs. Normal Hex Strings:** A major technical breakthrough was understanding the Web Crypto API's memory safety protocols. I learned that a raw hex string or a standard array buffer is dangerously vulnerable to memory scraping. By converting keys into native CryptoKey objects, the cryptographic material remains opaque, tightly scoped, and isolated inside the browser's internal engine, preventing basic JavaScript loops from leaking the raw key material.

---
**Important Notice: Zero-Knowledge:**
> [!CAUTION]
> Because this application is strictly Zero-Knowledge, the server has zero visibility into your cryptographic components. Lost or forgotten Master Passwords cannot be recovered or reset under any circumstance. If you lose your password, your vault is permanently locked.

---

## Demo Web Access
A live, production-ready version of the site is available to test. However, to keep hosting maintenance minimal, the live site is treated as a temporary sandbox for recruiters:

- Access the Live Deployment: [Sekyu Demo](https://bonn13.pythonanywhere.com/)
- Registration required: You can use fake credentials as the app only needs a unique username to create an isolated vault.
- 24-hour Data Purge: You are welcome to test all features, but please note that all database entries are automatically deleted every 24 hours at exactly 12:00 UTC. **Do not store actual production passwords here!**
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
