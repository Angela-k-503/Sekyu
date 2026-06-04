
let decryptedDEK = null;

export const cryptoSession = Object.freeze({
    setSession(dekCryptoKey) {
        if (!(dekCryptoKey instanceof CryptoKey)) {
            throw new TypeError("cryptoSession expects a CryptoKey");
        }
        decryptedDEK = dekCryptoKey;
    },
    getDEK() {
        return decryptedDEK;
    },
    clearSession() {
        decryptedDEK = null;
    }
});

