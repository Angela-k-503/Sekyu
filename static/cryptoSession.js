
let decryptedDEK = null;

export const cryptoSession = {
    setSession(dekUint8Array) {
        decryptedDEK = dekUint8Array;
    },
    getDEK() {
        return decryptedDEK;
    },
    clearSession() {
        decryptedDEK = null;
    }
};

