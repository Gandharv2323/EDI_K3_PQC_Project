/**
 * Browser-side AES-256-GCM Encryption
 * Compatible with Node.js bridge crypto implementation
 */

/**
 * Convert base64 string to Uint8Array
 */
function base64ToBytes(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

/**
 * Convert Uint8Array to base64 string
 */
function bytesToBase64(bytes) {
    const binaryString = String.fromCharCode(...bytes);
    return btoa(binaryString);
}

/**
 * Encrypt plaintext using AES-256-GCM
 * @param {string} plaintext - Data to encrypt
 * @param {Uint8Array} key - 32-byte AES key
 * @returns {Promise<string>} Base64-encoded: IV(12) + ciphertext + tag(16)
 */
export async function encryptAES_GCM(plaintext, key) {
    try {
        // Generate random 12-byte IV
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // Import key for AES-GCM
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
        
        // Encrypt
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            cryptoKey,
            data
        );
        
        // Combine IV + ciphertext (which includes tag at the end)
        const result = new Uint8Array(12 + ciphertext.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(ciphertext), 12);
        
        return bytesToBase64(result);
    } catch (error) {
        console.error('[CRYPTO] Encryption failed:', error);
        throw error;
    }
}

/**
 * Decrypt AES-256-GCM encrypted data
 * @param {string} ciphertext_b64 - Base64-encoded: IV(12) + ciphertext + tag(16)
 * @param {Uint8Array} key - 32-byte AES key
 * @returns {Promise<string>} Decrypted plaintext
 */
export async function decryptAES_GCM(ciphertext_b64, key) {
    try {
        // Decode from base64
        const data = base64ToBytes(ciphertext_b64);
        
        // Verify minimum length
        if (data.length < 28) {
            console.error('[CRYPTO] Data too short');
            return '';
        }
        
        // Extract IV (first 12 bytes)
        const iv = data.slice(0, 12);
        
        // Extract ciphertext + tag (remaining bytes)
        const ciphertext = data.slice(12);
        
        // Import key
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        // Decrypt
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            cryptoKey,
            ciphertext
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(plaintext);
    } catch (error) {
        console.error('[CRYPTO] Decryption failed:', error);
        return '';
    }
}
