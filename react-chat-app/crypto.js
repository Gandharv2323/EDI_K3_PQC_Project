/**
 * AES-256-GCM Encryption Module for Node.js Bridge
 * Compatible with C++ server's EncryptionEnhanced implementation
 */

import crypto from 'crypto';

/**
 * Encrypt data using AES-256-GCM
 * @param {string} plaintext - Data to encrypt
 * @param {Buffer} key - 32-byte AES key
 * @returns {string} Base64-encoded: IV(12) + ciphertext + tag(16)
 */
export function encryptAES_GCM(plaintext, key) {
    if (key.length !== 32) {
        throw new Error(`Invalid key size: ${key.length} (expected 32)`);
    }
    
    // Generate random 12-byte IV for GCM
    const iv = crypto.randomBytes(12);
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    // Encrypt plaintext
    let ciphertext = cipher.update(plaintext, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    
    // Get authentication tag (16 bytes)
    const tag = cipher.getAuthTag();
    
    // Combine: IV(12) + ciphertext + tag(16)
    const result = Buffer.concat([iv, ciphertext, tag]);
    
    // Return as base64
    return result.toString('base64');
}

/**
 * Decrypt AES-256-GCM encrypted data
 * @param {string} ciphertext_b64 - Base64-encoded: IV(12) + ciphertext + tag(16)
 * @param {Buffer} key - 32-byte AES key
 * @returns {string} Decrypted plaintext
 * @throws {Error} If key size is invalid, data format is invalid, or decryption fails
 */
export function decryptAES_GCM(ciphertext_b64, key) {
    try {
        if (key.length !== 32) {
            throw new Error(`Invalid key size: ${key.length} (expected 32)`);
        }
        
        // Decode from base64
        const data = Buffer.from(ciphertext_b64, 'base64');
        
        // Verify minimum length: IV(12) + tag(16) = 28 bytes
        if (data.length < 28) {
            throw new Error('Data too short (missing IV or tag)');
        }
        
        // Extract IV (first 12 bytes)
        const iv = data.subarray(0, 12);
        
        // Extract tag (last 16 bytes)
        const tag = data.subarray(data.length - 16);
        
        // Extract ciphertext (middle part)
        const ciphertext = data.subarray(12, data.length - 16);
        
        // Create decipher
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        
        // Set authentication tag
        decipher.setAuthTag(tag);
        
        // Decrypt
        let plaintext = decipher.update(ciphertext, null, 'utf8');
        plaintext += decipher.final('utf8');
        
        return plaintext;
    } catch (error) {
        throw new Error(`decryptAES_GCM failed: ${error.message}`);
    }
}

/**
 * Generate random 32-byte AES key
 * @returns {Buffer} 32-byte random key
 */
export function generateKey() {
    return crypto.randomBytes(32);
}


