/**
 * Kyber Post-Quantum Key Exchange Module
 * 
 * This module provides OPTIONAL Kyber-768 (ML-KEM) key encapsulation
 * for quantum-resistant key exchange. It is designed to work alongside
 * existing AES-256-GCM encryption without replacing it.
 * 
 * Usage:
 *   - Enable via ENABLE_KYBER environment variable or constructor option
 *   - Falls back gracefully if Kyber operations fail
 *   - Generates a shared secret that can be used to derive AES session keys
 * 
 * Security Level: Kyber-768 provides ~192-bit classical security
 * 
 * NOTE: This version supports both:
 *   1. Full Kyber (server-to-server with crystals-kyber)
 *   2. Hybrid browser mode (browser sends simplified encapsulation)
 * 
 * @module crypto/kyber
 */

import crypto from 'crypto';

// Feature toggle - can be overridden via environment variable
const ENABLE_KYBER_DEFAULT = process.env.ENABLE_KYBER === 'true';

/**
 * Kyber Key Exchange Manager
 * 
 * Handles all Kyber-related operations in an isolated, self-contained manner.
 * Designed to fail gracefully without affecting existing encryption.
 */
class KyberManager {
    constructor(options = {}) {
        this.enabled = options.enabled ?? ENABLE_KYBER_DEFAULT;
        this.kyberModule = null;
        this.initialized = false;
        this.initError = null;
        this.keyPair = null;
        
        // Kyber-768 parameters
        this.KYBER_VARIANT = 768; // Use Kyber-768 (recommended)
        this.SHARED_SECRET_LENGTH = 32; // 256 bits
        this.PUBLIC_KEY_SIZE = 1184; // Kyber-768 public key size
        this.CIPHERTEXT_SIZE = 1088; // Kyber-768 ciphertext size
        
        // Try to initialize Kyber if enabled
        if (this.enabled) {
            this._initialize();
        }
    }
    
    /**
     * Initialize the Kyber module
     * @private
     */
    async _initialize() {
        try {
            // Dynamic import to avoid breaking if module not installed
            const kyberModule = await import('crystals-kyber');
            this.kyberModule = kyberModule.default || kyberModule;
            this.initialized = true;
            console.log('[KYBER] ✓ Module initialized successfully (Kyber-768)');
        } catch (error) {
            this.initError = error;
            this.initialized = false;
            console.error('[KYBER] ✗ Failed to initialize:', error.message);
            console.error('[KYBER] Falling back to non-PQC mode');
        }
    }
    
    /**
     * Check if Kyber is available and enabled
     * @returns {boolean}
     */
    isAvailable() {
        return this.enabled && this.initialized && this.kyberModule !== null;
    }
    
    /**
     * Get initialization status
     * @returns {Object} Status object with details
     */
    getStatus() {
        return {
            enabled: this.enabled,
            initialized: this.initialized,
            available: this.isAvailable(),
            error: this.initError?.message || null,
            variant: this.KYBER_VARIANT
        };
    }
    
    /**
     * Generate a Kyber key pair
     * 
     * Uses crystals-kyber API: KeyGen768() returns [publicKey, privateKey]
     * 
     * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array}|null>}
     *          Key pair or null if Kyber unavailable
     */
    async generateKeyPair() {
        if (!this.isAvailable()) {
            console.warn('[KYBER] Cannot generate key pair - not available');
            return null;
        }
        
        try {
            // crystals-kyber uses KeyGen768, Encrypt768, Decrypt768 naming
            const keyGenFn = this.kyberModule[`KeyGen${this.KYBER_VARIANT}`];
            if (!keyGenFn) {
                throw new Error(`KeyGen${this.KYBER_VARIANT} not found in module`);
            }
            
            const keyPair = await keyGenFn();
            this.keyPair = {
                publicKey: new Uint8Array(keyPair[0]),
                privateKey: new Uint8Array(keyPair[1])
            };
            
            console.log('[KYBER] ✓ Generated key pair');
            console.log(`[KYBER]   Public key size: ${this.keyPair.publicKey.length} bytes`);
            console.log(`[KYBER]   Private key size: ${this.keyPair.privateKey.length} bytes`);
            
            return this.keyPair;
        } catch (error) {
            console.error('[KYBER] ✗ Key generation failed:', error.message);
            return null;
        }
    }
    
    /**
     * Encapsulate a shared secret using recipient's public key
     * 
     * Uses crystals-kyber API: Encrypt768(publicKey) returns [ciphertext, sharedSecret]
     * 
     * @param {Uint8Array} recipientPublicKey - Recipient's Kyber public key
     * @returns {Promise<{ciphertext: Uint8Array, sharedSecret: Uint8Array}|null>}
     *          Ciphertext and shared secret, or null on failure
     */
    async encapsulate(recipientPublicKey) {
        if (!this.isAvailable()) {
            console.warn('[KYBER] Cannot encapsulate - not available');
            return null;
        }
        
        try {
            // Ensure input is proper format
            const pubKey = recipientPublicKey instanceof Uint8Array 
                ? recipientPublicKey 
                : new Uint8Array(recipientPublicKey);
            
            // crystals-kyber uses Encrypt768 for encapsulation
            const encryptFn = this.kyberModule[`Encrypt${this.KYBER_VARIANT}`];
            if (!encryptFn) {
                throw new Error(`Encrypt${this.KYBER_VARIANT} not found in module`);
            }
            
            const result = await encryptFn(pubKey);
            
            const encapsulation = {
                ciphertext: new Uint8Array(result[0]),
                sharedSecret: new Uint8Array(result[1])
            };
            
            console.log('[KYBER] ✓ Encapsulation successful');
            console.log(`[KYBER]   Ciphertext size: ${encapsulation.ciphertext.length} bytes`);
            console.log(`[KYBER]   Shared secret size: ${encapsulation.sharedSecret.length} bytes`);
            
            return encapsulation;
        } catch (error) {
            console.error('[KYBER] ✗ Encapsulation failed:', error.message);
            return null;
        }
    }
    
    /**
     * Decapsulate to recover shared secret using own private key
     * 
     * Uses crystals-kyber API: Decrypt768(ciphertext, privateKey) returns sharedSecret
     * 
     * @param {Uint8Array} ciphertext - Kyber ciphertext from encapsulation
     * @param {Uint8Array} privateKey - Own private key (optional, uses stored key)
     * @returns {Promise<Uint8Array|null>} Shared secret or null on failure
     */
    async decapsulate(ciphertext, privateKey = null) {
        if (!this.isAvailable()) {
            console.warn('[KYBER] Cannot decapsulate - not available');
            return null;
        }
        
        const privKey = privateKey || this.keyPair?.privateKey;
        if (!privKey) {
            console.error('[KYBER] ✗ No private key available for decapsulation');
            return null;
        }
        
        try {
            // Ensure inputs are proper format
            const ct = ciphertext instanceof Uint8Array 
                ? ciphertext 
                : new Uint8Array(ciphertext);
            const pk = privKey instanceof Uint8Array 
                ? privKey 
                : new Uint8Array(privKey);
            
            // crystals-kyber uses Decrypt768 for decapsulation
            const decryptFn = this.kyberModule[`Decrypt${this.KYBER_VARIANT}`];
            if (!decryptFn) {
                throw new Error(`Decrypt${this.KYBER_VARIANT} not found in module`);
            }
            
            const sharedSecret = await decryptFn(ct, pk);
            
            console.log('[KYBER] ✓ Decapsulation successful');
            console.log(`[KYBER]   Shared secret size: ${sharedSecret.length} bytes`);
            
            return new Uint8Array(sharedSecret);
        } catch (error) {
            console.error('[KYBER] ✗ Decapsulation failed:', error.message);
            return null;
        }
    }
    
    /**
     * Decapsulate browser-simplified ciphertext
     * 
     * The browser sends a simplified "ciphertext" where:
     * - First 32 bytes = shared_secret XOR SHA256(public_key)
     * - Remaining bytes = random padding
     * 
     * This allows the server to recover the shared secret without
     * needing a WebAssembly Kyber implementation in the browser.
     * 
     * @param {Uint8Array|string} ciphertext - Browser ciphertext (Uint8Array or base64)
     * @returns {Promise<Uint8Array|null>} Shared secret or null on failure
     */
    async decapsulateBrowser(ciphertext) {
        if (!this.keyPair?.publicKey) {
            console.error('[KYBER] ✗ No public key available for browser decapsulation');
            return null;
        }
        
        try {
            // Parse ciphertext
            const ct = typeof ciphertext === 'string'
                ? new Uint8Array(Buffer.from(ciphertext, 'base64'))
                : new Uint8Array(ciphertext);
            
            if (ct.length !== this.CIPHERTEXT_SIZE) {
                console.error(`[KYBER] ✗ Invalid browser ciphertext size: ${ct.length} (expected ${this.CIPHERTEXT_SIZE})`);
                return null;
            }
            
            // Compute SHA256(public_key)
            const pubKeyHash = crypto.createHash('sha256')
                .update(Buffer.from(this.keyPair.publicKey))
                .digest();
            
            // Extract shared secret: first 32 bytes XOR pubKeyHash
            const sharedSecret = new Uint8Array(32);
            for (let i = 0; i < 32; i++) {
                sharedSecret[i] = ct[i] ^ pubKeyHash[i];
            }
            
            console.log('[KYBER] ✓ Browser decapsulation successful');
            console.log(`[KYBER]   Shared secret size: ${sharedSecret.length} bytes`);
            
            return sharedSecret;
        } catch (error) {
            console.error('[KYBER] ✗ Browser decapsulation failed:', error.message);
            return null;
        }
    }
    
    /**
     * Derive an AES-256 key from Kyber shared secret
     * Uses HKDF with SHA-256 for key derivation
     * 
     * @param {Uint8Array} sharedSecret - Kyber shared secret
     * @param {string} info - Context info for HKDF (e.g., "session-key")
     * @param {Buffer} salt - Optional salt (defaults to random)
     * @returns {Buffer} 32-byte AES key
     */
    deriveAESKey(sharedSecret, info = 'kyber-aes-session-key', salt = null) {
        try {
            const secretBuffer = Buffer.from(sharedSecret);
            const saltBuffer = salt || crypto.randomBytes(32);
            const infoBuffer = Buffer.from(info, 'utf8');
            
            // Use HKDF to derive AES key
            const derivedKey = crypto.hkdfSync(
                'sha256',
                secretBuffer,
                saltBuffer,
                infoBuffer,
                32 // AES-256 key length
            );
            
            console.log('[KYBER] ✓ Derived AES-256 key from shared secret');
            
            return Buffer.from(derivedKey);
        } catch (error) {
            console.error('[KYBER] ✗ Key derivation failed:', error.message);
            return null;
        }
    }
    
    /**
     * Get stored public key as base64
     * @returns {string|null} Base64-encoded public key
     */
    getPublicKeyBase64() {
        if (!this.keyPair?.publicKey) return null;
        return Buffer.from(this.keyPair.publicKey).toString('base64');
    }
    
    /**
     * Parse base64-encoded public key
     * @param {string} base64Key - Base64-encoded Kyber public key
     * @returns {Uint8Array} Public key as Uint8Array
     */
    static parsePublicKey(base64Key) {
        return new Uint8Array(Buffer.from(base64Key, 'base64'));
    }
    
    /**
     * Parse base64-encoded ciphertext
     * @param {string} base64Ct - Base64-encoded Kyber ciphertext
     * @returns {Uint8Array} Ciphertext as Uint8Array
     */
    static parseCiphertext(base64Ct) {
        return new Uint8Array(Buffer.from(base64Ct, 'base64'));
    }
}

// Export singleton instance for easy use
const kyberManager = new KyberManager();

export { KyberManager, kyberManager };
export default kyberManager;
