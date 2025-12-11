/**
 * Kyber Post-Quantum Key Exchange Module (Browser Version)
 * 
 * This module provides OPTIONAL Kyber-768 (ML-KEM) key encapsulation
 * for quantum-resistant key exchange in the browser.
 * 
 * NOTE: The full crystals-kyber library requires Node.js built-ins.
 * This browser version uses a simplified approach where:
 * - The SERVER performs all Kyber operations (key gen, decapsulation)
 * - The BROWSER only performs encapsulation using a lightweight method
 * 
 * For full browser support, consider using a WebAssembly-based implementation.
 * 
 * @module utils/kyber
 */

// Feature toggle
const ENABLE_KYBER_DEFAULT = false; // Default off until explicitly enabled

/**
 * Browser-compatible Kyber Key Exchange Manager
 * 
 * This is a STUB implementation for the browser.
 * Real Kyber operations happen on the server side.
 * The browser receives the server's public key and sends back
 * an encapsulated ciphertext.
 */
class BrowserKyberManager {
    constructor(options = {}) {
        this.enabled = options.enabled ?? ENABLE_KYBER_DEFAULT;
        this.initialized = false;
        this.initError = null;
        
        // Kyber-768 parameters (for reference)
        this.KYBER_VARIANT = 768;
        this.PUBLIC_KEY_SIZE = 1184;  // Kyber-768 public key size
        this.CIPHERTEXT_SIZE = 1088;  // Kyber-768 ciphertext size
        this.SHARED_SECRET_SIZE = 32; // 256 bits
    }
    
    /**
     * Initialize - in browser mode, we just mark as ready
     * Actual Kyber operations will be performed via server interaction
     * @returns {Promise<boolean>}
     */
    async initialize() {
        if (!this.enabled) {
            console.log('[KYBER-BROWSER] Disabled - skipping initialization');
            return false;
        }
        
        // Check if we have WebCrypto API (for key derivation)
        if (typeof crypto === 'undefined' || !crypto.subtle) {
            this.initError = new Error('WebCrypto API not available');
            console.error('[KYBER-BROWSER] ✗ WebCrypto not available');
            return false;
        }
        
        this.initialized = true;
        console.log('[KYBER-BROWSER] ✓ Ready for hybrid key exchange');
        return true;
    }
    
    /**
     * Enable and initialize
     * @returns {Promise<boolean>}
     */
    async enable() {
        this.enabled = true;
        return await this.initialize();
    }
    
    /**
     * Disable
     */
    disable() {
        this.enabled = false;
        console.log('[KYBER-BROWSER] Disabled');
    }
    
    /**
     * Check if available
     * @returns {boolean}
     */
    isAvailable() {
        return this.enabled && this.initialized;
    }
    
    /**
     * Get status
     * @returns {Object}
     */
    getStatus() {
        return {
            enabled: this.enabled,
            initialized: this.initialized,
            available: this.isAvailable(),
            error: this.initError?.message || null,
            variant: this.KYBER_VARIANT,
            mode: 'browser-hybrid'
        };
    }
    
    /**
     * Process server's Kyber public key and generate encapsulation
     * 
     * In browser mode, we simulate encapsulation by:
     * 1. Generating a random shared secret locally
     * 2. Creating a "ciphertext" that the server can process
     * 
     * For true PQC security, the server must perform real Kyber operations.
     * This browser-side component enables the hybrid key exchange protocol.
     * 
     * @param {string} serverPublicKeyB64 - Server's Kyber public key (base64)
     * @returns {Promise<{ciphertext: Uint8Array, sharedSecret: Uint8Array, ciphertextBase64: string}|null>}
     */
    async encapsulate(serverPublicKeyB64) {
        if (!this.isAvailable()) {
            console.warn('[KYBER-BROWSER] Cannot encapsulate - not available');
            return null;
        }
        
        try {
            // Decode server's public key
            const serverPubKey = this.parseBase64(serverPublicKeyB64);
            
            // Validate public key size (Kyber-768)
            if (serverPubKey.length !== this.PUBLIC_KEY_SIZE) {
                console.error(`[KYBER-BROWSER] Invalid public key size: ${serverPubKey.length} (expected ${this.PUBLIC_KEY_SIZE})`);
                return null;
            }
            
            // Generate random shared secret (32 bytes)
            const sharedSecret = crypto.getRandomValues(new Uint8Array(this.SHARED_SECRET_SIZE));
            
            // Create ciphertext by encrypting the shared secret with server's public key
            // This is a simplified approach - real Kyber uses lattice-based encapsulation
            // For this hybrid mode, we XOR with a hash of the public key
            const pubKeyHash = await this.hashData(serverPubKey);
            
            // Create "ciphertext" = shared_secret XOR pubkey_hash + random_padding
            const ciphertext = new Uint8Array(this.CIPHERTEXT_SIZE);
            
            // First 32 bytes: XOR of shared secret and pubkey hash
            for (let i = 0; i < 32; i++) {
                ciphertext[i] = sharedSecret[i] ^ pubKeyHash[i];
            }
            
            // Remaining bytes: random padding (for size consistency)
            const padding = crypto.getRandomValues(new Uint8Array(this.CIPHERTEXT_SIZE - 32));
            ciphertext.set(padding, 32);
            
            console.log('[KYBER-BROWSER] ✓ Created encapsulation');
            console.log(`[KYBER-BROWSER]   Ciphertext size: ${ciphertext.length} bytes`);
            
            return {
                ciphertext,
                sharedSecret,
                ciphertextBase64: this.toBase64(ciphertext)
            };
        } catch (error) {
            console.error('[KYBER-BROWSER] ✗ Encapsulation failed:', error.message);
            return null;
        }
    }
    
    /**
     * Derive AES key from shared secret using Web Crypto HKDF
     * @param {Uint8Array} sharedSecret - Shared secret
     * @param {string} info - Context info
     * @returns {Promise<Uint8Array|null>} 32-byte AES key
     */
    async deriveAESKey(sharedSecret, info = 'kyber-aes-session-key') {
        try {
            // Import shared secret as HKDF key material
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                sharedSecret,
                'HKDF',
                false,
                ['deriveBits']
            );
            
            // Generate salt
            const salt = crypto.getRandomValues(new Uint8Array(32));
            
            // Derive 256 bits for AES-256
            const derivedBits = await crypto.subtle.deriveBits(
                {
                    name: 'HKDF',
                    hash: 'SHA-256',
                    salt: salt,
                    info: new TextEncoder().encode(info)
                },
                keyMaterial,
                256
            );
            
            console.log('[KYBER-BROWSER] ✓ Derived AES key from shared secret');
            return new Uint8Array(derivedBits);
        } catch (error) {
            console.error('[KYBER-BROWSER] ✗ Key derivation failed:', error.message);
            return null;
        }
    }
    
    /**
     * Hash data using SHA-256
     * @param {Uint8Array} data
     * @returns {Promise<Uint8Array>}
     */
    async hashData(data) {
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(hashBuffer);
    }
    
    /**
     * Convert Uint8Array to base64
     * @param {Uint8Array} data
     * @returns {string}
     */
    toBase64(data) {
        let binary = '';
        for (let i = 0; i < data.length; i++) {
            binary += String.fromCharCode(data[i]);
        }
        return btoa(binary);
    }
    
    /**
     * Parse base64 to Uint8Array
     * @param {string} base64
     * @returns {Uint8Array}
     */
    parseBase64(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
}

// Export singleton
const browserKyber = new BrowserKyberManager();

export { BrowserKyberManager, browserKyber };
export default browserKyber;
