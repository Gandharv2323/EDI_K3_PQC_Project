#ifndef ENCRYPTION_ENHANCED_H
#define ENCRYPTION_ENHANCED_H

#include <string>
#include <vector>
 
/**
 * Enhanced Encryption Class
 * 
 * Implements secure cryptographic operations following NIST standards:
 * - AES-256-GCM for authenticated encryption (NIST SP 800-38D)
 * - SHA-256 for integrity verification (FIPS 180-4)
 * - PBKDF2-HMAC-SHA256 for key derivation (NIST SP 800-132)
 * - Cryptographically secure random generation
 * 
 * Security Properties:
 * - Confidentiality: AES-256 (~2^256 brute-force resistance)
 * - Authenticity: GCM tag prevents tampering
 * - Integrity: SHA-256 hash verification
 * - Key Derivation: PBKDF2 with 200k iterations (OWASP 2023)
 */
class EncryptionEnhanced {
private:
    // AES-256 requires 32-byte key
    // WARNING: Static key shared across application (insecure for production)
    static const std::string AES_KEY;
    
    // DEPRECATED: Static IV - NO LONGER USED
    // v2.0+ generates random IVs per encryption call
    // This static member exists only for backward compatibility in decryption
    static const unsigned char IV[12];
    
    // PBKDF2 iteration count (OWASP 2023 minimum: 200k)
    static const int PBKDF2_ITERATIONS = 200000;
    
    // Salt size for PBKDF2: 128 bits (16 bytes)
    static const int SALT_SIZE = 16;
    
    // GCM authentication tag size: 128 bits (16 bytes)
    static const int GCM_TAG_SIZE = 16;
    
public:
    // ============================================
    // Hash Functions
    // ============================================
    
    /**
     * SHA-256 Hash Function
     * 
     * Purpose: Independent integrity verification
     * Output: 64-character hexadecimal string (256 bits)
     * 
     * Security Properties:
     * - Collision Resistance: ~2^128 operations
     * - Preimage Resistance: ~2^256 operations
     * - Avalanche Effect: 1-bit change → ~50% output change
     * 
     * @param input - Data to hash
     * @return Hexadecimal hash string
     */
    static std::string sha256(const std::string& input);
    
    // ============================================
    // AES-256-GCM Encryption (AEAD)
    // ============================================
    
    /**
     * AES-256-GCM Encryption with AAD (Dynamic Key/IV)
     * BINARY BUFFER API - RECOMMENDED
     * 
     * Algorithm: AES-256-GCM (NIST SP 800-38D)
     * Mode: Galois/Counter Mode (Authenticated Encryption)
     * Key Size: 256 bits (32 bytes)
     * IV Size: 96 bits (12 bytes) - GCM recommended
     * Tag Size: 128 bits (16 bytes)
     * 
     * This API accepts binary buffers with explicit lengths, preventing
     * issues with embedded null bytes in keys/IVs.
     * 
     * VALIDATION BEHAVIOR:
     * - Validates key_len == 32 (AES-256 requirement)
     * - Validates iv_len == 12 (GCM recommended size)
     * - Throws std::invalid_argument on size mismatch with message:
     *   "Invalid key size: expected 32 bytes, got N bytes" OR
     *   "Invalid IV size: expected 12 bytes, got N bytes"
     * - Fail-fast on invalid input (no partial encryption)
     * 
     * CALLER RESPONSIBILITIES:
     * - Provide correctly sized buffers (32-byte key, 12-byte IV)
     * - Generate a fresh, cryptographically secure random IV for EVERY encryption
     * - NEVER reuse IVs with the same key (breaks GCM security completely)
     * - Use generateIV() to create cryptographically secure random IVs
     * - Manage key lifecycle securely (use SecureKeyBuffer, lock memory)
     * 
     * IV SECURITY CRITICAL:
     * Reusing an IV with the same key in GCM mode allows attackers to:
     * - Recover the authentication key
     * - Forge authenticated messages
     * - Decrypt all messages encrypted with that (key, IV) pair
     * 
     * @param plaintext - Data to encrypt
     * @param key - Encryption key (must be exactly 32 bytes)
     * @param key_len - Length of key (must be 32)
     * @param iv - Initialization vector (must be exactly 12 bytes, fresh random per call)
     * @param iv_len - Length of IV (must be 12)
     * @param aad - Additional authenticated data (optional)
     * @param aad_len - Length of AAD (0 if aad is null/empty)
     * @return Base64-encoded: IV(12) + ciphertext + tag(16)
     * @throws std::invalid_argument - If key_len != 32 or iv_len != 12
     */
    static std::string encryptAES_GCM(const std::string& plaintext, 
                                       const unsigned char* key, size_t key_len,
                                       const unsigned char* iv, size_t iv_len,
                                       const unsigned char* aad = nullptr, size_t aad_len = 0);
    
    /**
     * AES-256-GCM Encryption with AAD (Dynamic Key/IV)
     * STRING API - FOR BACKWARD COMPATIBILITY ONLY
     * 
     * WARNING: This API is fragile for binary keys with embedded nulls.
     * Use the binary buffer API instead (new signature above).
     * 
     * If using this API, IMPORTANT:
     * - Construct std::string with explicit length: std::string(ptr, len)
     * - Never use c_str() or assume null-termination for binary data
     * - Use data() for accessing binary data, not c_str()
     * 
     * @param plaintext - Data to encrypt
     * @param key - 32-byte encryption key (std::string with binary data)
     * @param iv - 12-byte IV (std::string with binary data)
     * @param aad - Additional authenticated data (optional)
     * @return Base64-encoded: IV(12) + ciphertext + tag(16)
     */
    static std::string encryptAES_GCM(const std::string& plaintext, 
                                       const std::string& key,
                                       const std::string& iv,
                                       const std::string& aad = "");
    
    /**
     * AES-256-GCM Decryption with AAD (Dynamic Key/IV)
     * BINARY BUFFER API - RECOMMENDED
     * 
     * Verifies:
     * 1. Ciphertext integrity (GCM tag)
     * 2. AAD authenticity
     * 3. No tampering occurred
     * 
     * @param ciphertext_b64 - Base64: IV(12) + ciphertext + tag(16)
     * @param key - Decryption key (must be exactly 32 bytes)
     * @param key_len - Length of key (must be 32)
     * @param aad - Additional authenticated data (optional)
     * @param aad_len - Length of AAD (0 if aad is null/empty)
     * @return Decrypted plaintext (empty if verification fails)
     */
    static std::string decryptAES_GCM(const std::string& ciphertext_b64,
                                       const unsigned char* key, size_t key_len,
                                       const unsigned char* aad = nullptr, size_t aad_len = 0);
    
    /**
     * AES-256-GCM Decryption with AAD (Dynamic Key/IV)
     * STRING API - FOR BACKWARD COMPATIBILITY ONLY
     * 
     * WARNING: This API is fragile for binary keys with embedded nulls.
     * Use the binary buffer API instead (new signature above).
     * 
     * If using this API, IMPORTANT:
     * - Construct std::string with explicit length: std::string(ptr, len)
     * - Never use c_str() or assume null-termination for binary data
     * 
     * @param ciphertext_b64 - Base64: IV(12) + ciphertext + tag(16)
     * @param key - 32-byte decryption key (std::string with binary data)
     * @param aad - Must match encryption AAD
     * @return Decrypted plaintext (empty if verification fails)
     */
    static std::string decryptAES_GCM(const std::string& ciphertext_b64,
                                       const std::string& key,
                                       const std::string& aad = "");
    
    /**
     * Legacy AES-256-GCM (DEPRECATED - BREAKING CHANGE)
     * 
     * WHAT THIS FUNCTION DOES:
     * - Uses STATIC hardcoded AES_KEY from class member (line 25) - INSECURE KEY MANAGEMENT
     * - Generates RANDOM IV per call (v2.0 fix) - SECURE IV HANDLING
     * - Exists for callers without their own key management
     * 
     * SECURITY WARNING: Previous v1.x used STATIC IV which breaks GCM security!
     * This has been FIXED in v2.0 to generate a fresh IV per call.
     * 
     * KEY vs IV DISTINCTION:
     * - Key: Uses class static member AES_KEY (insecure - shared across app)
     * - IV: Generates fresh random value per call (secure - unique per message)
     * 
     * BREAKING CHANGE:
     * - Old (v1.x): Used static IV[12] class member - INSECURE!
     * - New (v2.0): Generates random IV per call - NOW SECURE!
     * 
     * This means:
     * - Data encrypted with v1.x CANNOT be decrypted with v2.0
     * - This function WILL LOG AN ERROR on first use
     * - Output format changed: now includes IV (same as modern encryptAES_GCM)
     * 
     * WHY IT'S STILL "LEGACY":
     * The static AES_KEY is a security weakness (key reuse, not rotatable, visible in code).
     * Modern applications should use encryptAES_GCM() with dynamic keys.
     * 
     * MIGRATION PATH:
     * 1. Decrypt all legacy v1.x ciphertexts using old binary (before upgrade)
     * 2. Re-encrypt using new encryptAES_GCM() with proper random keys AND IVs
     * 3. Update all callers to manage their own keys (e.g., from key derivation)
     * 4. Stop using static class keys entirely
     * 5. Plan to remove this function in v3.0
     * 
     * DO NOT USE IN NEW CODE - Use encryptAES_GCM() with dynamic keys instead!
     * 
     * @param plaintext - Data to encrypt
     * @param aad - Additional authenticated data (optional)
     * @return Base64-encoded: IV(12) + ciphertext + tag(16) [NEW FORMAT]
     */
    static std::string encryptAES_GCM_Legacy(const std::string& plaintext, const std::string& aad = "");
    
    /**
     * Legacy AES-256-GCM Decryption (DEPRECATED - BREAKING CHANGE)
     * 
     * WHAT THIS FUNCTION DOES:
     * - Uses STATIC hardcoded AES_KEY from class member (line 25)
     * - Decrypts data that was encrypted with Legacy function
     * - Handles BOTH old (v1.x) and new (v2.0) ciphertext formats
     * 
     * COMPANION TO: encryptAES_GCM_Legacy (uses same static AES_KEY)
     * 
     * This function can decrypt BOTH:
     * - New v2.0 format: IV(12) + ciphertext + tag(16) [encrypted with random IV]
     * - Old v1.x format: ciphertext + tag(16) [encrypted with static IV[12] member - INSECURE]
     * 
     * FORMAT AUTO-DETECTION ALGORITHM:
     * 
     * Step 1: Size-based heuristic
     *   - If decoded_size >= 28 bytes (12 IV + 16 tag minimum) → Try v2.0 format
     *   - If decoded_size < 28 bytes → Skip to v1.x format (cannot have IV prefix)
     * 
     * Step 2: Try-decrypt v2.0 (if size check passed)
     *   - Attempt to decrypt assuming first 12 bytes are IV
     *   - Call decryptAES_GCM() with static AES_KEY
     *   - If decryption succeeds (GCM tag verifies) → Return result
     *   - If decryption fails (tag mismatch) → Fall through to Step 3
     * 
     * Step 3: Fallback to v1.x format
     *   - Assume entire decoded data is: ciphertext + tag(16)
     *   - Use static IV[12] class member from line 29 (INSECURE)
     *   - Attempt decryption with static key AND static IV
     *   - If GCM tag verifies → Return result with security warning
     *   - If tag fails → Return empty string (authentication failed)
     * 
     * RELIABILITY CONCERNS (acknowledged):
     * - False positive risk: If v1.x ciphertext starts with 12 bytes that happen to decrypt
     *   successfully when interpreted as v2.0 IV, function returns wrong result
     * - Side-channel risk: Attempting decryption for format detection exposes timing info
     * - No explicit version marker - relies on implicit size/decrypt success heuristics
     * 
     * RECOMMENDED ALTERNATIVES (not currently implemented):
     * - Option 1: Add version prefix (e.g., "v2:" before Base64 encoding)
     * - Option 2: Separate functions (decryptAES_GCM_Legacy_V1 / _V2)
     * - Option 3: Migrate all old data and deprecate v1.x support entirely
     * 
     * CURRENT BEHAVIOR: Best-effort auto-detection for gradual migration
     * 
     * SECURITY NOTE:
     * Both formats use the static AES_KEY (insecure key management).
     * Only the IV handling differs (v1.x static vs v2.0 random).
     * 
     * DO NOT USE IN NEW CODE - Use decryptAES_GCM() with dynamic keys instead!
     * 
     * @param ciphertext_b64 - Base64 ciphertext (NEW or OLD format)
     * @param aad - Must match encryption AAD
     * @return Decrypted plaintext (empty if verification fails)
     */
    static std::string decryptAES_GCM_Legacy(const std::string& ciphertext_b64, const std::string& aad = "");
    
    // ============================================
    // Legacy AES-256-CBC (Educational)
    // ============================================
    
    /**
     * AES-256-CBC Encryption (Legacy/Educational)
     * 
     * WARNING: CBC mode does NOT provide authentication!
     * Use AES-GCM for production.
     * 
     * Included for educational comparison:
     * - Shows difference between encryption-only vs AEAD
     * - Demonstrates need for separate MAC
     * 
     * @param plaintext - Data to encrypt
     * @return Base64-encoded ciphertext
     */
    static std::string encryptAES(const std::string& plaintext);
    
    /**
     * AES-256-CBC Decryption (Legacy/Educational)
     * 
     * @param ciphertext_b64 - Base64 ciphertext
     * @return Decrypted plaintext
     */
    static std::string decryptAES(const std::string& ciphertext_b64);
    
    // ============================================
    // Base64 Encoding/Decoding
    // ============================================
    
    /**
     * Base64 Encoding
     * 
     * Converts binary data to ASCII text for transmission
     * Standard: RFC 4648
     * 
     * @param input - Binary data
     * @return Base64 string
     */
    static std::string base64Encode(const std::vector<unsigned char>& input);
    
    /**
     * Base64 Decoding
     * 
     * @param input - Base64 string
     * @return Binary data
     */
    static std::vector<unsigned char> base64Decode(const std::string& input);
    
    // ============================================
    // Key Derivation (PBKDF2)
    // ============================================
    
    /**
     * PBKDF2-HMAC-SHA256 Key Derivation
     * 
     * Standard: NIST SP 800-132, RFC 8018
     * Iterations: 200,000 (OWASP 2023 minimum)
     * Output: 256-bit key for AES-256
     * 
     * Process:
     * Passphrase + Salt (128-bit random) →
     * PBKDF2-HMAC-SHA256 (200k iterations) →
     * 256-bit Derived Key
     * 
     * Security:
     * - Salt prevents rainbow table attacks
     * - High iteration count increases brute-force cost
     * - ~100ms computation time on modern hardware
     * 
     * @param passphrase - User-provided passphrase
     * @param salt - Random salt (hex string)
     * @return Derived key (hex string, 256 bits)
     */
    static std::string deriveKey(const std::string& passphrase, const std::string& salt);
    
    // ============================================
    // Password Hashing
    // ============================================
    
    /**
     * Hash Password with Salt
     * 
     * Uses PBKDF2-HMAC-SHA256 for password storage
     * 
     * @param password - User password
     * @param salt - Random salt (hex string)
     * @return Password hash (hex string)
     */
    static std::string hashPassword(const std::string& password, const std::string& salt);
    
    /**
     * Verify Password Against Hash
     * 
     * Constant-time comparison to prevent timing attacks
     * 
     * @param password - Password to verify
     * @param hash - Stored password hash
     * @param salt - Salt used during hashing
     * @return true if password matches
     */
    static bool verifyPassword(const std::string& password, const std::string& hash, const std::string& salt);
    
    // ============================================
    // Random Generation
    // ============================================
    
    /**
     * Generate Cryptographically Secure Random Salt
     * 
     * Uses OpenSSL RAND_bytes (CSPRNG)
     * Size: 128 bits (16 bytes)
     * 
     * @return Random salt (hex string)
     */
    static std::string generateSalt();
    
    /**
     * Generate Random IV for AES-GCM
     * 
     * Size: 96 bits (12 bytes) - GCM recommended
     * CRITICAL: Never reuse IV with same key!
     * 
     * @return Random IV (12 raw bytes as string)
     */
    static std::string generateIV();
    
    /**
     * Generate Random Encryption Key
     * 
     * Size: 256 bits (32 bytes) for AES-256
     * 
     * @return Random key (32 raw bytes as string)
     */
    static std::string generateKey();
    
    /**
     * Generate Random Nonce
     * 
     * General-purpose random data generation
     * 
     * @param size - Number of bytes
     * @return Random data (hex string)
     */
    static std::string generateNonce(size_t size);
};

#endif
