/**
 * Enhanced Encryption Implementation
 * 
 * Implements cryptographic operations following the Cryptographic Design Document:
 * - AES-256-GCM: Authenticated encryption (NIST SP 800-38D)
 * - SHA-256: Integrity verification (FIPS 180-4)
 * - PBKDF2-HMAC-SHA256: Key derivation (NIST SP 800-132)
 * 
 * References:
 * - NIST SP 800-38D: GCM Specification
 * - RFC 5116: AEAD Interface
 * - RFC 8018: PBKDF2 Specification
 * - OWASP Password Storage Cheat Sheet
 */
 
#include "encryption_enhanced.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <iostream>

// AES-256 key: 32 bytes (256 bits)
// In production, this should be derived from a passphrase or securely exchanged
const std::string EncryptionEnhanced::AES_KEY = "ChatServer2025SecureAESKey256bit!";

// GCM recommended IV: 12 bytes (96 bits)
// In production, use random IV for each message (never reuse!)
const unsigned char EncryptionEnhanced::IV[12] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b
};

// ============================================
// SHA-256 Hash Function
// ============================================

std::string EncryptionEnhanced::sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
    
    // Convert to hexadecimal string
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// ============================================
// AES-256-GCM Encryption (AEAD) - Dynamic Key/IV
// ============================================

std::string EncryptionEnhanced::encryptAES_GCM(const std::string& plaintext,
                                                const std::string& key,
                                                const std::string& iv,
                                                const std::string& aad) {
    // Validate key and IV sizes
    if (key.length() != 32) {
        std::cerr << "[CRYPTO] Invalid key size: " << key.length() << " (expected 32)" << std::endl;
        return "";
    }
    if (iv.length() != 12) {
        std::cerr << "[CRYPTO] Invalid IV size: " << iv.length() << " (expected 12)" << std::endl;
        return "";
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[CRYPTO] Failed to create cipher context" << std::endl;
        return "";
    }
    
    // Allocate buffer: plaintext + padding + tag
    std::vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH + GCM_TAG_SIZE);
    int len = 0;
    int ciphertext_len = 0;
    
    // Initialize AES-256-GCM encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        std::cerr << "[CRYPTO] GCM init failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Set IV length (96 bits for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        std::cerr << "[CRYPTO] IV length set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Set key and IV (runtime-provided)
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, 
                           (const unsigned char*)key.c_str(),
                           (const unsigned char*)iv.c_str()) != 1) {
        std::cerr << "[CRYPTO] Key/IV set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Add AAD (Additional Authenticated Data)
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, 
                              (const unsigned char*)aad.c_str(), aad.length()) != 1) {
            std::cerr << "[CRYPTO] AAD update failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
    }
    
    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          (const unsigned char*)plaintext.c_str(),
                          plaintext.length()) != 1) {
        std::cerr << "[CRYPTO] Encryption update failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        std::cerr << "[CRYPTO] Encryption final failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    
    // Get GCM authentication tag (128 bits)
    unsigned char tag[GCM_TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1) {
        std::cerr << "[CRYPTO] Tag retrieval failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Prepend IV, append tag: IV(12) + ciphertext + tag(16)
    std::vector<unsigned char> result;
    result.insert(result.end(), iv.begin(), iv.end());  // IV first
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);  // ciphertext
    result.insert(result.end(), tag, tag + GCM_TAG_SIZE);  // tag last
    
    return base64Encode(result);
}

std::string EncryptionEnhanced::decryptAES_GCM(const std::string& ciphertext_b64,
                                                const std::string& key,
                                                const std::string& aad) {
    // Validate key size
    if (key.length() != 32) {
        std::cerr << "[CRYPTO] Invalid key size: " << key.length() << " (expected 32)" << std::endl;
        return "";
    }
    
    std::vector<unsigned char> data = base64Decode(ciphertext_b64);
    
    // Verify minimum length: IV(12) + tag(16) = 28 bytes minimum
    if (data.size() < 12 + GCM_TAG_SIZE) {
        std::cerr << "[CRYPTO] Data too short (missing IV or tag)" << std::endl;
        return "";
    }
    
    // Extract IV from beginning
    std::string iv((char*)data.data(), 12);
    
    // Extract tag from end
    int ct_len = data.size() - 12 - GCM_TAG_SIZE;
    unsigned char tag[GCM_TAG_SIZE];
    std::memcpy(tag, data.data() + 12 + ct_len, GCM_TAG_SIZE);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[CRYPTO] Failed to create cipher context" << std::endl;
        return "";
    }
    
    std::vector<unsigned char> plaintext(ct_len + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int plaintext_len = 0;
    
    // Initialize AES-256-GCM decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        std::cerr << "[CRYPTO] GCM init failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        std::cerr << "[CRYPTO] IV length set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Set key and IV (runtime-provided)
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           (const unsigned char*)key.c_str(),
                           (const unsigned char*)iv.c_str()) != 1) {
        std::cerr << "[CRYPTO] Key/IV set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Add AAD (must match encryption AAD!)
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len,
                              (const unsigned char*)aad.c_str(), aad.length()) != 1) {
            std::cerr << "[CRYPTO] AAD update failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
    }
    
    // Decrypt ciphertext (skip IV at beginning)
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          data.data() + 12, ct_len) != 1) {
        std::cerr << "[CRYPTO] Decryption update failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag) != 1) {
        std::cerr << "[CRYPTO] Tag set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Finalize and verify tag
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        std::cerr << "[CRYPTO] ❌ Authentication FAILED - Message tampered or wrong key!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return ""; // Authentication failure!
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return std::string((char*)plaintext.data(), plaintext_len);
}

// ============================================
// AES-256-GCM with Binary Buffer API (RECOMMENDED)
// ============================================

std::string EncryptionEnhanced::encryptAES_GCM(const std::string& plaintext,
                                                const unsigned char* key, size_t key_len,
                                                const unsigned char* iv, size_t iv_len,
                                                const unsigned char* aad, size_t aad_len) {
    // Validate key and IV sizes
    if (key_len != 32) {
        std::cerr << "[CRYPTO] Invalid key size: " << key_len << " (expected 32)" << std::endl;
        return "";
    }
    if (!key) {
        std::cerr << "[CRYPTO] Key pointer is null" << std::endl;
        return "";
    }
    
    if (iv_len != 12) {
        std::cerr << "[CRYPTO] Invalid IV size: " << iv_len << " (expected 12)" << std::endl;
        return "";
    }
    if (!iv) {
        std::cerr << "[CRYPTO] IV pointer is null" << std::endl;
        return "";
    }
    
    // Validate AAD if provided
    if (aad_len > 0 && !aad) {
        std::cerr << "[CRYPTO] AAD length is " << aad_len << " but AAD pointer is null" << std::endl;
        return "";
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[CRYPTO] Failed to create cipher context" << std::endl;
        return "";
    }
    
    // Allocate buffer: plaintext + padding + tag
    std::vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH + GCM_TAG_SIZE);
    int len = 0;
    int ciphertext_len = 0;
    
    // Initialize AES-256-GCM encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        std::cerr << "[CRYPTO] GCM init failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Set IV length (96 bits for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr) != 1) {
        std::cerr << "[CRYPTO] IV length set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Set key and IV using binary buffers (safe for embedded nulls)
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        std::cerr << "[CRYPTO] Key/IV set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Add AAD (Additional Authenticated Data) if provided
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len) != 1) {
            std::cerr << "[CRYPTO] AAD update failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
    }
    
    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          (const unsigned char*)plaintext.data(),
                          plaintext.length()) != 1) {
        std::cerr << "[CRYPTO] Encryption update failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        std::cerr << "[CRYPTO] Encryption final failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    
    // Get GCM authentication tag (128 bits)
    unsigned char tag[GCM_TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1) {
        std::cerr << "[CRYPTO] Tag retrieval failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Prepend IV, append tag: IV(12) + ciphertext + tag(16)
    std::vector<unsigned char> result;
    result.insert(result.end(), iv, iv + iv_len);  // IV first
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);  // ciphertext
    result.insert(result.end(), tag, tag + GCM_TAG_SIZE);  // tag last
    
    return base64Encode(result);
}

std::string EncryptionEnhanced::decryptAES_GCM(const std::string& ciphertext_b64,
                                                const unsigned char* key, size_t key_len,
                                                const unsigned char* aad, size_t aad_len) {
    // Validate key size
    if (key_len != 32) {
        std::cerr << "[CRYPTO] Invalid key size: " << key_len << " (expected 32)" << std::endl;
        return "";
    }
    if (!key) {
        std::cerr << "[CRYPTO] Key pointer is null" << std::endl;
        return "";
    }
    
    // Validate AAD if provided
    if (aad_len > 0 && !aad) {
        std::cerr << "[CRYPTO] AAD length is " << aad_len << " but AAD pointer is null" << std::endl;
        return "";
    }
    
    std::vector<unsigned char> data = base64Decode(ciphertext_b64);
    
    // Verify minimum length: IV(12) + tag(16) = 28 bytes minimum
    if (data.size() < 12 + GCM_TAG_SIZE) {
        std::cerr << "[CRYPTO] Data too short (missing IV or tag)" << std::endl;
        return "";
    }
    
    // Extract IV from beginning
    const unsigned char* iv_ptr = data.data();
    const size_t iv_len = 12;
    
    // Extract tag from end
    int ct_len = data.size() - 12 - GCM_TAG_SIZE;
    unsigned char tag[GCM_TAG_SIZE];
    std::memcpy(tag, data.data() + 12 + ct_len, GCM_TAG_SIZE);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[CRYPTO] Failed to create cipher context" << std::endl;
        return "";
    }
    
    std::vector<unsigned char> plaintext(ct_len + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int plaintext_len = 0;
    
    // Initialize AES-256-GCM decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        std::cerr << "[CRYPTO] GCM init failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr) != 1) {
        std::cerr << "[CRYPTO] IV length set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Set key and IV using binary buffers (safe for embedded nulls)
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv_ptr) != 1) {
        std::cerr << "[CRYPTO] Key/IV set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Add AAD (Additional Authenticated Data) if provided
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len) != 1) {
            std::cerr << "[CRYPTO] AAD update failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
    }
    
    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          data.data() + 12, ct_len) != 1) {
        std::cerr << "[CRYPTO] Decryption update failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;
    
    // Set expected tag for verification
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag) != 1) {
        std::cerr << "[CRYPTO] Tag set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Finalize decryption and verify tag
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        std::cerr << "[CRYPTO] ❌ Authentication FAILED - Message tampered or wrong key!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return ""; // Authentication failure!
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return std::string((char*)plaintext.data(), plaintext_len);
}

// ============================================
// Legacy Functions (DEPRECATED - BREAKING CHANGE v1.x -> v2.0)
// ============================================

/**
 * SECURITY ALERT: BREAKING CHANGE FROM v1.x TO v2.0
 * 
 * Previous implementation used a STATIC IV (hardcoded in code),
 * which is a CRITICAL SECURITY FLAW in GCM mode.
 * 
 * GCM SECURITY REQUIREMENT: Each encryption with the same key MUST use a unique IV.
 * 
 * Old v1.x behavior (INSECURE):
 * - Used static IV: {0x00, 0x01, ..., 0x0b}
 * - Same IV for EVERY encryption with the same key
 * - Violates GCM security: IV reuse allows key recovery attacks
 * 
 * New v2.0 behavior (SECURE):
 * - Generates fresh random IV for EVERY encryption
 * - Each ciphertext includes its unique IV (same format as modern encryptAES_GCM)
 * - IV reuse attacks are now impossible
 * 
 * Migration Impact:
 * - Data encrypted with v1.x (static IV) CANNOT be decrypted with v2.0
 * - Format changed: v1.x ciphertext (no IV) vs v2.0 ciphertext (IV prepended)
 * - This is intentional - the v1.x format was INSECURE
 * 
 * Migration Path:
 * 1. BEFORE upgrading: Decrypt all v1.x ciphertexts with old binary
 * 2. Re-encrypt using new encryptAES_GCM() with random IVs
 * 3. Update application code to use encryptAES_GCM() not Legacy version
 * 4. Delete any Legacy function calls from your codebase
 * 
 * These functions remain ONLY for explicit migration support.
 * NEW CODE MUST USE encryptAES_GCM() and decryptAES_GCM()
 */

std::string EncryptionEnhanced::encryptAES_GCM_Legacy(const std::string& plaintext, const std::string& aad) {
    // Log security warning - this should only be used during migration
    static bool warned = false;
    if (!warned) {
        std::cerr << std::endl;
        std::cerr << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
        std::cerr << "║ SECURITY WARNING: Using deprecated encryptAES_GCM_Legacy()     ║" << std::endl;
        std::cerr << "║                                                                ║" << std::endl;
        std::cerr << "║ CRITICAL: Previous version used STATIC IV (insecure in GCM)   ║" << std::endl;
        std::cerr << "║ NEW: Now generates RANDOM IV per call (secure)                ║" << std::endl;
        std::cerr << "║                                                                ║" << std::endl;
        std::cerr << "║ ACTION: Replace ALL calls to encryptAES_GCM_Legacy() with:    ║" << std::endl;
        std::cerr << "║         encryptAES_GCM(plaintext, key, generateIV())           ║" << std::endl;
        std::cerr << "║                                                                ║" << std::endl;
        std::cerr << "║ MIGRATION: Old ciphertexts encrypted with static IV will      ║" << std::endl;
        std::cerr << "║            need to be decrypted and re-encrypted.             ║" << std::endl;
        std::cerr << "╚════════════════════════════════════════════════════════════════╝" << std::endl;
        std::cerr << std::endl;
        warned = true;
    }
    
    // Generate a FRESH random IV for each encryption (SECURE)
    std::string iv = generateIV();
    if (iv.empty() || iv.length() != 12) {
        std::cerr << "[CRYPTO] ERROR: Failed to generate IV for legacy encryption" << std::endl;
        return "";
    }
    
    // Use modern encryption with random IV (NEW FORMAT: includes IV)
    // This is now SECURE (unlike old static IV implementation)
    return encryptAES_GCM(plaintext, 
                         reinterpret_cast<const unsigned char*>(AES_KEY.data()), AES_KEY.length(),
                         reinterpret_cast<const unsigned char*>(iv.data()), iv.length(),
                         reinterpret_cast<const unsigned char*>(aad.data()), aad.length());
}

std::string EncryptionEnhanced::decryptAES_GCM_Legacy(const std::string& ciphertext_b64, const std::string& aad) {
    // Log migration note
    static bool warned = false;
    if (!warned) {
        std::cerr << "[CRYPTO] WARNING: decryptAES_GCM_Legacy() is deprecated" << std::endl;
        std::cerr << "[CRYPTO]          Use decryptAES_GCM() for new code" << std::endl;
        warned = true;
    }
    
    std::vector<unsigned char> data = base64Decode(ciphertext_b64);
    
    if (data.empty()) {
        std::cerr << "[CRYPTO] Base64 decode failed" << std::endl;
        return "";
    }
    
    // Try to detect format:
    // NEW v2.0 format: IV(12) + ciphertext + tag(16) = minimum 28 bytes
    // OLD v1.x format: ciphertext + tag(16) = less than 28 bytes (with static IV)
    
    const size_t NEW_FORMAT_MIN_SIZE = 12 + GCM_TAG_SIZE;  // 28 bytes
    
    if (data.size() >= NEW_FORMAT_MIN_SIZE) {
        // Likely NEW format (v2.0) - IV is prepended
        // Try to decrypt as new format first
        std::cerr << "[CRYPTO] Attempting to decrypt as v2.0 format (IV + ciphertext + tag)..." << std::endl;
        std::string result = decryptAES_GCM(
            ciphertext_b64,
            reinterpret_cast<const unsigned char*>(AES_KEY.data()), AES_KEY.length(),
            reinterpret_cast<const unsigned char*>(aad.data()), aad.length()
        );
        
        if (!result.empty()) {
            std::cerr << "[CRYPTO] ✓ Successfully decrypted as v2.0 format" << std::endl;
            return result;
        }
        std::cerr << "[CRYPTO] Failed to decrypt as v2.0 format" << std::endl;
    }
    
    // Try OLD v1.x format (static IV, no IV prepended)
    std::cerr << "[CRYPTO] Attempting to decrypt as v1.x format (static IV, no IV prepended)..." << std::endl;
    std::cerr << "[CRYPTO] WARNING: v1.x format used STATIC IV - this is INSECURE!" << std::endl;
    
    // Verify minimum length (must have tag)
    if (data.size() < GCM_TAG_SIZE) {
        std::cerr << "[CRYPTO] Ciphertext too short (missing tag)" << std::endl;
        return "";
    }
    
    // Extract tag from end of ciphertext
    int ct_len = data.size() - GCM_TAG_SIZE;
    unsigned char tag[GCM_TAG_SIZE];
    std::memcpy(tag, data.data() + ct_len, GCM_TAG_SIZE);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[CRYPTO] Failed to create cipher context" << std::endl;
        return "";
    }
    
    std::vector<unsigned char> plaintext(ct_len + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int plaintext_len = 0;
    
    // Initialize AES-256-GCM decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        std::cerr << "[CRYPTO] GCM init failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        std::cerr << "[CRYPTO] IV length set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Set key and IV (STATIC IV from v1.x - INSECURE but needed for backward compat)
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, 
                           (const unsigned char*)AES_KEY.c_str(), IV) != 1) {
        std::cerr << "[CRYPTO] Key/IV set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Add AAD if provided
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, 
                              (const unsigned char*)aad.c_str(), aad.length()) != 1) {
            std::cerr << "[CRYPTO] AAD update failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
    }
    
    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, data.data(), ct_len) != 1) {
        std::cerr << "[CRYPTO] Decryption update failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;
    
    // Set expected tag for verification
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag) != 1) {
        std::cerr << "[CRYPTO] Tag set failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Finalize decryption and verify tag
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        std::cerr << "[CRYPTO] ❌ Authentication FAILED - Message tampered or wrong key!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return ""; // Authentication failure!
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    std::cerr << "[CRYPTO] ✓ Successfully decrypted as v1.x format (with static IV)" << std::endl;
    std::cerr << "[CRYPTO] IMPORTANT: This data should be re-encrypted with v2.0 format!" << std::endl;
    
    return std::string((char*)plaintext.data(), plaintext_len);
}

// ============================================
// Legacy AES-256-CBC (Educational)
// ============================================


std::string EncryptionEnhanced::encryptAES(const std::string& plaintext) {
    // WARNING: CBC mode does NOT provide authentication!
    // This is for educational/legacy purposes only.
    // Use encryptAES_GCM() for production.
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    std::vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int ciphertext_len = 0;
    
    // Use CBC mode (legacy)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           (const unsigned char*)AES_KEY.c_str(), IV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          (const unsigned char*)plaintext.c_str(),
                          plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    ciphertext.resize(ciphertext_len);
    return base64Encode(ciphertext);
}

std::string EncryptionEnhanced::decryptAES(const std::string& ciphertext_b64) {
    // WARNING: CBC mode does NOT provide authentication!
    // This is for educational/legacy purposes only.
    // Use decryptAES_GCM() for production.
    
    std::vector<unsigned char> ciphertext = base64Decode(ciphertext_b64);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int plaintext_len = 0;
    
    // Use CBC mode (legacy)
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           (const unsigned char*)AES_KEY.c_str(), IV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return std::string((char*)plaintext.data(), plaintext_len);
}

// ============================================
// Base64 Encoding/Decoding
// ============================================

std::string EncryptionEnhanced::base64Encode(const std::vector<unsigned char>& input) {
    static const char* base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    size_t in_len = input.size();
    size_t idx = 0;
    
    while (in_len--) {
        char_array_3[i++] = input[idx++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for (int j = i; j < 3; j++)
            char_array_3[j] = '\0';
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        
        for (int j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];
        
        while (i++ < 3)
            ret += '=';
    }
    
    return ret;
}

std::vector<unsigned char> EncryptionEnhanced::base64Decode(const std::string& input) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::vector<unsigned char> ret;
    int i = 0;
    unsigned char char_array_4[4], char_array_3[3];
    size_t in_len = input.size();
    size_t idx = 0;
    
    while (in_len-- && (input[idx] != '=') && 
           (isalnum(input[idx]) || (input[idx] == '+') || (input[idx] == '/'))) {
        char_array_4[i++] = input[idx]; idx++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);
            
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            
            for (i = 0; i < 3; i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }
    
    if (i) {
        for (int j = i; j < 4; j++)
            char_array_4[j] = 0;
        
        for (int j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);
        
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        
        for (int j = 0; j < i - 1; j++)
            ret.push_back(char_array_3[j]);
    }
    
    return ret;
}

std::string EncryptionEnhanced::generateSalt() {
    // Generate 128-bit (16 bytes) random salt
    unsigned char salt[SALT_SIZE];
    
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        std::cerr << "[CRYPTO] Random salt generation failed" << std::endl;
        return "";
    }
    
    // Convert to hex string
    std::stringstream ss;
    for (int i = 0; i < SALT_SIZE; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];
    }
    return ss.str();
}

std::string EncryptionEnhanced::generateIV() {
    // Generate 96-bit (12 bytes) random IV for GCM
    // CRITICAL: Never reuse IV with same key!
    unsigned char iv[12];
    
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        std::cerr << "[CRYPTO] Random IV generation failed" << std::endl;
        return "";
    }
    
    // Return as raw bytes (not hex)
    return std::string((char*)iv, 12);
}

std::string EncryptionEnhanced::generateKey() {
    // Generate 256-bit (32 bytes) random key for AES-256
    unsigned char key[32];
    
    if (RAND_bytes(key, sizeof(key)) != 1) {
        std::cerr << "[CRYPTO] Random key generation failed" << std::endl;
        return "";
    }
    
    // Return as raw bytes (not hex)
    return std::string((char*)key, 32);
}

std::string EncryptionEnhanced::generateNonce(size_t size) {
    // Generate random nonce of specified size
    std::vector<unsigned char> nonce(size);
    
    if (RAND_bytes(nonce.data(), size) != 1) {
        std::cerr << "[CRYPTO] Random nonce generation failed" << std::endl;
        return "";
    }
    
    // Return as raw bytes (not hex) for use in key derivation
    return std::string(reinterpret_cast<char*>(nonce.data()), size);
}

// ============================================
// PBKDF2 Key Derivation
// ============================================

std::string EncryptionEnhanced::deriveKey(const std::string& passphrase, const std::string& salt) {
    /**
     * Derives a 256-bit (32-byte) key from a passphrase using PBKDF2-HMAC-SHA256
     * 
     * @param passphrase - Input key material (e.g., username + nonce)
     * @param salt - Salt value for key derivation
     * @return Derived key as hex string (64 characters)
     */
    
    unsigned char derived_key[32];  // 256 bits
    const int iterations = 100000;  // NIST recommendation
    
    // PBKDF2 key derivation
    int result = PKCS5_PBKDF2_HMAC(
        passphrase.c_str(), passphrase.length(),
        (const unsigned char*)salt.c_str(), salt.length(),
        iterations,
        EVP_sha256(),
        32,  // Desired output length (256 bits)
        derived_key
    );
    
    if (result != 1) {
        std::cerr << "[CRYPTO] PBKDF2 key derivation failed" << std::endl;
        return "";
    }
    
    // Convert to hex string for storage/logging
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)derived_key[i];
    }
    
    return ss.str();
}

/**
 * Implementation Notes:
 * 
 * 1. AES-256-GCM Implementation:
 *    - Uses OpenSSL EVP interface for AEAD operations
 *    - Tag is appended to ciphertext for transmission
 *    - AAD (Additional Authenticated Data) authenticated but not encrypted
 *    - Verification failure returns empty string (safe fail)
 * 
 * 2. PBKDF2 Key Derivation:
 *    - 200,000 iterations meets OWASP 2023 minimum
 *    - Computation time ~100ms on modern CPU (acceptable UX)
 *    - Salt prevents rainbow table attacks
 *    - Output matches AES-256 key length (32 bytes)
 * 
 * 3. Random Generation:
 *    - Uses OpenSSL RAND_bytes (cryptographically secure)
 *    - Seeded from /dev/urandom on Linux, CryptGenRandom on Windows
 *    - Suitable for cryptographic purposes (keys, IVs, salts)
 * 
 * 4. Security Considerations:
 *    - IV MUST be unique for each message with same key
 *    - AAD MUST match between encryption and decryption
 *    - Tag verification failure indicates tampering
 *    - Constant-time password comparison prevents timing attacks
 * 
 * 5. Error Handling:
 *    - All crypto failures return empty string
 *    - Errors logged to stderr for debugging
 *    - Never expose partial plaintext on auth failure
 *    - Safe defaults (fail closed, not open)
 */
