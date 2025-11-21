/**
 * Simple XOR Encryption Implementation
 * 
 * EDUCATIONAL ONLY - DO NOT USE IN PRODUCTION!
 * 
 * This implementation demonstrates why XOR cipher is insecure:
 * 
 * Attack Example 1: Known Plaintext Attack
 * If attacker knows any plaintext P and sees ciphertext C:
 *   K = P XOR C  (recovers key!)
 * Then all messages encrypted with same key are compromised.
 * 
 * Attack Example 2: Crib Dragging
 * If two messages encrypted with same key:
 *   C1 = P1 XOR K
 *   C2 = P2 XOR K
 *   C1 XOR C2 = P1 XOR P2  (key cancels out!)
 * Attacker can use frequency analysis on P1 XOR P2.
 * 
 * Attack Example 3: Bit Flipping
 * Attacker can flip bits in ciphertext:
 *   C' = C XOR mask
 *   P' = P XOR mask (controlled corruption!)
 * No authentication means changes go undetected.
 * 
 * Educational Comparison:
 * XOR Cipher       vs   AES-256-GCM
 * ❌ No security        ✅ Military-grade encryption
 * ❌ No authentication  ✅ Built-in authentication
 * ❌ No integrity       ✅ Tamper detection
 * ❌ Trivial to break   ✅ 2^256 brute-force resistance
 */

#include "encryption.h"

// Hardcoded key - VERY BAD PRACTICE!
// In production:
// - Generate random keys per session
// - Use key derivation (PBKDF2, HKDF)
// - Exchange keys securely (Diffie-Hellman)
// - Store keys securely (never in code)
const std::string Encryption::XOR_KEY = "ChatServer2025SecretKey!";

std::string Encryption::encryptXOR(const std::string& plaintext) {
    std::string encrypted = plaintext;
    size_t keyLen = XOR_KEY.length();
    
    // Simple repeating-key XOR
    // Weakness: Pattern repeats every keyLen bytes
    for (size_t i = 0; i < plaintext.length(); ++i) {
        encrypted[i] = plaintext[i] ^ XOR_KEY[i % keyLen];
    }
    
    return encrypted;
}

std::string Encryption::decryptXOR(const std::string& ciphertext) {
    // XOR is symmetric: decrypt is same as encrypt
    // This is convenient but provides no error detection!
    // Corrupted ciphertext decrypts to garbage with no warning.
    return encryptXOR(ciphertext);
}

/**
 * Why This is Insecure:
 * 
 * 1. Static Key:
 *    - Same key for all messages
 *    - Compromise of one message compromises all
 * 
 * 2. No Key Derivation:
 *    - Key is just a string (low entropy)
 *    - No salt, no iterations (easy to brute-force)
 * 
 * 3. No Authentication:
 *    - Can't detect tampering
 *    - Can't detect replay attacks
 *    - Can't verify sender identity
 * 
 * 4. Pattern Leakage:
 *    - Key repeats every 24 bytes
 *    - Same plaintext byte at positions i and i+24 
 *      produce same ciphertext (statistical attack!)
 * 
 * 5. Malleability:
 *    - Attacker can flip specific bits
 *    - Example: Change "alice" to "alicd" by flipping one bit
 *    - No way to detect this happened
 * 
 * Proper Alternative:
 * Use EncryptionEnhanced::encryptAES_GCM() which provides:
 * ✅ Strong encryption (AES-256)
 * ✅ Authentication (GCM tag)
 * ✅ Integrity verification
 * ✅ Tamper detection
 * ✅ AAD support (metadata protection)
 */
