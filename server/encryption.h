#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

/**
 * Simple XOR Encryption (EDUCATIONAL ONLY)
 * 
 * WARNING: This is an INSECURE cipher for demonstration purposes only!
 * 
 * Purpose: Demonstrate why simple XOR cipher is inadequate for security
 * 
 * Critical Weaknesses:
 * ❌ No security against known-plaintext attacks
 * ❌ Trivial to break with frequency analysis
 * ❌ Key reuse reveals XOR of two plaintexts
 * ❌ No authentication (anyone can flip bits)
 * ❌ Vulnerable to bit-flipping attacks
 * ❌ Pattern preservation when key is shorter than plaintext
 * 
 * Educational Value:
 * - Shows difference between encryption-only vs authenticated encryption
 * - Demonstrates importance of proper cipher selection
 * - Highlights need for authentication in addition to confidentiality
 * 
 * Algorithm:
 * Encryption: C[i] = P[i] XOR K[i mod len(K)]
 * Decryption: P[i] = C[i] XOR K[i mod len(K)]  (same operation!)
 * 
 * Security Properties:
 * - Confidentiality: ❌ NONE (trivial to break)
 * - Authenticity: ❌ NONE (no MAC/tag)
 * - Integrity: ❌ NONE (bit flips undetected)
 * 
 * NEVER USE IN PRODUCTION!
 * Use AES-256-GCM from EncryptionEnhanced instead.
 */
class Encryption {
private:
    // Static key - VERY insecure! (all messages use same key)
    // In production, keys should be:
    // - Randomly generated per session
    // - Securely exchanged (e.g., Diffie-Hellman)
    // - Never hardcoded in source code
    static const std::string XOR_KEY;

public:
    /**
     * XOR Encryption
     * 
     * Performs simple XOR operation between plaintext and repeating key
     * 
     * @param plaintext - Data to "encrypt"
     * @return "Encrypted" data (NOT secure!)
     */
    static std::string encryptXOR(const std::string& plaintext);
    
    /**
     * XOR Decryption
     * 
     * Performs same XOR operation to recover plaintext
     * (XOR is its own inverse: A XOR B XOR B = A)
     * 
     * @param ciphertext - "Encrypted" data
     * @return Recovered plaintext
     */
    static std::string decryptXOR(const std::string& ciphertext);
};

#endif
