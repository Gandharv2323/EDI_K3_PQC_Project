/**
 * @file pq_kem.h
 * @brief Post-Quantum Key Encapsulation Mechanism (KEM) using Kyber-768
 * 
 * Implements NIST ML-KEM (Kyber) for quantum-resistant key exchange.
 * This module provides:
 * - Kyber-768 keypair generation
 * - Key encapsulation (client-side)
 * - Key decapsulation (server-side)
 * - Hybrid key derivation for AES-256-GCM
 * 
 * References:
 * - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
 * - CRYSTALS-Kyber specification
 * - liboqs documentation
 * 
 * @author SecureChatServer Team
 * @version 1.0
 * @date 2025
 */

#ifndef PQ_KEM_H
#define PQ_KEM_H

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <cstdint>

namespace pqc {

/**
 * @brief Kyber-768 algorithm constants
 * 
 * Kyber-768 provides NIST Security Level 3 (~AES-192 equivalent)
 * Recommended for general-purpose use balancing security and performance
 */
struct KyberConstants {
    /// Public key size in bytes (Kyber-768)
    static constexpr size_t PUBLIC_KEY_SIZE = 1184;
    
    /// Secret key size in bytes (Kyber-768)
    static constexpr size_t SECRET_KEY_SIZE = 2400;
    
    /// Ciphertext size in bytes (Kyber-768)
    static constexpr size_t CIPHERTEXT_SIZE = 1088;
    
    /// Shared secret size in bytes
    static constexpr size_t SHARED_SECRET_SIZE = 32;
    
    /// Algorithm name for liboqs
    static constexpr const char* ALGORITHM_NAME = "Kyber768";
    
    /// NIST security level
    static constexpr int SECURITY_LEVEL = 3;
};

/**
 * @brief Secure buffer for sensitive cryptographic data
 * 
 * Automatically zeros memory on destruction to prevent key leakage.
 * Uses volatile writes to prevent compiler optimization of zeroing.
 */
class SecureBuffer {
public:
    /**
     * @brief Construct secure buffer with specified size
     * @param size Buffer size in bytes
     */
    explicit SecureBuffer(size_t size);
    
    /**
     * @brief Destructor - securely zeros memory
     */
    ~SecureBuffer();
    
    // Disable copy to prevent accidental key duplication
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    // Allow move semantics
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    
    /**
     * @brief Get pointer to buffer data
     * @return Pointer to buffer
     */
    uint8_t* data() noexcept { return data_.data(); }
    const uint8_t* data() const noexcept { return data_.data(); }
    
    /**
     * @brief Get buffer size
     * @return Size in bytes
     */
    size_t size() const noexcept { return data_.size(); }
    
    /**
     * @brief Convert to string (for compatibility)
     * @return String containing buffer data
     */
    std::string toString() const;
    
    /**
     * @brief Securely zero the buffer contents
     */
    void clear() noexcept;

private:
    std::vector<uint8_t> data_;
    
    /**
     * @brief Secure memory zeroing (prevents compiler optimization)
     */
    static void secureZero(void* ptr, size_t size) noexcept;
};

/**
 * @brief Kyber keypair container
 */
struct KyberKeyPair {
    SecureBuffer publicKey;   ///< Public key (can be shared)
    SecureBuffer secretKey;   ///< Secret key (keep private!)
    
    KyberKeyPair(size_t pkSize, size_t skSize)
        : publicKey(pkSize), secretKey(skSize) {}
};

/**
 * @brief Result of key encapsulation
 */
struct EncapsulationResult {
    SecureBuffer ciphertext;     ///< Ciphertext to send to key holder
    SecureBuffer sharedSecret;   ///< Derived shared secret
    
    EncapsulationResult(size_t ctSize, size_t ssSize)
        : ciphertext(ctSize), sharedSecret(ssSize) {}
};

/**
 * @brief Kyber-768 Key Encapsulation Mechanism
 * 
 * Provides quantum-resistant key exchange using CRYSTALS-Kyber algorithm.
 * 
 * Usage Flow:
 * 1. Server generates keypair: generateKeyPair()
 * 2. Server shares public key with client
 * 3. Client encapsulates: encapsulate(publicKey) → (ciphertext, sharedSecret)
 * 4. Client sends ciphertext to server
 * 5. Server decapsulates: decapsulate(ciphertext, secretKey) → sharedSecret
 * 6. Both parties now share the same secret
 * 
 * Security Notes:
 * - Secret keys must NEVER be transmitted
 * - Each session should use a fresh keypair (forward secrecy)
 * - Shared secrets should be processed through KDF before use as keys
 */
class KyberKEM {
public:
    /**
     * @brief Initialize Kyber KEM
     * @throws std::runtime_error if liboqs initialization fails
     */
    KyberKEM();
    
    /**
     * @brief Destructor - cleanup liboqs resources
     */
    ~KyberKEM();
    
    // Disable copy
    KyberKEM(const KyberKEM&) = delete;
    KyberKEM& operator=(const KyberKEM&) = delete;
    
    /**
     * @brief Generate a new Kyber-768 keypair
     * 
     * Generates a fresh public/secret keypair using cryptographically
     * secure random number generation.
     * 
     * @return Optional containing keypair, or nullopt on failure
     */
    std::optional<KyberKeyPair> generateKeyPair();
    
    /**
     * @brief Encapsulate a shared secret using public key
     * 
     * Client-side operation: Uses the server's public key to generate
     * a shared secret and ciphertext. The ciphertext is sent to the
     * server, which can recover the same shared secret.
     * 
     * @param publicKey Server's Kyber public key (1184 bytes)
     * @return Optional containing (ciphertext, sharedSecret), or nullopt on failure
     */
    std::optional<EncapsulationResult> encapsulate(const uint8_t* publicKey, size_t pkLen);
    std::optional<EncapsulationResult> encapsulate(const SecureBuffer& publicKey);
    std::optional<EncapsulationResult> encapsulate(const std::string& publicKey);
    
    /**
     * @brief Decapsulate ciphertext to recover shared secret
     * 
     * Server-side operation: Uses the secret key to recover the
     * shared secret from the client's ciphertext.
     * 
     * @param ciphertext Ciphertext from client (1088 bytes)
     * @param secretKey Server's Kyber secret key (2400 bytes)
     * @return Optional containing shared secret, or nullopt on failure
     */
    std::optional<SecureBuffer> decapsulate(const uint8_t* ciphertext, size_t ctLen,
                                             const uint8_t* secretKey, size_t skLen);
    std::optional<SecureBuffer> decapsulate(const SecureBuffer& ciphertext,
                                             const SecureBuffer& secretKey);
    std::optional<SecureBuffer> decapsulate(const std::string& ciphertext,
                                             const std::string& secretKey);
    
    /**
     * @brief Check if Kyber-768 is available
     * @return true if algorithm is supported
     */
    static bool isAvailable();
    
    /**
     * @brief Get algorithm name
     * @return "Kyber768"
     */
    static const char* getAlgorithmName() { return KyberConstants::ALGORITHM_NAME; }
    
    /**
     * @brief Get public key size
     * @return Size in bytes (1184)
     */
    static size_t getPublicKeySize() { return KyberConstants::PUBLIC_KEY_SIZE; }
    
    /**
     * @brief Get secret key size
     * @return Size in bytes (2400)
     */
    static size_t getSecretKeySize() { return KyberConstants::SECRET_KEY_SIZE; }
    
    /**
     * @brief Get ciphertext size
     * @return Size in bytes (1088)
     */
    static size_t getCiphertextSize() { return KyberConstants::CIPHERTEXT_SIZE; }
    
    /**
     * @brief Get shared secret size
     * @return Size in bytes (32)
     */
    static size_t getSharedSecretSize() { return KyberConstants::SHARED_SECRET_SIZE; }

private:
    /// Internal state (opaque pointer to liboqs context)
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Derive AES-256 key from Kyber shared secret using SHA3-256
 * 
 * Processes the raw Kyber shared secret through SHA3-256 to produce
 * a suitable AES-256-GCM encryption key.
 * 
 * Key Derivation: AES_key = SHA3-256(shared_secret || context)
 * 
 * @param sharedSecret Raw Kyber shared secret (32 bytes)
 * @param context Optional context string for domain separation
 * @return 32-byte AES-256 key, or empty on failure
 */
SecureBuffer deriveAESKeyFromSharedSecret(const SecureBuffer& sharedSecret,
                                           const std::string& context = "AES-256-GCM-KEY");
SecureBuffer deriveAESKeyFromSharedSecret(const uint8_t* sharedSecret, size_t ssLen,
                                           const std::string& context = "AES-256-GCM-KEY");

/**
 * @brief Derive AES-256 key using hybrid classical + PQ approach
 * 
 * Combines Kyber shared secret with ECDH/X25519 shared secret for
 * defense-in-depth against both classical and quantum attacks.
 * 
 * Derivation: AES_key = SHA3-256(kyber_ss || classical_ss || context)
 * 
 * @param kyberSecret Kyber-768 shared secret
 * @param classicalSecret Classical DH shared secret (e.g., X25519)
 * @param context Domain separation context
 * @return 32-byte AES-256 key
 */
SecureBuffer deriveHybridAESKey(const SecureBuffer& kyberSecret,
                                 const SecureBuffer& classicalSecret,
                                 const std::string& context = "HYBRID-AES-256-GCM-KEY");

/**
 * @brief SHA3-256 hash function
 * 
 * @param data Input data
 * @param len Input length
 * @return 32-byte hash
 */
SecureBuffer sha3_256(const uint8_t* data, size_t len);
SecureBuffer sha3_256(const std::string& data);

/**
 * @brief Encode binary data to Base64
 * @param data Binary data
 * @return Base64 string
 */
std::string base64Encode(const SecureBuffer& data);
std::string base64Encode(const uint8_t* data, size_t len);

/**
 * @brief Decode Base64 to binary data
 * @param encoded Base64 string
 * @return Binary data
 */
SecureBuffer base64Decode(const std::string& encoded);

} // namespace pqc

#endif // PQ_KEM_H
