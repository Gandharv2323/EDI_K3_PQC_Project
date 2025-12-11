/**
 * @file pq_sign.h
 * @brief Post-Quantum Digital Signatures using Dilithium-III
 * 
 * Implements NIST ML-DSA (Dilithium) for quantum-resistant digital signatures.
 * This module provides:
 * - Dilithium-III keypair generation
 * - Message signing
 * - Signature verification
 * 
 * References:
 * - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
 * - CRYSTALS-Dilithium specification
 * - liboqs documentation
 * 
 * @author SecureChatServer Team
 * @version 1.0
 * @date 2025
 */

#ifndef PQ_SIGN_H
#define PQ_SIGN_H

#include "pq_kem.h"  // For SecureBuffer
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <cstdint>

namespace pqc {

/**
 * @brief Dilithium-III algorithm constants
 * 
 * Dilithium-III provides NIST Security Level 3 (~AES-192 equivalent)
 * Balanced security and performance, recommended for general use
 */
struct DilithiumConstants {
    /// Public key size in bytes (Dilithium3)
    static constexpr size_t PUBLIC_KEY_SIZE = 1952;
    
    /// Secret key size in bytes (Dilithium3)
    static constexpr size_t SECRET_KEY_SIZE = 4032;
    
    /// Signature size in bytes (Dilithium3)
    static constexpr size_t SIGNATURE_SIZE = 3309;
    
    /// Algorithm name for liboqs
    static constexpr const char* ALGORITHM_NAME = "Dilithium3";
    
    /// NIST security level
    static constexpr int SECURITY_LEVEL = 3;
};

/**
 * @brief Dilithium keypair container
 */
struct DilithiumKeyPair {
    SecureBuffer publicKey;   ///< Public key (for verification)
    SecureBuffer secretKey;   ///< Secret key (for signing)
    
    DilithiumKeyPair(size_t pkSize, size_t skSize)
        : publicKey(pkSize), secretKey(skSize) {}
};

/**
 * @brief Signed message container
 */
struct SignedMessage {
    std::vector<uint8_t> message;     ///< Original message
    SecureBuffer signature;           ///< Dilithium signature
    
    SignedMessage(size_t sigSize) : signature(sigSize) {}
};

/**
 * @brief Dilithium-III Digital Signature Scheme
 * 
 * Provides quantum-resistant digital signatures using CRYSTALS-Dilithium.
 * 
 * Usage Flow:
 * 1. Generate keypair: generateKeyPair()
 * 2. Sign message: sign(message, secretKey) → signature
 * 3. Verify signature: verify(message, signature, publicKey) → bool
 * 
 * Security Notes:
 * - Secret keys must NEVER be transmitted
 * - Signatures are deterministic (no random component visible)
 * - Provides strong unforgeability under chosen message attack (SUF-CMA)
 */
class DilithiumSign {
public:
    /**
     * @brief Initialize Dilithium signature scheme
     * @throws std::runtime_error if liboqs initialization fails
     */
    DilithiumSign();
    
    /**
     * @brief Destructor - cleanup liboqs resources
     */
    ~DilithiumSign();
    
    // Disable copy
    DilithiumSign(const DilithiumSign&) = delete;
    DilithiumSign& operator=(const DilithiumSign&) = delete;
    
    /**
     * @brief Generate a new Dilithium-III keypair
     * 
     * @return Optional containing keypair, or nullopt on failure
     */
    std::optional<DilithiumKeyPair> generateKeyPair();
    
    /**
     * @brief Sign a message
     * 
     * @param message Message to sign
     * @param messageLen Length of message
     * @param secretKey Signing key (4000 bytes)
     * @param skLen Secret key length
     * @return Optional containing signature, or nullopt on failure
     */
    std::optional<SecureBuffer> sign(const uint8_t* message, size_t messageLen,
                                      const uint8_t* secretKey, size_t skLen);
    std::optional<SecureBuffer> sign(const std::string& message,
                                      const SecureBuffer& secretKey);
    std::optional<SecureBuffer> sign(const std::vector<uint8_t>& message,
                                      const SecureBuffer& secretKey);
    
    /**
     * @brief Verify a signature
     * 
     * @param message Original message
     * @param messageLen Length of message
     * @param signature Signature to verify
     * @param sigLen Signature length
     * @param publicKey Verification key (1952 bytes)
     * @param pkLen Public key length
     * @return true if signature is valid
     */
    bool verify(const uint8_t* message, size_t messageLen,
                const uint8_t* signature, size_t sigLen,
                const uint8_t* publicKey, size_t pkLen);
    bool verify(const std::string& message,
                const SecureBuffer& signature,
                const SecureBuffer& publicKey);
    bool verify(const std::vector<uint8_t>& message,
                const SecureBuffer& signature,
                const SecureBuffer& publicKey);
    
    /**
     * @brief Check if Dilithium3 is available
     * @return true if algorithm is supported
     */
    static bool isAvailable();
    
    /**
     * @brief Get algorithm name
     * @return "Dilithium3"
     */
    static const char* getAlgorithmName() { return DilithiumConstants::ALGORITHM_NAME; }
    
    /**
     * @brief Get public key size
     * @return Size in bytes (1952)
     */
    static size_t getPublicKeySize() { return DilithiumConstants::PUBLIC_KEY_SIZE; }
    
    /**
     * @brief Get secret key size
     * @return Size in bytes (4000)
     */
    static size_t getSecretKeySize() { return DilithiumConstants::SECRET_KEY_SIZE; }
    
    /**
     * @brief Get signature size
     * @return Size in bytes (3293)
     */
    static size_t getSignatureSize() { return DilithiumConstants::SIGNATURE_SIZE; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Sign-then-encrypt helper
 * 
 * Signs a message and returns a structure ready for encryption.
 * Format: [4-byte signature length][signature][message]
 * 
 * @param message Message to sign
 * @param secretKey Dilithium secret key
 * @param signer DilithiumSign instance
 * @return Signed message blob, or empty on failure
 */
std::optional<std::vector<uint8_t>> signThenPrepare(
    const std::string& message,
    const SecureBuffer& secretKey,
    DilithiumSign& signer);

/**
 * @brief Verify-after-decrypt helper
 * 
 * Parses a signed message blob and verifies the signature.
 * 
 * @param signedBlob Format: [4-byte signature length][signature][message]
 * @param publicKey Dilithium public key
 * @param signer DilithiumSign instance
 * @return Original message if signature valid, or nullopt
 */
std::optional<std::string> verifyAndExtract(
    const std::vector<uint8_t>& signedBlob,
    const SecureBuffer& publicKey,
    DilithiumSign& signer);

} // namespace pqc

#endif // PQ_SIGN_H
