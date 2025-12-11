/**
 * @file pq_sign.cpp
 * @brief Implementation of Post-Quantum Digital Signatures (Dilithium-III)
 * 
 * Uses liboqs (Open Quantum Safe) library for Dilithium-III implementation.
 * 
 * Build Requirements:
 * - liboqs >= 0.8.0
 */

#include "pq_sign.h"

#ifndef PQC_ENABLED
#define PQC_ENABLED 1
#endif

#if PQC_ENABLED
#include <oqs/oqs.h>
#endif

#include <cstring>
#include <stdexcept>
#include <iostream>

namespace pqc {

// ============================================
// DilithiumSign Implementation
// ============================================

#if PQC_ENABLED

struct DilithiumSign::Impl {
    OQS_SIG* sig = nullptr;
    
    Impl() {
        // Initialize liboqs (safe to call multiple times)
        OQS_init();
        
        // Create ML-DSA-65 signature instance (formerly Dilithium3)
        sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
        if (!sig) {
            throw std::runtime_error("Failed to initialize Dilithium-III signature scheme");
        }
    }
    
    ~Impl() {
        if (sig) {
            OQS_SIG_free(sig);
        }
    }
};

DilithiumSign::DilithiumSign() : impl_(std::make_unique<Impl>()) {
    std::cout << "[PQC] Dilithium-III signature scheme initialized" << std::endl;
    std::cout << "[PQC]   Public key size:  " << impl_->sig->length_public_key << " bytes" << std::endl;
    std::cout << "[PQC]   Secret key size:  " << impl_->sig->length_secret_key << " bytes" << std::endl;
    std::cout << "[PQC]   Signature size:   " << impl_->sig->length_signature << " bytes" << std::endl;
}

DilithiumSign::~DilithiumSign() = default;

bool DilithiumSign::isAvailable() {
    return OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_65);
}

std::optional<DilithiumKeyPair> DilithiumSign::generateKeyPair() {
    if (!impl_ || !impl_->sig) {
        std::cerr << "[PQC] ERROR: Signature scheme not initialized" << std::endl;
        return std::nullopt;
    }
    
    DilithiumKeyPair keyPair(impl_->sig->length_public_key, impl_->sig->length_secret_key);
    
    OQS_STATUS status = OQS_SIG_keypair(impl_->sig,
                                         keyPair.publicKey.data(),
                                         keyPair.secretKey.data());
    
    if (status != OQS_SUCCESS) {
        std::cerr << "[PQC] ERROR: Signature keypair generation failed" << std::endl;
        return std::nullopt;
    }
    
    std::cout << "[PQC] ✓ Dilithium-III keypair generated successfully" << std::endl;
    return keyPair;
}

std::optional<SecureBuffer> DilithiumSign::sign(const uint8_t* message, size_t messageLen,
                                                 const uint8_t* secretKey, size_t skLen) {
    if (!impl_ || !impl_->sig) {
        std::cerr << "[PQC] ERROR: Signature scheme not initialized" << std::endl;
        return std::nullopt;
    }
    
    if (!message || messageLen == 0) {
        std::cerr << "[PQC] ERROR: Empty message to sign" << std::endl;
        return std::nullopt;
    }
    
    if (!secretKey || skLen != impl_->sig->length_secret_key) {
        std::cerr << "[PQC] ERROR: Invalid secret key size (expected "
                  << impl_->sig->length_secret_key << ", got " << skLen << ")" << std::endl;
        return std::nullopt;
    }
    
    SecureBuffer signature(impl_->sig->length_signature);
    size_t sigLen = 0;
    
    OQS_STATUS status = OQS_SIG_sign(impl_->sig,
                                      signature.data(),
                                      &sigLen,
                                      message,
                                      messageLen,
                                      secretKey);
    
    if (status != OQS_SUCCESS) {
        std::cerr << "[PQC] ERROR: Signing failed" << std::endl;
        return std::nullopt;
    }
    
    // Dilithium signatures may be smaller than max size
    // Create a properly sized buffer
    if (sigLen < signature.size()) {
        SecureBuffer trimmedSig(sigLen);
        std::memcpy(trimmedSig.data(), signature.data(), sigLen);
        std::cout << "[PQC] ✓ Message signed successfully (" << sigLen << " bytes)" << std::endl;
        return trimmedSig;
    }
    
    std::cout << "[PQC] ✓ Message signed successfully (" << sigLen << " bytes)" << std::endl;
    return signature;
}

std::optional<SecureBuffer> DilithiumSign::sign(const std::string& message,
                                                 const SecureBuffer& secretKey) {
    return sign(reinterpret_cast<const uint8_t*>(message.data()), message.size(),
                secretKey.data(), secretKey.size());
}

std::optional<SecureBuffer> DilithiumSign::sign(const std::vector<uint8_t>& message,
                                                 const SecureBuffer& secretKey) {
    return sign(message.data(), message.size(), secretKey.data(), secretKey.size());
}

bool DilithiumSign::verify(const uint8_t* message, size_t messageLen,
                            const uint8_t* signature, size_t sigLen,
                            const uint8_t* publicKey, size_t pkLen) {
    if (!impl_ || !impl_->sig) {
        std::cerr << "[PQC] ERROR: Signature scheme not initialized" << std::endl;
        return false;
    }
    
    if (!message || messageLen == 0) {
        std::cerr << "[PQC] ERROR: Empty message to verify" << std::endl;
        return false;
    }
    
    if (!signature || sigLen == 0 || sigLen > impl_->sig->length_signature) {
        std::cerr << "[PQC] ERROR: Invalid signature size" << std::endl;
        return false;
    }
    
    if (!publicKey || pkLen != impl_->sig->length_public_key) {
        std::cerr << "[PQC] ERROR: Invalid public key size (expected "
                  << impl_->sig->length_public_key << ", got " << pkLen << ")" << std::endl;
        return false;
    }
    
    OQS_STATUS status = OQS_SIG_verify(impl_->sig,
                                        message,
                                        messageLen,
                                        signature,
                                        sigLen,
                                        publicKey);
    
    if (status != OQS_SUCCESS) {
        std::cerr << "[PQC] ✗ Signature verification FAILED" << std::endl;
        return false;
    }
    
    std::cout << "[PQC] ✓ Signature verified successfully" << std::endl;
    return true;
}

bool DilithiumSign::verify(const std::string& message,
                            const SecureBuffer& signature,
                            const SecureBuffer& publicKey) {
    return verify(reinterpret_cast<const uint8_t*>(message.data()), message.size(),
                  signature.data(), signature.size(),
                  publicKey.data(), publicKey.size());
}

bool DilithiumSign::verify(const std::vector<uint8_t>& message,
                            const SecureBuffer& signature,
                            const SecureBuffer& publicKey) {
    return verify(message.data(), message.size(),
                  signature.data(), signature.size(),
                  publicKey.data(), publicKey.size());
}

#else // PQC_ENABLED == 0

// Stub implementations when liboqs is not available

struct DilithiumSign::Impl {};

DilithiumSign::DilithiumSign() : impl_(nullptr) {
    std::cerr << "[PQC] WARNING: Dilithium-III not available (liboqs not installed)" << std::endl;
}

DilithiumSign::~DilithiumSign() = default;

bool DilithiumSign::isAvailable() { return false; }

std::optional<DilithiumKeyPair> DilithiumSign::generateKeyPair() {
    std::cerr << "[PQC] ERROR: Dilithium-III not available" << std::endl;
    return std::nullopt;
}

std::optional<SecureBuffer> DilithiumSign::sign(const uint8_t*, size_t, const uint8_t*, size_t) {
    std::cerr << "[PQC] ERROR: Dilithium-III not available" << std::endl;
    return std::nullopt;
}

std::optional<SecureBuffer> DilithiumSign::sign(const std::string&, const SecureBuffer&) {
    return std::nullopt;
}

std::optional<SecureBuffer> DilithiumSign::sign(const std::vector<uint8_t>&, const SecureBuffer&) {
    return std::nullopt;
}

bool DilithiumSign::verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) {
    std::cerr << "[PQC] ERROR: Dilithium-III not available" << std::endl;
    return false;
}

bool DilithiumSign::verify(const std::string&, const SecureBuffer&, const SecureBuffer&) {
    return false;
}

bool DilithiumSign::verify(const std::vector<uint8_t>&, const SecureBuffer&, const SecureBuffer&) {
    return false;
}

#endif // PQC_ENABLED

// ============================================
// Sign-then-encrypt / Verify-after-decrypt helpers
// ============================================

std::optional<std::vector<uint8_t>> signThenPrepare(
    const std::string& message,
    const SecureBuffer& secretKey,
    DilithiumSign& signer) {
    
    // Sign the message
    auto signatureOpt = signer.sign(message, secretKey);
    if (!signatureOpt) {
        return std::nullopt;
    }
    
    const SecureBuffer& signature = *signatureOpt;
    
    // Create blob: [4-byte signature length][signature][message]
    std::vector<uint8_t> blob;
    blob.reserve(4 + signature.size() + message.size());
    
    // Write signature length (big-endian)
    uint32_t sigLen = static_cast<uint32_t>(signature.size());
    blob.push_back((sigLen >> 24) & 0xFF);
    blob.push_back((sigLen >> 16) & 0xFF);
    blob.push_back((sigLen >> 8) & 0xFF);
    blob.push_back(sigLen & 0xFF);
    
    // Write signature
    blob.insert(blob.end(), signature.data(), signature.data() + signature.size());
    
    // Write message
    blob.insert(blob.end(), message.begin(), message.end());
    
    return blob;
}

std::optional<std::string> verifyAndExtract(
    const std::vector<uint8_t>& signedBlob,
    const SecureBuffer& publicKey,
    DilithiumSign& signer) {
    
    // Minimum size: 4 (length) + 1 (min signature) + 0 (empty message)
    if (signedBlob.size() < 5) {
        std::cerr << "[PQC] ERROR: Signed blob too short" << std::endl;
        return std::nullopt;
    }
    
    // Read signature length (big-endian)
    uint32_t sigLen = (static_cast<uint32_t>(signedBlob[0]) << 24) |
                      (static_cast<uint32_t>(signedBlob[1]) << 16) |
                      (static_cast<uint32_t>(signedBlob[2]) << 8) |
                      static_cast<uint32_t>(signedBlob[3]);
    
    // Validate signature length
    if (sigLen > DilithiumConstants::SIGNATURE_SIZE || sigLen + 4 > signedBlob.size()) {
        std::cerr << "[PQC] ERROR: Invalid signature length in blob" << std::endl;
        return std::nullopt;
    }
    
    // Extract signature
    const uint8_t* sigPtr = signedBlob.data() + 4;
    
    // Extract message
    size_t msgOffset = 4 + sigLen;
    size_t msgLen = signedBlob.size() - msgOffset;
    const uint8_t* msgPtr = signedBlob.data() + msgOffset;
    
    // Verify signature
    if (!signer.verify(msgPtr, msgLen, sigPtr, sigLen, publicKey.data(), publicKey.size())) {
        return std::nullopt;
    }
    
    // Return extracted message
    return std::string(reinterpret_cast<const char*>(msgPtr), msgLen);
}

} // namespace pqc
