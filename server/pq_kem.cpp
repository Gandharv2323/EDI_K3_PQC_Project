/**
 * @file pq_kem.cpp
 * @brief Implementation of Post-Quantum Key Encapsulation Mechanism (Kyber-768)
 * 
 * Uses liboqs (Open Quantum Safe) library for Kyber-768 implementation.
 * 
 * Build Requirements:
 * - liboqs >= 0.8.0
 * - OpenSSL >= 3.0 (for SHA3-256)
 * 
 * References:
 * - https://github.com/open-quantum-safe/liboqs
 * - NIST FIPS 203 ML-KEM Standard
 */

#include "pq_kem.h"

#ifndef PQC_ENABLED
#define PQC_ENABLED 1
#endif

#if PQC_ENABLED
#include <oqs/oqs.h>
#endif

#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace pqc {

// ============================================
// SecureBuffer Implementation
// ============================================

SecureBuffer::SecureBuffer(size_t size) : data_(size, 0) {}

SecureBuffer::~SecureBuffer() {
    clear();
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(std::move(other.data_)) {
    // Source is now empty, no need to zero
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        clear();  // Zero current data before replacing
        data_ = std::move(other.data_);
    }
    return *this;
}

void SecureBuffer::secureZero(void* ptr, size_t size) noexcept {
    // Use volatile to prevent compiler optimization
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (size--) {
        *p++ = 0;
    }
    
    // Memory barrier to ensure writes complete
#if defined(_MSC_VER)
    _ReadWriteBarrier();
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

void SecureBuffer::clear() noexcept {
    if (!data_.empty()) {
        secureZero(data_.data(), data_.size());
    }
}

std::string SecureBuffer::toString() const {
    return std::string(reinterpret_cast<const char*>(data_.data()), data_.size());
}

// ============================================
// KyberKEM Implementation
// ============================================

#if PQC_ENABLED

struct KyberKEM::Impl {
    OQS_KEM* kem = nullptr;
    
    Impl() {
        // Initialize liboqs
        OQS_init();
        
        // Create Kyber-768 KEM instance
        kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        if (!kem) {
            throw std::runtime_error("Failed to initialize Kyber-768 KEM");
        }
    }
    
    ~Impl() {
        if (kem) {
            OQS_KEM_free(kem);
        }
        // Note: OQS_destroy() is not needed per liboqs docs
    }
};

KyberKEM::KyberKEM() : impl_(std::make_unique<Impl>()) {
    std::cout << "[PQC] Kyber-768 KEM initialized" << std::endl;
    std::cout << "[PQC]   Public key size:  " << impl_->kem->length_public_key << " bytes" << std::endl;
    std::cout << "[PQC]   Secret key size:  " << impl_->kem->length_secret_key << " bytes" << std::endl;
    std::cout << "[PQC]   Ciphertext size:  " << impl_->kem->length_ciphertext << " bytes" << std::endl;
    std::cout << "[PQC]   Shared secret:    " << impl_->kem->length_shared_secret << " bytes" << std::endl;
}

KyberKEM::~KyberKEM() = default;

bool KyberKEM::isAvailable() {
    return OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_768);
}

std::optional<KyberKeyPair> KyberKEM::generateKeyPair() {
    if (!impl_ || !impl_->kem) {
        std::cerr << "[PQC] ERROR: KEM not initialized" << std::endl;
        return std::nullopt;
    }
    
    KyberKeyPair keyPair(impl_->kem->length_public_key, impl_->kem->length_secret_key);
    
    OQS_STATUS status = OQS_KEM_keypair(impl_->kem, 
                                         keyPair.publicKey.data(), 
                                         keyPair.secretKey.data());
    
    if (status != OQS_SUCCESS) {
        std::cerr << "[PQC] ERROR: Keypair generation failed" << std::endl;
        return std::nullopt;
    }
    
    std::cout << "[PQC] ✓ Kyber-768 keypair generated successfully" << std::endl;
    return keyPair;
}

std::optional<EncapsulationResult> KyberKEM::encapsulate(const uint8_t* publicKey, size_t pkLen) {
    if (!impl_ || !impl_->kem) {
        std::cerr << "[PQC] ERROR: KEM not initialized" << std::endl;
        return std::nullopt;
    }
    
    if (!publicKey || pkLen != impl_->kem->length_public_key) {
        std::cerr << "[PQC] ERROR: Invalid public key size (expected " 
                  << impl_->kem->length_public_key << ", got " << pkLen << ")" << std::endl;
        return std::nullopt;
    }
    
    EncapsulationResult result(impl_->kem->length_ciphertext, impl_->kem->length_shared_secret);
    
    OQS_STATUS status = OQS_KEM_encaps(impl_->kem,
                                        result.ciphertext.data(),
                                        result.sharedSecret.data(),
                                        publicKey);
    
    if (status != OQS_SUCCESS) {
        std::cerr << "[PQC] ERROR: Encapsulation failed" << std::endl;
        return std::nullopt;
    }
    
    std::cout << "[PQC] ✓ Key encapsulated successfully" << std::endl;
    return result;
}

std::optional<EncapsulationResult> KyberKEM::encapsulate(const SecureBuffer& publicKey) {
    return encapsulate(publicKey.data(), publicKey.size());
}

std::optional<EncapsulationResult> KyberKEM::encapsulate(const std::string& publicKey) {
    return encapsulate(reinterpret_cast<const uint8_t*>(publicKey.data()), publicKey.size());
}

std::optional<SecureBuffer> KyberKEM::decapsulate(const uint8_t* ciphertext, size_t ctLen,
                                                   const uint8_t* secretKey, size_t skLen) {
    if (!impl_ || !impl_->kem) {
        std::cerr << "[PQC] ERROR: KEM not initialized" << std::endl;
        return std::nullopt;
    }
    
    if (!ciphertext || ctLen != impl_->kem->length_ciphertext) {
        std::cerr << "[PQC] ERROR: Invalid ciphertext size (expected " 
                  << impl_->kem->length_ciphertext << ", got " << ctLen << ")" << std::endl;
        return std::nullopt;
    }
    
    if (!secretKey || skLen != impl_->kem->length_secret_key) {
        std::cerr << "[PQC] ERROR: Invalid secret key size (expected " 
                  << impl_->kem->length_secret_key << ", got " << skLen << ")" << std::endl;
        return std::nullopt;
    }
    
    SecureBuffer sharedSecret(impl_->kem->length_shared_secret);
    
    OQS_STATUS status = OQS_KEM_decaps(impl_->kem,
                                        sharedSecret.data(),
                                        ciphertext,
                                        secretKey);
    
    if (status != OQS_SUCCESS) {
        std::cerr << "[PQC] ERROR: Decapsulation failed" << std::endl;
        return std::nullopt;
    }
    
    std::cout << "[PQC] ✓ Key decapsulated successfully" << std::endl;
    return sharedSecret;
}

std::optional<SecureBuffer> KyberKEM::decapsulate(const SecureBuffer& ciphertext,
                                                   const SecureBuffer& secretKey) {
    return decapsulate(ciphertext.data(), ciphertext.size(),
                       secretKey.data(), secretKey.size());
}

std::optional<SecureBuffer> KyberKEM::decapsulate(const std::string& ciphertext,
                                                   const std::string& secretKey) {
    return decapsulate(reinterpret_cast<const uint8_t*>(ciphertext.data()), ciphertext.size(),
                       reinterpret_cast<const uint8_t*>(secretKey.data()), secretKey.size());
}

#else // PQC_ENABLED == 0

// Stub implementations when liboqs is not available

struct KyberKEM::Impl {};

KyberKEM::KyberKEM() : impl_(nullptr) {
    std::cerr << "[PQC] WARNING: Kyber-768 not available (liboqs not installed)" << std::endl;
}

KyberKEM::~KyberKEM() = default;

bool KyberKEM::isAvailable() { return false; }

std::optional<KyberKeyPair> KyberKEM::generateKeyPair() {
    std::cerr << "[PQC] ERROR: Kyber-768 not available" << std::endl;
    return std::nullopt;
}

std::optional<EncapsulationResult> KyberKEM::encapsulate(const uint8_t*, size_t) {
    std::cerr << "[PQC] ERROR: Kyber-768 not available" << std::endl;
    return std::nullopt;
}

std::optional<EncapsulationResult> KyberKEM::encapsulate(const SecureBuffer&) {
    return std::nullopt;
}

std::optional<EncapsulationResult> KyberKEM::encapsulate(const std::string&) {
    return std::nullopt;
}

std::optional<SecureBuffer> KyberKEM::decapsulate(const uint8_t*, size_t, const uint8_t*, size_t) {
    std::cerr << "[PQC] ERROR: Kyber-768 not available" << std::endl;
    return std::nullopt;
}

std::optional<SecureBuffer> KyberKEM::decapsulate(const SecureBuffer&, const SecureBuffer&) {
    return std::nullopt;
}

std::optional<SecureBuffer> KyberKEM::decapsulate(const std::string&, const std::string&) {
    return std::nullopt;
}

#endif // PQC_ENABLED

// ============================================
// SHA3-256 Implementation
// ============================================

SecureBuffer sha3_256(const uint8_t* data, size_t len) {
    SecureBuffer hash(32);  // SHA3-256 produces 32 bytes
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "[PQC] ERROR: Failed to create SHA3-256 context" << std::endl;
        return SecureBuffer(0);
    }
    
    unsigned int hashLen = 0;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), &hashLen) != 1) {
        std::cerr << "[PQC] ERROR: SHA3-256 computation failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return SecureBuffer(0);
    }
    
    EVP_MD_CTX_free(ctx);
    return hash;
}

SecureBuffer sha3_256(const std::string& data) {
    return sha3_256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ============================================
// Key Derivation Functions
// ============================================

SecureBuffer deriveAESKeyFromSharedSecret(const SecureBuffer& sharedSecret,
                                           const std::string& context) {
    return deriveAESKeyFromSharedSecret(sharedSecret.data(), sharedSecret.size(), context);
}

SecureBuffer deriveAESKeyFromSharedSecret(const uint8_t* sharedSecret, size_t ssLen,
                                           const std::string& context) {
    if (!sharedSecret || ssLen == 0) {
        std::cerr << "[PQC] ERROR: Invalid shared secret" << std::endl;
        return SecureBuffer(0);
    }
    
    // Concatenate shared_secret || context
    std::vector<uint8_t> input(ssLen + context.size());
    std::memcpy(input.data(), sharedSecret, ssLen);
    std::memcpy(input.data() + ssLen, context.data(), context.size());
    
    // Derive key using SHA3-256
    SecureBuffer key = sha3_256(input.data(), input.size());
    
    // Zero the temporary input buffer
    volatile uint8_t* p = input.data();
    for (size_t i = 0; i < input.size(); i++) {
        p[i] = 0;
    }
    
    if (key.size() != 32) {
        std::cerr << "[PQC] ERROR: Key derivation failed" << std::endl;
        return SecureBuffer(0);
    }
    
    std::cout << "[PQC] ✓ AES-256 key derived from shared secret" << std::endl;
    return key;
}

SecureBuffer deriveHybridAESKey(const SecureBuffer& kyberSecret,
                                 const SecureBuffer& classicalSecret,
                                 const std::string& context) {
    if (kyberSecret.size() == 0 || classicalSecret.size() == 0) {
        std::cerr << "[PQC] ERROR: Invalid secrets for hybrid derivation" << std::endl;
        return SecureBuffer(0);
    }
    
    // Concatenate kyber_ss || classical_ss || context
    size_t totalLen = kyberSecret.size() + classicalSecret.size() + context.size();
    std::vector<uint8_t> input(totalLen);
    
    size_t offset = 0;
    std::memcpy(input.data() + offset, kyberSecret.data(), kyberSecret.size());
    offset += kyberSecret.size();
    std::memcpy(input.data() + offset, classicalSecret.data(), classicalSecret.size());
    offset += classicalSecret.size();
    std::memcpy(input.data() + offset, context.data(), context.size());
    
    // Derive key using SHA3-256
    SecureBuffer key = sha3_256(input.data(), input.size());
    
    // Zero the temporary input buffer
    volatile uint8_t* p = input.data();
    for (size_t i = 0; i < input.size(); i++) {
        p[i] = 0;
    }
    
    std::cout << "[PQC] ✓ Hybrid AES-256 key derived" << std::endl;
    return key;
}

// ============================================
// Base64 Encoding/Decoding
// ============================================

static const char* BASE64_CHARS = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const SecureBuffer& data) {
    return base64Encode(data.data(), data.size());
}

std::string base64Encode(const uint8_t* data, size_t len) {
    std::string ret;
    int i = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];
    size_t idx = 0;
    
    while (len--) {
        char_array_3[i++] = data[idx++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++)
                ret += BASE64_CHARS[char_array_4[i]];
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
            ret += BASE64_CHARS[char_array_4[j]];
        
        while (i++ < 3)
            ret += '=';
    }
    
    return ret;
}

SecureBuffer base64Decode(const std::string& encoded) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    size_t in_len = encoded.size();
    int i = 0;
    size_t idx = 0;
    uint8_t char_array_4[4], char_array_3[3];
    std::vector<uint8_t> ret;
    
    while (in_len-- && (encoded[idx] != '=') && 
           (std::isalnum(encoded[idx]) || (encoded[idx] == '+') || (encoded[idx] == '/'))) {
        char_array_4[i++] = encoded[idx++];
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
        for (int j = 0; j < i; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);
        
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        
        for (int j = 0; j < i - 1; j++)
            ret.push_back(char_array_3[j]);
    }
    
    SecureBuffer result(ret.size());
    std::memcpy(result.data(), ret.data(), ret.size());
    
    return result;
}

} // namespace pqc
