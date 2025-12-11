# Post-Quantum Cryptography (PQC) Integration

This document describes the Post-Quantum Cryptography extensions added to the SecureChatServer encryption module.

## Overview

The encryption system now supports quantum-resistant cryptographic algorithms in addition to the existing classical algorithms:

| Category | Classical | Post-Quantum |
|----------|-----------|--------------|
| Key Exchange | ECDH / DH | **Kyber-768 (ML-KEM)** |
| Encryption | AES-256-GCM | AES-256-GCM (derived from Kyber) |
| Signatures | ECDSA / RSA | **Dilithium-III (ML-DSA)** |
| Hashing | SHA-256 | **SHA3-256** |

## Algorithms

### Kyber-768 (NIST ML-KEM)
- **Security Level**: NIST Level 3 (~AES-192 equivalent)
- **Public Key**: 1,184 bytes
- **Secret Key**: 2,400 bytes
- **Ciphertext**: 1,088 bytes
- **Shared Secret**: 32 bytes
- **Use Case**: Quantum-resistant key encapsulation for session key establishment

### Dilithium-III (NIST ML-DSA)
- **Security Level**: NIST Level 3
- **Public Key**: 1,952 bytes
- **Secret Key**: 4,000 bytes
- **Signature**: ~3,293 bytes
- **Use Case**: Quantum-resistant digital signatures for message authentication

## Dependencies

### Required
- **OpenSSL >= 3.0** - For AES-256-GCM, SHA-256, SHA3-256, PBKDF2
- **liboqs >= 0.8.0** - Open Quantum Safe library for Kyber and Dilithium

### Installing liboqs

#### Linux (Ubuntu/Debian)
```bash
# From package manager (if available)
sudo apt install liboqs-dev

# Or build from source
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

#### macOS
```bash
brew install liboqs
```

#### Windows
```powershell
# Using vcpkg
vcpkg install liboqs:x64-windows

# Or build from source with CMake
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON -G "Visual Studio 17 2022" ..
cmake --build . --config Release
cmake --install . --prefix C:/liboqs
```

## Building

```bash
cd server

# Configure (will detect liboqs automatically)
cmake -B build -S .

# Build all targets
cmake --build build

# Run PQC tests
./build/test_pqc
```

### Build Output
- `chat_server` - Main chat server with PQC support
- `test_encryption` - Classic encryption tests
- `test_pqc` - Post-Quantum Cryptography tests
- `libencryption_enhanced_pqc.a` - Static library for external use

## API Reference

### Kyber-768 Key Encapsulation

```cpp
#include "encryption_enhanced.h"

// Generate keypair
std::string publicKey, secretKey;
EncryptionEnhanced::pqGenerateKeyPair(publicKey, secretKey);

// Encapsulate (client-side)
std::string ciphertext, sharedSecret;
EncryptionEnhanced::pqEncapsulate(publicKey, ciphertext, sharedSecret);

// Decapsulate (server-side)
std::string recoveredSecret;
EncryptionEnhanced::pqDecapsulate(ciphertext, secretKey, recoveredSecret);
// sharedSecret == recoveredSecret

// Derive AES-256 session key
std::string sessionKey = EncryptionEnhanced::pqDeriveSessionKey(sharedSecret);
```

### Hybrid PQC + AES-256-GCM Encryption

```cpp
// Generate recipient's keypair
std::string recipientPK, recipientSK;
EncryptionEnhanced::pqGenerateKeyPair(recipientPK, recipientSK);

// Encrypt message (sender)
std::string plaintext = "Secret message";
std::string ciphertext = EncryptionEnhanced::pqHybridEncrypt(
    plaintext, recipientPK, "optional-aad"
);

// Decrypt message (recipient)
std::string decrypted = EncryptionEnhanced::pqHybridDecrypt(
    ciphertext, recipientSK, "optional-aad"
);
```

### Dilithium-III Digital Signatures

```cpp
// Generate signing keypair
std::string signPK, signSK;
EncryptionEnhanced::pqSignGenerateKeyPair(signPK, signSK);

// Sign message
std::string message = "Important message";
std::string signature;
EncryptionEnhanced::pqSign(message, signSK, signature);

// Verify signature
bool isValid = EncryptionEnhanced::pqVerify(message, signature, signPK);
```

### Sign-then-Encrypt (Full Security)

```cpp
// Alice's signing keypair
std::string aliceSignPK, aliceSignSK;
EncryptionEnhanced::pqSignGenerateKeyPair(aliceSignPK, aliceSignSK);

// Bob's encryption keypair
std::string bobEncPK, bobEncSK;
EncryptionEnhanced::pqGenerateKeyPair(bobEncPK, bobEncSK);

// Alice sends authenticated, encrypted message to Bob
std::string message = "Hello Bob!";
std::string encrypted = EncryptionEnhanced::pqSignThenEncrypt(
    message, aliceSignSK, bobEncPK
);

// Bob decrypts and verifies it came from Alice
std::string decrypted = EncryptionEnhanced::pqDecryptThenVerify(
    encrypted, bobEncSK, aliceSignPK
);
// Returns empty string if signature verification fails
```

### SHA3-256 Hash Function

```cpp
// Hex output (64 characters)
std::string hash = EncryptionEnhanced::sha3_256("data");

// Raw binary output (32 bytes)
std::string rawHash = EncryptionEnhanced::sha3_256_raw("data");
```

### Availability Check

```cpp
if (EncryptionEnhanced::isPQCKEMAvailable()) {
    // Kyber-768 is available
}

if (EncryptionEnhanced::isPQCSignAvailable()) {
    // Dilithium-III is available
}
```

## Security Considerations

### Key Sizes
PQC keys are significantly larger than classical keys:

| Algorithm | Public Key | Secret Key | Ciphertext/Signature |
|-----------|------------|------------|---------------------|
| Kyber-768 | 1,184 B | 2,400 B | 1,088 B |
| Dilithium-III | 1,952 B | 4,000 B | ~3,293 B |
| RSA-2048 | 256 B | 256 B | 256 B |
| ECDSA P-256 | 64 B | 32 B | 64 B |

### Forward Secrecy
Use ephemeral Kyber keypairs for each session to achieve forward secrecy. If a long-term key is compromised, past session keys remain secure.

### Hybrid Approach
The implementation uses hybrid encryption (Kyber + AES-256-GCM) which provides security against both classical and quantum attacks. Even if one algorithm is broken, the other provides protection.

### Memory Safety
Sensitive data (keys, shared secrets) are:
- Stored in `SecureBuffer` which zeros memory on destruction
- Cleared from memory immediately after use
- Protected against compiler optimization of zeroing

## Backward Compatibility

All existing APIs remain unchanged:
- `encryptAES_GCM()` / `decryptAES_GCM()` - Still work as before
- `sha256()` - Classical SHA-256 still available
- `deriveKey()` - PBKDF2 key derivation unchanged
- `generateKey()` / `generateIV()` / `generateSalt()` - All unchanged

## Performance

Approximate operation times on modern hardware (Intel i7, 3.0 GHz):

| Operation | Time |
|-----------|------|
| Kyber-768 keypair | ~50 µs |
| Kyber-768 encapsulate | ~60 µs |
| Kyber-768 decapsulate | ~50 µs |
| Dilithium-III keypair | ~100 µs |
| Dilithium-III sign | ~150 µs |
| Dilithium-III verify | ~100 µs |
| SHA3-256 (1KB) | ~5 µs |

## File Structure

```
server/
├── encryption_enhanced.h      # Main header (updated with PQC)
├── encryption_enhanced.cpp    # Implementation (updated with PQC)
├── pq_kem.h                   # Kyber-768 KEM module
├── pq_kem.cpp
├── pq_sign.h                  # Dilithium-III signature module
├── pq_sign.cpp
├── test_pqc.cpp               # PQC integration tests
└── CMakeLists.txt             # Updated build configuration
```

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST FIPS 203 - ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 - ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [Open Quantum Safe (liboqs)](https://github.com/open-quantum-safe/liboqs)
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)

## License

This PQC integration follows the same license as the main SecureChatServer project.
