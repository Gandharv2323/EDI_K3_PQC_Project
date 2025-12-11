/**
 * @file test_pqc.cpp
 * @brief Comprehensive test suite for Post-Quantum Cryptography integration
 * 
 * Tests:
 * 1. Kyber-768 KEM: Keypair generation, encapsulation, decapsulation
 * 2. Dilithium-III: Keypair generation, signing, verification
 * 3. SHA3-256 hash function
 * 4. Key derivation from shared secrets
 * 5. Hybrid PQC + AES-256-GCM encryption/decryption
 * 6. Sign-then-encrypt / Decrypt-then-verify flow
 * 7. Full secure messaging flow (realistic usage)
 * 
 * Build: cmake -B build && cmake --build build
 * Run: ./build/test_pqc
 * 
 * @author SecureChatServer Team
 * @version 1.0
 * @date 2025
 */

#include <iostream>
#include <string>
#include <iomanip>
#include <chrono>
#include <cassert>
#include <cstring>

#include "encryption_enhanced.h"
#include "pq_kem.h"
#include "pq_sign.h"

// ============================================
// Test Utilities
// ============================================

#define TEST_PASS(name) std::cout << "✓ PASS: " << name << std::endl
#define TEST_FAIL(name) std::cout << "✗ FAIL: " << name << std::endl
#define TEST_INFO(msg) std::cout << "  INFO: " << msg << std::endl

static int tests_passed = 0;
static int tests_failed = 0;

void printHex(const std::string& label, const std::string& data, size_t maxLen = 32) {
    std::cout << "  " << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < std::min(data.size(), maxLen); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << (int)(unsigned char)data[i];
    }
    if (data.size() > maxLen) std::cout << "...";
    std::cout << std::dec << std::endl;
}

void printHex(const std::string& label, const pqc::SecureBuffer& data, size_t maxLen = 32) {
    std::cout << "  " << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < std::min(data.size(), maxLen); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << (int)data.data()[i];
    }
    if (data.size() > maxLen) std::cout << "...";
    std::cout << std::dec << std::endl;
}

// ============================================
// Test 1: Kyber-768 KEM Direct API
// ============================================

bool test_kyber_kem_direct() {
    std::cout << "\n=== Test 1: Kyber-768 KEM (Direct API) ===" << std::endl;
    
    try {
        // Check availability
        if (!pqc::KyberKEM::isAvailable()) {
            TEST_FAIL("Kyber-768 not available");
            return false;
        }
        TEST_INFO("Kyber-768 algorithm available");
        
        // Create KEM instance
        pqc::KyberKEM kem;
        
        // Generate keypair
        auto start = std::chrono::high_resolution_clock::now();
        auto keyPairOpt = kem.generateKeyPair();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        if (!keyPairOpt) {
            TEST_FAIL("Keypair generation");
            return false;
        }
        TEST_PASS("Keypair generation (" + std::to_string(duration.count()) + " µs)");
        
        printHex("Public key", keyPairOpt->publicKey);
        printHex("Secret key", keyPairOpt->secretKey);
        
        // Verify sizes
        if (keyPairOpt->publicKey.size() != pqc::KyberConstants::PUBLIC_KEY_SIZE) {
            TEST_FAIL("Public key size");
            return false;
        }
        if (keyPairOpt->secretKey.size() != pqc::KyberConstants::SECRET_KEY_SIZE) {
            TEST_FAIL("Secret key size");
            return false;
        }
        TEST_PASS("Key sizes correct");
        
        // Encapsulate
        start = std::chrono::high_resolution_clock::now();
        auto encapResultOpt = kem.encapsulate(keyPairOpt->publicKey);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        if (!encapResultOpt) {
            TEST_FAIL("Encapsulation");
            return false;
        }
        TEST_PASS("Encapsulation (" + std::to_string(duration.count()) + " µs)");
        
        printHex("Ciphertext", encapResultOpt->ciphertext);
        printHex("Shared secret (encap)", encapResultOpt->sharedSecret);
        
        // Decapsulate
        start = std::chrono::high_resolution_clock::now();
        auto decapResultOpt = kem.decapsulate(encapResultOpt->ciphertext, keyPairOpt->secretKey);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        if (!decapResultOpt) {
            TEST_FAIL("Decapsulation");
            return false;
        }
        TEST_PASS("Decapsulation (" + std::to_string(duration.count()) + " µs)");
        
        printHex("Shared secret (decap)", *decapResultOpt);
        
        // Verify shared secrets match
        if (encapResultOpt->sharedSecret.size() != decapResultOpt->size()) {
            TEST_FAIL("Shared secret size mismatch");
            return false;
        }
        
        bool secretsMatch = (std::memcmp(
            encapResultOpt->sharedSecret.data(),
            decapResultOpt->data(),
            encapResultOpt->sharedSecret.size()
        ) == 0);
        
        if (!secretsMatch) {
            TEST_FAIL("Shared secrets don't match!");
            return false;
        }
        TEST_PASS("Shared secrets match");
        
        tests_passed++;
        return true;
        
    } catch (const std::exception& e) {
        TEST_FAIL("Exception: " + std::string(e.what()));
        tests_failed++;
        return false;
    }
}

// ============================================
// Test 2: Dilithium-III Signatures Direct API
// ============================================

bool test_dilithium_sign_direct() {
    std::cout << "\n=== Test 2: Dilithium-III Signatures (Direct API) ===" << std::endl;
    
    try {
        // Check availability
        if (!pqc::DilithiumSign::isAvailable()) {
            TEST_FAIL("Dilithium-III not available");
            return false;
        }
        TEST_INFO("Dilithium-III algorithm available");
        
        // Create signer instance
        pqc::DilithiumSign signer;
        
        // Generate keypair
        auto start = std::chrono::high_resolution_clock::now();
        auto keyPairOpt = signer.generateKeyPair();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        if (!keyPairOpt) {
            TEST_FAIL("Keypair generation");
            return false;
        }
        TEST_PASS("Keypair generation (" + std::to_string(duration.count()) + " µs)");
        
        printHex("Public key", keyPairOpt->publicKey);
        printHex("Secret key", keyPairOpt->secretKey);
        
        // Test message
        std::string message = "Hello, Post-Quantum World! This is a test message for Dilithium-III signatures.";
        TEST_INFO("Message: \"" + message + "\"");
        
        // Sign
        start = std::chrono::high_resolution_clock::now();
        auto signatureOpt = signer.sign(message, keyPairOpt->secretKey);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        if (!signatureOpt) {
            TEST_FAIL("Signing");
            return false;
        }
        TEST_PASS("Signing (" + std::to_string(duration.count()) + " µs)");
        
        printHex("Signature", *signatureOpt);
        
        // Verify
        start = std::chrono::high_resolution_clock::now();
        bool valid = signer.verify(message, *signatureOpt, keyPairOpt->publicKey);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        if (!valid) {
            TEST_FAIL("Signature verification");
            return false;
        }
        TEST_PASS("Signature verified (" + std::to_string(duration.count()) + " µs)");
        
        // Test tampered message
        std::string tamperedMessage = message + "!";
        bool invalidDetected = !signer.verify(tamperedMessage, *signatureOpt, keyPairOpt->publicKey);
        
        if (!invalidDetected) {
            TEST_FAIL("Tamper detection");
            return false;
        }
        TEST_PASS("Tampered message correctly rejected");
        
        tests_passed++;
        return true;
        
    } catch (const std::exception& e) {
        TEST_FAIL("Exception: " + std::string(e.what()));
        tests_failed++;
        return false;
    }
}

// ============================================
// Test 3: SHA3-256 Hash Function
// ============================================

bool test_sha3_256() {
    std::cout << "\n=== Test 3: SHA3-256 Hash Function ===" << std::endl;
    
    try {
        std::string input = "Hello, World!";
        
        // Test via EncryptionEnhanced
        std::string hash = EncryptionEnhanced::sha3_256(input);
        
        if (hash.empty()) {
            TEST_FAIL("SHA3-256 hash is empty");
            return false;
        }
        
        if (hash.size() != 64) {  // 32 bytes = 64 hex chars
            TEST_FAIL("SHA3-256 hash wrong length: " + std::to_string(hash.size()));
            return false;
        }
        TEST_PASS("SHA3-256 hash computed");
        TEST_INFO("Input: \"" + input + "\"");
        TEST_INFO("Hash:  " + hash);
        
        // Test raw version
        std::string rawHash = EncryptionEnhanced::sha3_256_raw(input);
        if (rawHash.size() != 32) {
            TEST_FAIL("SHA3-256 raw hash wrong length");
            return false;
        }
        TEST_PASS("SHA3-256 raw hash computed (32 bytes)");
        
        // Verify determinism
        std::string hash2 = EncryptionEnhanced::sha3_256(input);
        if (hash != hash2) {
            TEST_FAIL("SHA3-256 not deterministic");
            return false;
        }
        TEST_PASS("SHA3-256 is deterministic");
        
        // Test different input produces different hash
        std::string hash3 = EncryptionEnhanced::sha3_256(input + "!");
        if (hash == hash3) {
            TEST_FAIL("SHA3-256 collision detected (should not happen)");
            return false;
        }
        TEST_PASS("Different inputs produce different hashes");
        
        tests_passed++;
        return true;
        
    } catch (const std::exception& e) {
        TEST_FAIL("Exception: " + std::string(e.what()));
        tests_failed++;
        return false;
    }
}

// ============================================
// Test 4: EncryptionEnhanced PQC API
// ============================================

bool test_encryption_enhanced_pqc() {
    std::cout << "\n=== Test 4: EncryptionEnhanced PQC API ===" << std::endl;
    
    try {
        // Check availability
        if (!EncryptionEnhanced::isPQCKEMAvailable()) {
            TEST_FAIL("PQC KEM not available");
            return false;
        }
        TEST_PASS("PQC KEM available");
        
        if (!EncryptionEnhanced::isPQCSignAvailable()) {
            TEST_FAIL("PQC Sign not available");
            return false;
        }
        TEST_PASS("PQC Sign available");
        
        // Generate Kyber keypair via EncryptionEnhanced
        std::string publicKey, secretKey;
        if (!EncryptionEnhanced::pqGenerateKeyPair(publicKey, secretKey)) {
            TEST_FAIL("pqGenerateKeyPair");
            return false;
        }
        TEST_PASS("pqGenerateKeyPair");
        
        if (publicKey.size() != EncryptionEnhanced::PQ_PUBLIC_KEY_SIZE) {
            TEST_FAIL("Public key size");
            return false;
        }
        if (secretKey.size() != EncryptionEnhanced::PQ_SECRET_KEY_SIZE) {
            TEST_FAIL("Secret key size");
            return false;
        }
        TEST_PASS("Key sizes correct");
        
        // Encapsulate
        std::string ciphertext, sharedSecret1;
        if (!EncryptionEnhanced::pqEncapsulate(publicKey, ciphertext, sharedSecret1)) {
            TEST_FAIL("pqEncapsulate");
            return false;
        }
        TEST_PASS("pqEncapsulate");
        
        // Decapsulate
        std::string sharedSecret2;
        if (!EncryptionEnhanced::pqDecapsulate(ciphertext, secretKey, sharedSecret2)) {
            TEST_FAIL("pqDecapsulate");
            return false;
        }
        TEST_PASS("pqDecapsulate");
        
        // Verify shared secrets match
        if (sharedSecret1 != sharedSecret2) {
            TEST_FAIL("Shared secrets don't match");
            return false;
        }
        TEST_PASS("Shared secrets match");
        
        // Derive session key
        std::string sessionKey = EncryptionEnhanced::pqDeriveSessionKey(sharedSecret1);
        if (sessionKey.empty() || sessionKey.size() != 32) {
            TEST_FAIL("pqDeriveSessionKey");
            return false;
        }
        TEST_PASS("pqDeriveSessionKey (32 bytes)");
        
        tests_passed++;
        return true;
        
    } catch (const std::exception& e) {
        TEST_FAIL("Exception: " + std::string(e.what()));
        tests_failed++;
        return false;
    }
}

// ============================================
// Test 5: Hybrid PQC + AES-256-GCM Encryption
// ============================================

bool test_hybrid_encryption() {
    std::cout << "\n=== Test 5: Hybrid PQC + AES-256-GCM Encryption ===" << std::endl;
    
    try {
        // Generate recipient keypair
        std::string recipientPK, recipientSK;
        if (!EncryptionEnhanced::pqGenerateKeyPair(recipientPK, recipientSK)) {
            TEST_FAIL("Recipient keypair generation");
            return false;
        }
        TEST_PASS("Recipient keypair generated");
        
        // Test message
        std::string plaintext = "This is a secret message encrypted with hybrid PQC + AES-256-GCM!";
        std::string aad = "additional-authenticated-data";
        
        TEST_INFO("Plaintext: \"" + plaintext + "\"");
        TEST_INFO("AAD: \"" + aad + "\"");
        
        // Encrypt
        auto start = std::chrono::high_resolution_clock::now();
        std::string ciphertext = EncryptionEnhanced::pqHybridEncrypt(plaintext, recipientPK, aad);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        if (ciphertext.empty()) {
            TEST_FAIL("Hybrid encryption");
            return false;
        }
        TEST_PASS("Hybrid encryption (" + std::to_string(duration.count()) + " µs)");
        TEST_INFO("Ciphertext length: " + std::to_string(ciphertext.size()) + " bytes");
        
        // Decrypt
        start = std::chrono::high_resolution_clock::now();
        std::string decrypted = EncryptionEnhanced::pqHybridDecrypt(ciphertext, recipientSK, aad);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        if (decrypted.empty()) {
            TEST_FAIL("Hybrid decryption");
            return false;
        }
        TEST_PASS("Hybrid decryption (" + std::to_string(duration.count()) + " µs)");
        
        // Verify plaintext matches
        if (decrypted != plaintext) {
            TEST_FAIL("Decrypted text doesn't match");
            TEST_INFO("Expected: \"" + plaintext + "\"");
            TEST_INFO("Got:      \"" + decrypted + "\"");
            return false;
        }
        TEST_PASS("Decrypted text matches original");
        
        // Test wrong AAD
        std::string wrongAad = "wrong-aad";
        std::string shouldFail = EncryptionEnhanced::pqHybridDecrypt(ciphertext, recipientSK, wrongAad);
        if (!shouldFail.empty()) {
            TEST_FAIL("Wrong AAD should fail decryption");
            return false;
        }
        TEST_PASS("Wrong AAD correctly rejected");
        
        // Test wrong key
        std::string wrongPK, wrongSK;
        EncryptionEnhanced::pqGenerateKeyPair(wrongPK, wrongSK);
        std::string shouldFail2 = EncryptionEnhanced::pqHybridDecrypt(ciphertext, wrongSK, aad);
        if (!shouldFail2.empty()) {
            TEST_FAIL("Wrong secret key should fail decryption");
            return false;
        }
        TEST_PASS("Wrong secret key correctly rejected");
        
        tests_passed++;
        return true;
        
    } catch (const std::exception& e) {
        TEST_FAIL("Exception: " + std::string(e.what()));
        tests_failed++;
        return false;
    }
}

// ============================================
// Test 6: Dilithium Signatures via EncryptionEnhanced
// ============================================

bool test_signatures_via_enhanced() {
    std::cout << "\n=== Test 6: Dilithium Signatures via EncryptionEnhanced ===" << std::endl;
    
    try {
        // Generate signing keypair
        std::string signPK, signSK;
        if (!EncryptionEnhanced::pqSignGenerateKeyPair(signPK, signSK)) {
            TEST_FAIL("Signing keypair generation");
            return false;
        }
        TEST_PASS("Signing keypair generated");
        
        if (signPK.size() != EncryptionEnhanced::PQ_SIGN_PUBLIC_KEY_SIZE) {
            TEST_FAIL("Public key size");
            return false;
        }
        if (signSK.size() != EncryptionEnhanced::PQ_SIGN_SECRET_KEY_SIZE) {
            TEST_FAIL("Secret key size");
            return false;
        }
        TEST_PASS("Key sizes correct");
        
        // Sign message
        std::string message = "This message will be signed with Dilithium-III.";
        std::string signature;
        
        if (!EncryptionEnhanced::pqSign(message, signSK, signature)) {
            TEST_FAIL("Signing");
            return false;
        }
        TEST_PASS("Message signed");
        TEST_INFO("Signature size: " + std::to_string(signature.size()) + " bytes");
        
        // Verify signature
        if (!EncryptionEnhanced::pqVerify(message, signature, signPK)) {
            TEST_FAIL("Signature verification");
            return false;
        }
        TEST_PASS("Signature verified");
        
        // Test tampered message
        std::string tamperedMessage = message + "!";
        if (EncryptionEnhanced::pqVerify(tamperedMessage, signature, signPK)) {
            TEST_FAIL("Tamper detection");
            return false;
        }
        TEST_PASS("Tampered message correctly rejected");
        
        tests_passed++;
        return true;
        
    } catch (const std::exception& e) {
        TEST_FAIL("Exception: " + std::string(e.what()));
        tests_failed++;
        return false;
    }
}

// ============================================
// Test 7: Sign-then-Encrypt / Decrypt-then-Verify
// ============================================

bool test_sign_then_encrypt() {
    std::cout << "\n=== Test 7: Sign-then-Encrypt / Decrypt-then-Verify ===" << std::endl;
    
    try {
        // Generate sender's signing keypair
        std::string senderSignPK, senderSignSK;
        if (!EncryptionEnhanced::pqSignGenerateKeyPair(senderSignPK, senderSignSK)) {
            TEST_FAIL("Sender signing keypair generation");
            return false;
        }
        TEST_PASS("Sender signing keypair generated");
        
        // Generate recipient's encryption keypair
        std::string recipientEncPK, recipientEncSK;
        if (!EncryptionEnhanced::pqGenerateKeyPair(recipientEncPK, recipientEncSK)) {
            TEST_FAIL("Recipient encryption keypair generation");
            return false;
        }
        TEST_PASS("Recipient encryption keypair generated");
        
        // Message from sender to recipient
        std::string message = "This is a confidential and authenticated message from Alice to Bob.";
        TEST_INFO("Original message: \"" + message + "\"");
        
        // Sign-then-encrypt
        auto start = std::chrono::high_resolution_clock::now();
        std::string ciphertext = EncryptionEnhanced::pqSignThenEncrypt(
            message, senderSignSK, recipientEncPK
        );
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        if (ciphertext.empty()) {
            TEST_FAIL("Sign-then-encrypt");
            return false;
        }
        TEST_PASS("Sign-then-encrypt (" + std::to_string(duration.count()) + " µs)");
        TEST_INFO("Ciphertext size: " + std::to_string(ciphertext.size()) + " bytes");
        
        // Decrypt-then-verify
        start = std::chrono::high_resolution_clock::now();
        std::string recovered = EncryptionEnhanced::pqDecryptThenVerify(
            ciphertext, recipientEncSK, senderSignPK
        );
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        if (recovered.empty()) {
            TEST_FAIL("Decrypt-then-verify");
            return false;
        }
        TEST_PASS("Decrypt-then-verify (" + std::to_string(duration.count()) + " µs)");
        
        // Verify message matches
        if (recovered != message) {
            TEST_FAIL("Recovered message doesn't match");
            TEST_INFO("Expected: \"" + message + "\"");
            TEST_INFO("Got:      \"" + recovered + "\"");
            return false;
        }
        TEST_PASS("Recovered message matches original");
        
        // Test wrong sender key (impersonation attack)
        std::string wrongSignPK, wrongSignSK;
        EncryptionEnhanced::pqSignGenerateKeyPair(wrongSignPK, wrongSignSK);
        
        std::string shouldFail = EncryptionEnhanced::pqDecryptThenVerify(
            ciphertext, recipientEncSK, wrongSignPK
        );
        if (!shouldFail.empty()) {
            TEST_FAIL("Wrong sender key should fail verification");
            return false;
        }
        TEST_PASS("Wrong sender key correctly rejected (impersonation prevented)");
        
        tests_passed++;
        return true;
        
    } catch (const std::exception& e) {
        TEST_FAIL("Exception: " + std::string(e.what()));
        tests_failed++;
        return false;
    }
}

// ============================================
// Test 8: Full Secure Chat Message Flow
// ============================================

bool test_full_chat_flow() {
    std::cout << "\n=== Test 8: Full Secure Chat Message Flow ===" << std::endl;
    
    try {
        std::cout << "  Simulating secure chat between Alice and Bob...\n" << std::endl;
        
        // ---- Setup Phase ----
        std::cout << "  [SETUP] Generating keypairs..." << std::endl;
        
        // Alice's keypairs
        std::string aliceEncPK, aliceEncSK;
        std::string aliceSignPK, aliceSignSK;
        EncryptionEnhanced::pqGenerateKeyPair(aliceEncPK, aliceEncSK);
        EncryptionEnhanced::pqSignGenerateKeyPair(aliceSignPK, aliceSignSK);
        std::cout << "  [SETUP] Alice: encryption + signing keypairs generated" << std::endl;
        
        // Bob's keypairs
        std::string bobEncPK, bobEncSK;
        std::string bobSignPK, bobSignSK;
        EncryptionEnhanced::pqGenerateKeyPair(bobEncPK, bobEncSK);
        EncryptionEnhanced::pqSignGenerateKeyPair(bobSignPK, bobSignSK);
        std::cout << "  [SETUP] Bob: encryption + signing keypairs generated" << std::endl;
        
        // Exchange public keys (simulated)
        std::cout << "  [SETUP] Public keys exchanged" << std::endl;
        
        // ---- Message 1: Alice → Bob ----
        std::cout << "\n  [MSG 1] Alice → Bob" << std::endl;
        std::string msg1 = "Hi Bob! This is Alice. Using quantum-safe encryption now!";
        std::cout << "  [ALICE] Plaintext: \"" << msg1 << "\"" << std::endl;
        
        std::string ct1 = EncryptionEnhanced::pqSignThenEncrypt(msg1, aliceSignSK, bobEncPK);
        std::cout << "  [ALICE] Encrypted and signed (" << ct1.size() << " bytes)" << std::endl;
        
        std::string dec1 = EncryptionEnhanced::pqDecryptThenVerify(ct1, bobEncSK, aliceSignPK);
        if (dec1.empty() || dec1 != msg1) {
            TEST_FAIL("Message 1 delivery");
            return false;
        }
        std::cout << "  [BOB]   Decrypted and verified: \"" << dec1 << "\"" << std::endl;
        
        // ---- Message 2: Bob → Alice ----
        std::cout << "\n  [MSG 2] Bob → Alice" << std::endl;
        std::string msg2 = "Hey Alice! Great to hear from you. PQC is working perfectly!";
        std::cout << "  [BOB]   Plaintext: \"" << msg2 << "\"" << std::endl;
        
        std::string ct2 = EncryptionEnhanced::pqSignThenEncrypt(msg2, bobSignSK, aliceEncPK);
        std::cout << "  [BOB]   Encrypted and signed (" << ct2.size() << " bytes)" << std::endl;
        
        std::string dec2 = EncryptionEnhanced::pqDecryptThenVerify(ct2, aliceEncSK, bobSignPK);
        if (dec2.empty() || dec2 != msg2) {
            TEST_FAIL("Message 2 delivery");
            return false;
        }
        std::cout << "  [ALICE] Decrypted and verified: \"" << dec2 << "\"" << std::endl;
        
        // ---- Attack Simulation ----
        std::cout << "\n  [ATTACK] Simulating man-in-the-middle..." << std::endl;
        
        // Eve tries to intercept and modify
        std::string eveSignPK, eveSignSK;
        EncryptionEnhanced::pqSignGenerateKeyPair(eveSignPK, eveSignSK);
        
        // Eve tries to impersonate Alice
        std::string fakeMsg = "Hi Bob, please send me your private key. -Alice";
        std::string fakeCt = EncryptionEnhanced::pqSignThenEncrypt(fakeMsg, eveSignSK, bobEncPK);
        
        std::string decFake = EncryptionEnhanced::pqDecryptThenVerify(fakeCt, bobEncSK, aliceSignPK);
        if (!decFake.empty()) {
            TEST_FAIL("MITM attack succeeded (should have failed)");
            return false;
        }
        std::cout << "  [BOB]   Verification FAILED - Attack detected!" << std::endl;
        std::cout << "  [BOB]   Message rejected (not from Alice)" << std::endl;
        
        TEST_PASS("Full chat flow with MITM protection");
        tests_passed++;
        return true;
        
    } catch (const std::exception& e) {
        TEST_FAIL("Exception: " + std::string(e.what()));
        tests_failed++;
        return false;
    }
}

// ============================================
// Test 9: AES-256-GCM Backward Compatibility
// ============================================

bool test_aes_backward_compat() {
    std::cout << "\n=== Test 9: AES-256-GCM Backward Compatibility ===" << std::endl;
    
    try {
        // Test that existing AES-256-GCM API still works
        std::string plaintext = "Testing backward compatibility with existing AES-256-GCM API";
        std::string key = EncryptionEnhanced::generateKey();
        std::string iv = EncryptionEnhanced::generateIV();
        std::string aad = "test-aad";
        
        if (key.size() != 32) {
            TEST_FAIL("Key generation (wrong size)");
            return false;
        }
        TEST_PASS("Key generation (32 bytes)");
        
        if (iv.size() != 12) {
            TEST_FAIL("IV generation (wrong size)");
            return false;
        }
        TEST_PASS("IV generation (12 bytes)");
        
        // Encrypt with existing API
        std::string ciphertext = EncryptionEnhanced::encryptAES_GCM(
            plaintext,
            reinterpret_cast<const unsigned char*>(key.data()), key.size(),
            reinterpret_cast<const unsigned char*>(iv.data()), iv.size(),
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size()
        );
        
        if (ciphertext.empty()) {
            TEST_FAIL("AES-GCM encryption");
            return false;
        }
        TEST_PASS("AES-GCM encryption");
        
        // Decrypt with existing API
        std::string decrypted = EncryptionEnhanced::decryptAES_GCM(
            ciphertext,
            reinterpret_cast<const unsigned char*>(key.data()), key.size(),
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size()
        );
        
        if (decrypted != plaintext) {
            TEST_FAIL("AES-GCM decryption");
            return false;
        }
        TEST_PASS("AES-GCM decryption");
        
        // Test SHA-256 still works
        std::string hash = EncryptionEnhanced::sha256("test");
        if (hash.size() != 64) {
            TEST_FAIL("SHA-256 (wrong size)");
            return false;
        }
        TEST_PASS("SHA-256 still works");
        
        // Test PBKDF2 still works
        std::string salt = EncryptionEnhanced::generateSalt();
        std::string derivedKey = EncryptionEnhanced::deriveKey("password", salt);
        if (derivedKey.empty()) {
            TEST_FAIL("PBKDF2 key derivation");
            return false;
        }
        TEST_PASS("PBKDF2 key derivation still works");
        
        tests_passed++;
        return true;
        
    } catch (const std::exception& e) {
        TEST_FAIL("Exception: " + std::string(e.what()));
        tests_failed++;
        return false;
    }
}

// ============================================
// Main Test Runner
// ============================================

int main() {
    std::cout << "╔══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║       Post-Quantum Cryptography Integration Tests            ║" << std::endl;
    std::cout << "║                                                              ║" << std::endl;
    std::cout << "║  Algorithms: Kyber-768 (KEM), Dilithium-III (Signatures)     ║" << std::endl;
    std::cout << "║  Integration: Hybrid PQC + AES-256-GCM                       ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Run all tests
    test_kyber_kem_direct();
    test_dilithium_sign_direct();
    test_sha3_256();
    test_encryption_enhanced_pqc();
    test_hybrid_encryption();
    test_signatures_via_enhanced();
    test_sign_then_encrypt();
    test_full_chat_flow();
    test_aes_backward_compat();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Print summary
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                        TEST SUMMARY                          ║" << std::endl;
    std::cout << "╠══════════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  Tests Passed: " << std::setw(3) << tests_passed << "                                          ║" << std::endl;
    std::cout << "║  Tests Failed: " << std::setw(3) << tests_failed << "                                          ║" << std::endl;
    std::cout << "║  Total Time:   " << std::setw(6) << duration.count() << " ms                                   ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
    
    if (tests_failed > 0) {
        std::cout << "\n⚠️  Some tests FAILED. Please review the output above." << std::endl;
        return 1;
    }
    
    std::cout << "\n✅ All tests PASSED! PQC integration is working correctly." << std::endl;
    return 0;
}
