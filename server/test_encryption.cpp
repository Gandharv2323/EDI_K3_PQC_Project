/**
 * Test encryption/decryption functionality
 * 
 * Compile and run to verify AES-GCM is working:
 *   cl /EHsc /std:c++17 test_encryption.cpp encryption_enhanced.cpp /I"C:\Program Files\OpenSSL\include" /link /LIBPATH:"C:\Program Files\OpenSSL\lib" libssl.lib libcrypto.lib
 * Or use CMake to build with the server project.
 */

#include "encryption_enhanced.h"
#include <iostream>
#include <string>

int main() {
    std::cout << "=== AES-256-GCM Encryption Test (Dynamic Keys/IVs) ===" << std::endl;
    
    // Generate test key and IV
    std::string key = EncryptionEnhanced::generateKey();
    if (key.length() != 32) {
        std::cerr << "❌ Key generation failed!" << std::endl;
        return 1;
    }
    std::cout << "✅ Generated 256-bit key" << std::endl;
    
    // Test 1: Basic encryption/decryption with unique IV per message
    std::string plaintext = "Hello, secure world!";
    std::cout << "\n[TEST 1] Basic Encryption/Decryption (Unique IV)" << std::endl;
    std::cout << "Plaintext: " << plaintext << std::endl;
    
    std::string iv1 = EncryptionEnhanced::generateIV();
    std::string encrypted = EncryptionEnhanced::encryptAES_GCM(plaintext, key, iv1);
    if (encrypted.empty()) {
        std::cerr << "❌ Encryption failed!" << std::endl;
        return 1;
    }
    std::cout << "✅ Encrypted successfully (length: " << encrypted.length() << ")" << std::endl;
    
    std::string decrypted = EncryptionEnhanced::decryptAES_GCM(encrypted, key);
    if (decrypted.empty()) {
        std::cerr << "❌ Decryption failed!" << std::endl;
        return 1;
    }
    std::cout << "Decrypted: " << decrypted << std::endl;
    
    if (plaintext == decrypted) {
        std::cout << "✅ Round-trip successful!" << std::endl;
    } else {
        std::cerr << "❌ Decrypted text doesn't match original!" << std::endl;
        return 1;
    }
    
    // Test 2: Chat message encryption with new IV
    std::cout << "\n[TEST 2] Chat Message Encryption (Different IV)" << std::endl;
    std::string chatMsg = "/msg alice Hello Alice! This is a secret message.";
    std::cout << "Original message: " << chatMsg << std::endl;
    
    std::string iv2 = EncryptionEnhanced::generateIV();
    encrypted = EncryptionEnhanced::encryptAES_GCM(chatMsg, key, iv2);
    decrypted = EncryptionEnhanced::decryptAES_GCM(encrypted, key);
    
    if (chatMsg == decrypted) {
        std::cout << "✅ Chat message encrypted and decrypted successfully!" << std::endl;
    } else {
        std::cerr << "❌ Chat message decryption failed!" << std::endl;
        return 1;
    }
    
    // Test 3: With AAD (Additional Authenticated Data)
    std::cout << "\n[TEST 3] Encryption with AAD" << std::endl;
    std::string aad = "sender=alice,recipient=bob,counter=1";
    std::string iv3 = EncryptionEnhanced::generateIV();
    encrypted = EncryptionEnhanced::encryptAES_GCM(plaintext, key, iv3, aad);
    decrypted = EncryptionEnhanced::decryptAES_GCM(encrypted, key, aad);
    
    if (plaintext == decrypted) {
        std::cout << "✅ AAD encryption successful!" << std::endl;
    } else {
        std::cerr << "❌ AAD decryption failed!" << std::endl;
        return 1;
    }
    
    // Test 4: AAD mismatch detection
    std::cout << "\n[TEST 4] AAD Tampering Detection" << std::endl;
    std::string wrongAAD = "sender=eve,recipient=bob,counter=1";
    decrypted = EncryptionEnhanced::decryptAES_GCM(encrypted, key, wrongAAD);
    
    if (decrypted.empty()) {
        std::cout << "✅ Correctly rejected tampered AAD!" << std::endl;
    } else {
        std::cerr << "❌ Failed to detect AAD tampering!" << std::endl;
        return 1;
    }
    
    std::cout << "\n=== All Tests Passed! ===" << std::endl;
    std::cout << "\nEncryption is now integrated into Connection class." << std::endl;
    std::cout << "All sendData() calls will encrypt, all receiveData() calls will decrypt." << std::endl;
    
    return 0;
}
