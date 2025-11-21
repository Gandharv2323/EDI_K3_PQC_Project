#include "encryption.h"

const std::string Encryption::XOR_KEY = "ChatServer2025SecretKey!";

std::string Encryption::encryptXOR(const std::string& plaintext) {
    std::string encrypted = plaintext;
    size_t keyLen = XOR_KEY.length();
    
    for (size_t i = 0; i < plaintext.length(); ++i) {
        encrypted[i] = plaintext[i] ^ XOR_KEY[i % keyLen];
    }
    
    return encrypted;
}

std::string Encryption::decryptXOR(const std::string& ciphertext) {
    return encryptXOR(ciphertext);
}
