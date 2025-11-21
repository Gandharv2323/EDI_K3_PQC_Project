#include "encryption_enhanced.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <cstring>

const std::string EncryptionEnhanced::AES_KEY = "ChatServer2025SecureAESKey256bit!";
const unsigned char EncryptionEnhanced::IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

std::string EncryptionEnhanced::sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string EncryptionEnhanced::encryptAES(const std::string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    std::vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int ciphertext_len = 0;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           (const unsigned char*)AES_KEY.c_str(), IV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          (const unsigned char*)plaintext.c_str(),
                          plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    ciphertext.resize(ciphertext_len);
    return base64Encode(ciphertext);
}

std::string EncryptionEnhanced::decryptAES(const std::string& ciphertext_b64) {
    std::vector<unsigned char> ciphertext = base64Decode(ciphertext_b64);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int plaintext_len = 0;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           (const unsigned char*)AES_KEY.c_str(), IV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return std::string((char*)plaintext.data(), plaintext_len);
}

std::string EncryptionEnhanced::base64Encode(const std::vector<unsigned char>& input) {
    static const char* base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    size_t in_len = input.size();
    size_t idx = 0;
    
    while (in_len--) {
        char_array_3[i++] = input[idx++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
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
            ret += base64_chars[char_array_4[j]];
        
        while (i++ < 3)
            ret += '=';
    }
    
    return ret;
}

std::vector<unsigned char> EncryptionEnhanced::base64Decode(const std::string& input) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::vector<unsigned char> ret;
    int i = 0;
    unsigned char char_array_4[4], char_array_3[3];
    size_t in_len = input.size();
    size_t idx = 0;
    
    while (in_len-- && (input[idx] != '=') && 
           (isalnum(input[idx]) || (input[idx] == '+') || (input[idx] == '/'))) {
        char_array_4[i++] = input[idx]; idx++;
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
        for (int j = i; j < 4; j++)
            char_array_4[j] = 0;
        
        for (int j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);
        
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        
        for (int j = 0; j < i - 1; j++)
            ret.push_back(char_array_3[j]);
    }
    
    return ret;
}

std::string EncryptionEnhanced::generateSalt() {
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));
    
    std::stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];
    }
    return ss.str();
}

std::string EncryptionEnhanced::hashPassword(const std::string& password, const std::string& salt) {
    return sha256(password + salt);
}

bool EncryptionEnhanced::verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) {
    return hashPassword(password, salt) == hash;
}
