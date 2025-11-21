#ifndef ENCRYPTION_ENHANCED_H
#define ENCRYPTION_ENHANCED_H

#include <string>
#include <vector>

class EncryptionEnhanced {
private:
    static const std::string AES_KEY;
    static const unsigned char IV[16];
    
public:
    static std::string sha256(const std::string& input);
    static std::string encryptAES(const std::string& plaintext);
    static std::string decryptAES(const std::string& ciphertext);
    
    static std::string base64Encode(const std::vector<unsigned char>& input);
    static std::vector<unsigned char> base64Decode(const std::string& input);
    
    static std::string hashPassword(const std::string& password, const std::string& salt);
    static bool verifyPassword(const std::string& password, const std::string& hash, const std::string& salt);
    static std::string generateSalt();
};

#endif
