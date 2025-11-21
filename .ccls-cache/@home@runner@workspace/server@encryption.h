#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

class Encryption {
private:
    static const std::string XOR_KEY;

public:
    static std::string encryptXOR(const std::string& plaintext);
    static std::string decryptXOR(const std::string& ciphertext);
};

#endif
