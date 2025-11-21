#ifndef PASSWORD_HASH_H
#define PASSWORD_HASH_H

#include <string>

/**
 * Password Hashing Utilities using PBKDF2-HMAC-SHA256
 * Follows OWASP recommendations for secure password storage
 */
class PasswordHash {
public:
    /**
     * Hash a password using PBKDF2-HMAC-SHA256
     * @param password - plaintext password
     * @param salt - optional salt (if empty, generates random 16-byte salt)
     * @return string in format: "pbkdf2:sha256:iterations$salt$hash"
     */
    static std::string hashPassword(const std::string& password, const std::string& salt = "");
    
    /**
     * Verify a password against a stored hash
     * @param password - plaintext password to verify
     * @param storedHash - hash string from hashPassword()
     * @return true if password matches, false otherwise
     */
    static bool verifyPassword(const std::string& password, const std::string& storedHash);
    
    /**
     * Generate random salt (16 bytes, hex-encoded)
     */
    static std::string generateSalt();
    
private:
    static const int ITERATIONS = 600000; // OWASP 2023 recommendation
    static const int SALT_LENGTH = 16;    // 16 bytes = 128 bits
    static const int HASH_LENGTH = 32;    // 32 bytes = 256 bits
};

#endif // PASSWORD_HASH_H
