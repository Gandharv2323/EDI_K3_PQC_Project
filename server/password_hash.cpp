#include "password_hash.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <iostream>

// Hex encoding helper
static std::string toHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

// Hex decoding helper
static std::vector<unsigned char> fromHex(const std::string& hex) {
    // Validate input length is even
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Invalid hex string: odd length (" + std::to_string(hex.length()) + " characters)");
    }
    
    // Validate all characters are valid hex digits (0-9, a-f, A-F)
    for (size_t i = 0; i < hex.length(); ++i) {
        unsigned char c = static_cast<unsigned char>(hex[i]);
        if (!std::isxdigit(c)) {
            std::ostringstream oss;
            oss << "Invalid hex string: non-hex character '" << c << "' (ASCII " << (int)c 
                << ") at position " << i;
            throw std::invalid_argument(oss.str());
        }
    }
    
    // Convert hex pairs to bytes
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        try {
            unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        } catch (const std::exception& e) {
            std::ostringstream oss;
            oss << "Failed to convert hex pair at position " << i << " ('" << byteString 
                << "'): " << e.what();
            throw std::invalid_argument(oss.str());
        }
    }
    return bytes;
}

// Constant-time string comparison to prevent timing attacks
// Compares two strings byte-by-byte without early exit
// Returns true if both strings match, false otherwise
// Takes the same time regardless of where mismatch occurs
static bool constantTimeCompare(const std::string& a, const std::string& b) {
    // First check: fail if lengths differ (but still check all bytes to maintain constant time)
    volatile unsigned char result = (a.length() == b.length()) ? 0 : 1;
    
    // Determine the maximum length to iterate (avoids out-of-bounds access)
    size_t maxLen = (a.length() > b.length()) ? a.length() : b.length();
    
    // Compare all bytes: XOR each pair and OR into accumulator
    // This ensures all comparisons take the same time
    for (size_t i = 0; i < maxLen; ++i) {
        unsigned char aVal = (i < a.length()) ? static_cast<unsigned char>(a[i]) : 0;
        unsigned char bVal = (i < b.length()) ? static_cast<unsigned char>(b[i]) : 0;
        result |= (aVal ^ bVal);
    }
    
    // Return true only if result is 0 (all bytes matched and lengths were equal)
    return (result == 0);
}

std::string PasswordHash::generateSalt() {
    unsigned char salt[SALT_LENGTH];
    if (RAND_bytes(salt, SALT_LENGTH) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }
    return toHex(salt, SALT_LENGTH);
}

std::string PasswordHash::hashPassword(const std::string& password, const std::string& salt) {
    // Generate salt if not provided
    std::string actualSalt = salt.empty() ? generateSalt() : salt;
    std::vector<unsigned char> saltBytes = fromHex(actualSalt);
    
    // Derive key using PBKDF2-HMAC-SHA256
    unsigned char hash[HASH_LENGTH];
    if (PKCS5_PBKDF2_HMAC(
        password.c_str(), password.length(),
        saltBytes.data(), saltBytes.size(),
        ITERATIONS,
        EVP_sha256(),
        HASH_LENGTH,
        hash
    ) != 1) {
        throw std::runtime_error("PBKDF2 hashing failed");
    }
    
    // Format: pbkdf2:sha256:iterations$salt$hash
    std::ostringstream oss;
    oss << "pbkdf2:sha256:" << ITERATIONS << "$" << actualSalt << "$" << toHex(hash, HASH_LENGTH);
    return oss.str();
}

bool PasswordHash::verifyPassword(const std::string& password, const std::string& storedHash) {
    // SECURITY: Only accept PBKDF2-hashed passwords
    // Plaintext passwords are no longer supported - all stored passwords must be migrated to PBKDF2
    if (storedHash.find("pbkdf2:") != 0) {
        // Legacy plaintext or unknown hash format detected
        std::cerr << "[PASSWORD] SECURITY ALERT: Attempted authentication with non-PBKDF2 hash format" << std::endl;
        std::cerr << "[PASSWORD] ERROR: This account uses an insecure password storage format and must be migrated" << std::endl;
        std::cerr << "[PASSWORD] ACTION REQUIRED: User must reset their password to enable login" << std::endl;
        std::cerr << "[PASSWORD] DETAILS: Expected hash to start with 'pbkdf2:' but got format: " 
                  << (storedHash.length() > 20 ? storedHash.substr(0, 20) + "..." : storedHash) << std::endl;
        return false;
    }
    
    // Parse stored hash: pbkdf2:sha256:iterations$salt$hash
    std::istringstream iss(storedHash);
    std::string algorithm, hashFunc, iterStr, salt, hash;
    
    // Split by colons and validate each extraction
    if (!std::getline(iss, algorithm, ':')) {
        std::cerr << "[PASSWORD] ERROR: Failed to parse algorithm from hash" << std::endl;
        return false;
    }
    
    if (!std::getline(iss, hashFunc, ':')) {
        std::cerr << "[PASSWORD] ERROR: Failed to parse hash function from hash" << std::endl;
        return false;
    }
    
    if (!std::getline(iss, iterStr, '$')) {
        std::cerr << "[PASSWORD] ERROR: Failed to parse iteration count from hash" << std::endl;
        return false;
    }
    
    if (!std::getline(iss, salt, '$')) {
        std::cerr << "[PASSWORD] ERROR: Failed to parse salt from hash" << std::endl;
        return false;
    }
    
    if (!std::getline(iss, hash)) {
        std::cerr << "[PASSWORD] ERROR: Failed to parse hash value from hash string" << std::endl;
        return false;
    }
    
    // Validate that all fields are non-empty
    if (algorithm.empty() || hashFunc.empty() || iterStr.empty() || salt.empty() || hash.empty()) {
        std::cerr << "[PASSWORD] ERROR: Invalid stored hash format - empty fields detected" << std::endl;
        std::cerr << "[PASSWORD] DEBUG: algorithm=" << (algorithm.empty() ? "EMPTY" : "OK");
        std::cerr << " hashFunc=" << (hashFunc.empty() ? "EMPTY" : "OK");
        std::cerr << " iterStr=" << (iterStr.empty() ? "EMPTY" : "OK");
        std::cerr << " salt=" << (salt.empty() ? "EMPTY" : "OK");
        std::cerr << " hash=" << (hash.empty() ? "EMPTY" : "OK") << std::endl;
        return false;
    }
    
    // Validate algorithm and hash function
    if (algorithm != "pbkdf2" || hashFunc != "sha256") {
        std::cerr << "[PASSWORD] ERROR: Unsupported hash format - algorithm=" << algorithm 
                  << " hashFunc=" << hashFunc << std::endl;
        return false;
    }
    
    // Validate that iterStr is a valid integer
    try {
        size_t pos;
        int iterations = std::stoi(iterStr, &pos);
        if (pos != iterStr.length()) {
            // Not all characters were converted to integer
            std::cerr << "[PASSWORD] ERROR: Invalid iteration count format (non-numeric characters): " << iterStr << std::endl;
            return false;
        }
        if (iterations <= 0) {
            std::cerr << "[PASSWORD] ERROR: Invalid iteration count (must be positive): " << iterations << std::endl;
            return false;
        }
    } catch (const std::invalid_argument& e) {
        std::cerr << "[PASSWORD] ERROR: Failed to parse iteration count as integer: " << iterStr << std::endl;
        return false;
    } catch (const std::out_of_range& e) {
        std::cerr << "[PASSWORD] ERROR: Iteration count out of range: " << iterStr << std::endl;
        return false;
    }
    
    // Hash the provided password with the stored salt
    std::string computedHash = hashPassword(password, salt);
    
    // Compare hashes using constant-time comparison to prevent timing attacks
    // This prevents attackers from determining password correctness by measuring response time
    return constantTimeCompare(computedHash, storedHash);
}
