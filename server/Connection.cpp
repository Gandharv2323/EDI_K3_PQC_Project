#include "Connection.h"
#include "encryption_enhanced.h"
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <chrono>

// Helper: Format data for logging output
static std::string formatDataForLog(const std::string& data, bool isEncrypted = false) {
    std::string display = data;
    if (display.length() > 100) {
        display = display.substr(0, 97) + "...";
    }
    // Replace newlines with \n for visibility
    for (size_t i = 0; i < display.length(); ++i) {
        if (display[i] == '\n') {
            display.replace(i, 1, "\\n");
        }
    }
    if (isEncrypted) {
        display += " [ENCRYPTED]";
    }
    return display;
}

// Helper: Get current ISO timestamp
static std::string getTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return oss.str();
}

// DecryptionError constructor
DecryptionError::DecryptionError(const std::string& message) 
    : std::runtime_error("[CRYPTO] DecryptionError: " + message) {}

Connection::Connection() : socketFd(-1), encryptionEnabled(false), allowPlaintextFallback(false) {
    std::memset(&address, 0, sizeof(address));
}

Connection::~Connection() {
    closeConnection();
}
 
int Connection::getSocketFd() const {
    return socketFd;
}

void Connection::setSocketFd(int fd) {
    socketFd = fd;
}

void Connection::enableEncryption(bool enable) {
    encryptionEnabled = enable;
}

bool Connection::isEncryptionEnabled() const {
    return encryptionEnabled;
}

bool Connection::sendRaw(const std::string& data) {
    if (socketFd < 0) {
        return false;
    }
    
    std::string message = data + "\n";
    ssize_t sent = send(socketFd, message.c_str(), message.length(), 0);
    
    return sent > 0;
}

std::string Connection::receiveRaw() {
    if (socketFd < 0) {
        return "";
    }
    
    char buffer[4096];
    std::memset(buffer, 0, sizeof(buffer));
    
    ssize_t bytesReceived = recv(socketFd, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesReceived <= 0) {
        return "";
    }
    
    std::string data(buffer, bytesReceived);
    
    if (!data.empty() && data.back() == '\n') {
        data.pop_back();
    }
    if (!data.empty() && data.back() == '\r') {
        data.pop_back();
    }
    
    return data;
}

bool Connection::sendData(const std::string& data) {
    // If encryption is not enabled, send as plaintext
    if (!encryptionEnabled) {
        std::cerr << "[" << getTimestamp() << "] [CPP->BRIDGE] [PLAINTEXT] \""
                  << formatDataForLog(data, false) << "\"" << std::endl;
        return sendRaw(data);
    }
    
    // Encryption is REQUIRED - fail if key is missing
    if (sessionKey.empty()) {
        std::cerr << "[CRYPTO] ERROR: Encryption enabled but no session key available - cannot send data" << std::endl;
        std::cerr << "[CRYPTO] ERROR: Use setSessionKey() or generateSessionKey() before sending encrypted data" << std::endl;
        // Do NOT fall back to plaintext - this is a configuration error
        return false;
    }
    
    // Validate session key size
    if (sessionKey.size() != 32) {
        std::cerr << "[CRYPTO] ERROR: Invalid session key size: " << sessionKey.size() 
                  << " bytes (expected 32)" << std::endl;
        return false;
    }
    
    // Generate unique IV for this message (12 bytes for GCM mode)
    std::string iv = EncryptionEnhanced::generateIV();
    if (iv.empty() || iv.length() != 12) {
        std::cerr << "[CRYPTO] ERROR: IV generation failed - returned " 
                  << (iv.empty() ? "empty" : "invalid length (" + std::to_string(iv.length()) + ")") 
                  << std::endl;
        std::cerr << "[CRYPTO] ERROR: Cannot continue without valid IV - rejecting send" << std::endl;
        // Do NOT fall back to plaintext - this indicates crypto subsystem failure
        return false;
    }
    
    // Encrypt data with session key and unique IV
    std::string keyStr(reinterpret_cast<const char*>(sessionKey.data()), sessionKey.size());
    std::string encrypted;
    try {
        encrypted = EncryptionEnhanced::encryptAES_GCM(data, keyStr, iv);
    } catch (const std::exception& e) {
        std::cerr << "[CRYPTO] ERROR: encryptAES_GCM threw exception: " << e.what() << std::endl;
        std::cerr << "[CRYPTO] ERROR: Message size: " << data.length() << " bytes" << std::endl;
        return false;
    }
    
    if (encrypted.empty()) {
        std::cerr << "[CRYPTO] ERROR: Encryption returned empty result for " 
                  << data.length() << " byte input" << std::endl;
        std::cerr << "[CRYPTO] ERROR: Possible data corruption or encryption function failure" << std::endl;
        // Check if plaintext fallback is explicitly enabled (should be rare)
        if (allowPlaintextFallback) {
            std::cerr << "[CRYPTO] WARNING: allowPlaintextFallback is enabled - falling back to plaintext" << std::endl;
            return sendRaw(data);
        }
        return false;
    }
    
    // Encryption successful - log it
    std::cerr << "[" << getTimestamp() << "] [CPP->BRIDGE] [ENCRYPTED] \""
              << formatDataForLog(data, true) << "\"" << std::endl;
    
    return sendRaw(encrypted);
}

std::string Connection::receiveData() {
    std::string rawData = receiveRaw();
    
    // If no data received or encryption not enabled, return plaintext as-is
    if (rawData.empty()) {
        return rawData;
    }
    
    if (!encryptionEnabled) {
        std::cerr << "[" << getTimestamp() << "] [BRIDGE->CPP] [PLAINTEXT] \""
                  << formatDataForLog(rawData, false) << "\"" << std::endl;
        return rawData;
    }
    
    // Encryption is enabled - decrypt is REQUIRED, plaintext is REJECTED
    
    // Ensure we have a session key
    if (sessionKey.empty()) {
        std::cerr << "[CRYPTO] ERROR: Encryption enabled but no session key available" << std::endl;
        throw DecryptionError("No session key available for decryption (length=0)");
    }
    
    if (sessionKey.size() != 32) {
        std::cerr << "[CRYPTO] ERROR: Invalid session key length: " << sessionKey.size() 
                  << " bytes (expected 32)" << std::endl;
        throw DecryptionError("Invalid session key length: " + std::to_string(sessionKey.size()) + 
                              " bytes (expected 32 bytes)");
    }
    
    // Log received data size for debugging (without exposing plaintext)
    std::cerr << "[CRYPTO] Attempting decryption of " << rawData.length() << " bytes" << std::endl;
    
    // Try to decrypt - must succeed when encryption is enabled
    // Convert secure key buffer to string for decryption function
    std::string keyStr(reinterpret_cast<const char*>(sessionKey.data()), sessionKey.size());
    std::string decrypted;
    try {
        decrypted = EncryptionEnhanced::decryptAES_GCM(rawData, keyStr);
    } catch (const std::exception& e) {
        std::cerr << "[CRYPTO] ERROR: decryptAES_GCM threw exception: " << e.what() << std::endl;
        std::cerr << "[CRYPTO] This may indicate tampering or key mismatch" << std::endl;
        // Return empty string instead of throwing - allows graceful handling
        // The calling code can decide what to do with empty messages
        return "";
    }
    
    // Check if decryption failed (empty result)
    if (decrypted.empty()) {
        std::cerr << "[CRYPTO] WARNING: Decryption returned empty result (may be tampering or MAC failure)" << std::endl;
        std::cerr << "[CRYPTO] Raw data size=" << rawData.length() << " bytes" << std::endl;
        
        // Log first 16 bytes as hex for debugging
        for (size_t i = 0; i < std::min(size_t(16), rawData.length()); ++i) {
            std::cerr << std::hex << (int)(unsigned char)rawData[i] << " ";
        }
        std::cerr << std::dec << std::endl;
        
        // Return empty string to indicate decryption failed
        // Calling code should handle this gracefully
        return "";
    }
    
    // Decryption successful - log it
    std::cerr << "[" << getTimestamp() << "] [BRIDGE->CPP] [ENCRYPTED] \""
              << formatDataForLog(decrypted, true) << "\"" << std::endl;
    
    return decrypted;
}

void Connection::setSessionKey(const unsigned char* keyData, size_t keyLen) {
    if (keyLen != 32) {
        std::cerr << "[CRYPTO] Invalid session key length: " << keyLen << " (expected 32)" << std::endl;
        throw std::invalid_argument("Session key must be exactly 32 bytes");
    }
    if (!keyData) {
        std::cerr << "[CRYPTO] ERROR: Session key data pointer is null" << std::endl;
        throw std::invalid_argument("Session key data pointer cannot be null");
    }
    try {
        sessionKey = SecureKeyBuffer(keyData, keyLen);
        std::cout << "[CRYPTO] Session key set securely (32 bytes, memory locked)" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[CRYPTO] ERROR: Failed to set session key: " << e.what() << std::endl;
        throw;
    }
}

void Connection::setSessionKeyFromString(const std::string& key) {
    if (key.length() != 32) {
        std::cerr << "[CRYPTO] Invalid session key length: " << key.length() << " (expected 32)" << std::endl;
        throw std::invalid_argument("Session key must be exactly 32 bytes");
    }
    try {
        sessionKey = SecureKeyBuffer(reinterpret_cast<const unsigned char*>(key.data()), key.length());
        std::cout << "[CRYPTO] Session key set securely (32 bytes, memory locked)" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[CRYPTO] ERROR: Failed to set session key from string: " << e.what() << std::endl;
        throw;
    }
}

std::string Connection::getSessionKeyHex(size_t limit) const {
    return sessionKey.toHexString(limit);
}

void Connection::generateSessionKey() {
    std::string keyStr = EncryptionEnhanced::generateKey();
    if (keyStr.empty() || keyStr.length() != 32) {
        std::cerr << "[CRYPTO] Failed to generate session key (invalid length: " << keyStr.length() << ")" << std::endl;
        throw std::runtime_error("Failed to generate valid session key");
    }
    try {
        sessionKey = SecureKeyBuffer(reinterpret_cast<const unsigned char*>(keyStr.data()), keyStr.length());
        std::cout << "[CRYPTO] Generated new session key securely (32 bytes, memory locked)" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[CRYPTO] ERROR: Failed to store generated session key: " << e.what() << std::endl;
        throw;
    }
}

void Connection::closeConnection() {
    if (socketFd >= 0) {
        close(socketFd);
        socketFd = -1;
    }
}
