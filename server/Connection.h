#ifndef CONNECTION_H
#define CONNECTION_H

#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <openssl/evp.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <sys/mman.h>
#endif

// Custom exception for decryption failures
class DecryptionError : public std::runtime_error {
public:
    explicit DecryptionError(const std::string& message);
};

// Secure key buffer: stores cryptographic key material with secure memory handling
// Features:
// - Explicit memory zeroing on destruction and reassignment
// - Locks memory to prevent swapping (on Unix/Linux via mlock)
// - Move-only semantics to prevent accidental copies
// - Cannot be copied, only moved
class SecureKeyBuffer {
private:
    std::vector<unsigned char> buffer;
    static constexpr size_t EXPECTED_SIZE = 32;  // AES-256 = 32 bytes
    
    // Helper: Securely zero memory
    static void secureZero(unsigned char* ptr, size_t size) {
        if (ptr && size > 0) {
            OPENSSL_cleanse(ptr, size);
        }
    }
    
    // Helper: Lock memory to prevent swapping (best effort)
    static void lockMemory(unsigned char* ptr, size_t size) {
        if (ptr && size > 0) {
#ifdef _WIN32
            // VirtualLock may fail due to working set limits, but we try
            BOOL result = VirtualLock(ptr, size);
            if (!result) {
                // Silently continue - VirtualLock can fail due to working set size limits
            }
#else
            // mlock may fail due to permissions, but we try
            int result = mlock(ptr, size);
            if (result != 0) {
                // Silently continue - mlock can fail due to RLIMIT_MEMLOCK
            }
#endif
        }
    }
    
    // Helper: Unlock memory
    static void unlockMemory(unsigned char* ptr, size_t size) {
        if (ptr && size > 0) {
#ifdef _WIN32
            VirtualUnlock(ptr, size);  // Ignore errors
#else
            munlock(ptr, size);  // Ignore errors
#endif
        }
    }
    
public:
    // Default constructor: creates empty buffer
    SecureKeyBuffer() : buffer() {}
    
    // Constructor: accepts 32-byte key
    SecureKeyBuffer(const unsigned char* keyData, size_t size) : buffer(size) {
        if (size != EXPECTED_SIZE) {
            throw std::invalid_argument("Key must be exactly " + std::to_string(EXPECTED_SIZE) + " bytes, got " + std::to_string(size));
        }
        if (!keyData) {
            throw std::invalid_argument("Key data pointer cannot be null");
        }
        // Copy data
        std::memcpy(buffer.data(), keyData, size);
        // Lock memory to prevent swapping
        lockMemory(buffer.data(), buffer.size());
    }
    
    // Constructor: accepts raw/binary key string (not base64)
    explicit SecureKeyBuffer(const std::string& keyStr) {
        // Validate size BEFORE populating buffer
        if (keyStr.size() != EXPECTED_SIZE) {
            throw std::invalid_argument("Key must be exactly " + std::to_string(EXPECTED_SIZE) + " bytes, got " + std::to_string(keyStr.size()));
        }
        // Size is valid - populate buffer
        buffer.assign(keyStr.begin(), keyStr.end());
        // Lock memory to prevent swapping
        lockMemory(buffer.data(), buffer.size());
    }
    
    // Destructor: securely zero memory and unlock
    ~SecureKeyBuffer() {
        unlockMemory(buffer.data(), buffer.size());
        secureZero(buffer.data(), buffer.size());
    }
    
    // Move constructor
    SecureKeyBuffer(SecureKeyBuffer&& other) noexcept {
        buffer = std::move(other.buffer);
        lockMemory(buffer.data(), buffer.size());
    }
    
    // Move assignment
    SecureKeyBuffer& operator=(SecureKeyBuffer&& other) noexcept {
        if (this != &other) {
            // Securely erase old key
            unlockMemory(buffer.data(), buffer.size());
            secureZero(buffer.data(), buffer.size());
            buffer.clear();
            
            // Move new key
            buffer = std::move(other.buffer);
            lockMemory(buffer.data(), buffer.size());
        }
        return *this;
    }
    
    // Explicitly delete copy operations
    SecureKeyBuffer(const SecureKeyBuffer&) = delete;
    SecureKeyBuffer& operator=(const SecureKeyBuffer&) = delete;
    
    // Get data pointer (read-only)
    const unsigned char* data() const { return buffer.data(); }
    
    // Get size
    size_t size() const { return buffer.size(); }
    
    // Convert to hex string for logging session IDs (only first 8 bytes)
    std::string toHexString(size_t limit = 8) const {
        std::string result;
        size_t count = std::min(limit, buffer.size());
        for (size_t i = 0; i < count; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", buffer[i]);
            result += hex;
        }
        return result;
    }
    
    // Check if empty
    bool empty() const { return buffer.empty(); }
    
    // Explicit cleanup
    void clear() {
        unlockMemory(buffer.data(), buffer.size());
        secureZero(buffer.data(), buffer.size());
        buffer.clear();
    }
};

class Connection {
protected:
    int socketFd;
    struct sockaddr_in address;
    bool encryptionEnabled;
    bool allowPlaintextFallback;  // Configuration flag: if true, fallback to plaintext on encryption failure; if false, fail hard
    SecureKeyBuffer sessionKey;  // Secure key storage - empty initially (default constructor)
     
    // Low-level receive (raw bytes)
    std::string receiveRaw();
    
public:
    Connection();
    virtual ~Connection();
    
    int getSocketFd() const;
    void setSocketFd(int fd);
    
    // Low-level send (raw bytes) - public for session key transmission
    bool sendRaw(const std::string& data);
    
    // High-level send/receive (with encryption)
    bool sendData(const std::string& data);
    
    // Receives data with automatic decryption when encryption is enabled.
    // IMPORTANT: If encryptionEnabled is true, decryption is REQUIRED and failures throw DecryptionError.
    // If encryptionEnabled is false, returns plaintext as-is.
    // Throws DecryptionError if:
    //   - Encryption is enabled but no valid session key exists
    //   - Decryption fails (corrupted data, wrong key, or tampered message)
    // Never returns plaintext when encryption is enabled (prevents fallback attacks).
    std::string receiveData();
    
    void enableEncryption(bool enable = true);
    bool isEncryptionEnabled() const;
    
    // Plaintext fallback configuration (SECURITY: default is false - no silent fallback)
    void setAllowPlaintextFallback(bool allow) { allowPlaintextFallback = allow; }
    bool isPlaintextFallbackAllowed() const { return allowPlaintextFallback; }
    
    // Session key management (now using secure storage)
    void setSessionKey(const unsigned char* keyData, size_t keyLen);
    void setSessionKeyFromString(const std::string& key);
    std::string getSessionKeyHex(size_t limit = 8) const;  // Get hex representation for logging only
    void generateSessionKey();  // Generate random session key
    
    void closeConnection();
};

#endif
