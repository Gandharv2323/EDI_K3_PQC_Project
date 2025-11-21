#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include <ctime>
#include <sstream>
#include <iomanip>

/**
 * Thread-Safe Structured Logging Framework
 * 
 * Features:
 * - Thread-safe logging with mutex protection
 * - Leveled logging: DEBUG, INFO, WARN, ERROR, SECURITY
 * - Structured log format with timestamp and category
 * - File rotation support (daily by default)
 * - Secure storage with restricted permissions (Unix-like systems)
 * - PII-safe: supports masked/hashed identifiers
 * - No std::cout/std::cerr usage (prevents interleaving and exposure)
 * 
 * Security Properties:
 * - Thread-safe: All operations protected by mutex
 * - No race conditions on file writes
 * - Timestamps for audit trail
 * - Log file permissions: 0600 (owner read/write only)
 * - Separate SECURITY category for audit logging
 * 
 * Usage Examples:
 * Logger::info("User authentication", "session_id_abc123", "authentication successful");
 * Logger::warn("User authentication", "session_id_abc123", "authentication failed: invalid credentials");
 * Logger::security("User authentication", "user_123", "password reset attempted");
 */

class Logger {
public:
    // Log levels
    enum class Level {
        DEBUG,
        INFO,
        WARN,
        ERR,  // Renamed from ERROR to avoid Windows macro conflict
        SECURITY  // Separate category for security/audit events
    };
    
    /**
     * Initialize the logging system
     * 
     * @param log_file - Path to log file (e.g., "server.log")
     * @param enable_console - Also log to stderr (default: false for security)
     */
    static void initialize(const std::string& log_file, bool enable_console = false);
    
    /**
     * Log a message with automatic timestamp and level
     * 
     * @param level - Log level (DEBUG, INFO, WARN, ERROR, SECURITY)
     * @param category - Log category (e.g., "User authentication", "Encryption", "Network")
     * @param safe_id - Non-sensitive identifier (e.g., masked username, session ID, user ID - NOT plaintext username)
     * @param message - Log message (should NOT contain PII)
     */
    static void log(Level level, const std::string& category, 
                    const std::string& safe_id, const std::string& message);
    
    /**
     * Convenience methods for each log level
     */
    static void debug(const std::string& category, const std::string& safe_id, const std::string& message) {
        log(Level::DEBUG, category, safe_id, message);
    }
    
    static void info(const std::string& category, const std::string& safe_id, const std::string& message) {
        log(Level::INFO, category, safe_id, message);
    }
    
    static void warn(const std::string& category, const std::string& safe_id, const std::string& message) {
        log(Level::WARN, category, safe_id, message);
    }
    
    static void error(const std::string& category, const std::string& safe_id, const std::string& message) {
        log(Level::ERR, category, safe_id, message);
    }
    
    static void security(const std::string& category, const std::string& safe_id, const std::string& message) {
        log(Level::SECURITY, category, safe_id, message);
    }
    
    /**
     * Rotate log file (call daily or on startup)
     * Renames current log to log.YYYY-MM-DD and creates new log file
     */
    static void rotate();
    
    /**
     * Close and flush all log files
     * Should be called on shutdown
     */
    static void shutdown();
    
    /**
     * Helper: Mask a username for safe logging
     * Returns first character + asterisks + last character
     * Example: "alice123" -> "a*****23"
     * 
     * @param username - Raw username (up to 6 chars shows all, longer masked)
     * @return Masked username safe for logging
     */
    static std::string maskUsername(const std::string& username);
    
private:
    static std::mutex log_mutex;
    static std::ofstream log_file;
    static std::string log_filename;
    static bool console_enabled;
    static bool initialized;
    
    // Helper to get level name string
    static std::string levelToString(Level level);
    
    // Helper to get current timestamp
    static std::string getCurrentTimestamp();
};

#endif
