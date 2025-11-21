#include "Logger.h"
#include <iostream>
#include <sys/stat.h>

// Static members
std::mutex Logger::log_mutex;
std::ofstream Logger::log_file;
std::string Logger::log_filename;
bool Logger::console_enabled = false;
bool Logger::initialized = false;

void Logger::initialize(const std::string& log_file_path, bool enable_console) {
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (initialized) {
        return;  // Already initialized
    }
    
    log_filename = log_file_path;
    console_enabled = enable_console;
    
    // Open log file in append mode
    log_file.open(log_filename, std::ios::app);
    
    if (!log_file.is_open()) {
        std::cerr << "[LOGGER] ERROR: Failed to open log file: " << log_filename << std::endl;
        return;
    }
    
    // Set file permissions to 0600 (owner read/write only) on Unix-like systems
#ifndef _WIN32
    chmod(log_filename.c_str(), 0600);
#endif
    
    initialized = true;
    log(Level::INFO, "Logger", "system", "Logging system initialized");
}

std::string Logger::levelToString(Level level) {
    switch (level) {
        case Level::DEBUG:    return "DEBUG";
        case Level::INFO:     return "INFO";
        case Level::WARN:     return "WARN";
        case Level::ERR:      return "ERROR";
        case Level::SECURITY: return "SECURITY";
        default:              return "UNKNOWN";
    }
}

std::string Logger::getCurrentTimestamp() {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string Logger::maskUsername(const std::string& username) {
    if (username.empty()) {
        return "[anonymous]";
    }
    
    if (username.length() <= 6) {
        // For short usernames, show all characters (no real masking possible)
        return "[user:" + username + "]";
    }
    
    // For longer usernames, mask middle part
    std::string masked = "[";
    masked += username[0];  // First character
    masked += "*";
    
    // Show length info
    masked += std::to_string(username.length());
    
    masked += "*";
    masked += username[username.length() - 1];  // Last character
    masked += "]";
    
    return masked;
}

void Logger::log(Level level, const std::string& category, 
                 const std::string& safe_id, const std::string& message) {
    if (!initialized) {
        // Not initialized yet - use minimal fallback
        if (console_enabled) {
            std::cerr << "[" << levelToString(level) << "] " << category << ": " << message << std::endl;
        }
        return;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (!log_file.is_open()) {
        return;  // Log file not open, silently fail
    }
    
    // Format: TIMESTAMP [LEVEL] [CATEGORY] [safe_id] message
    std::string timestamp = getCurrentTimestamp();
    std::string level_str = levelToString(level);
    
    std::string log_entry = timestamp + " [" + level_str + "] [" + category + "] [" + safe_id + "] " + message;
    
    // Write to file
    log_file << log_entry << std::endl;
    log_file.flush();  // Ensure immediate write
    
    // Optionally also write to console (for debugging)
    if (console_enabled) {
        std::cerr << log_entry << std::endl;
    }
}

void Logger::rotate() {
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (!initialized || !log_file.is_open()) {
        return;
    }
    
    // Close current log file
    log_file.close();
    
    // Generate timestamp for backup filename
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    
    std::ostringstream backup_name;
    backup_name << log_filename << "." << std::put_time(&tm, "%Y-%m-%d");
    
    // Rename current log to backup name
    std::rename(log_filename.c_str(), backup_name.str().c_str());
    
    // Reopen log file (creates new file)
    log_file.open(log_filename, std::ios::app);
    
    if (!log_file.is_open()) {
        std::cerr << "[LOGGER] ERROR: Failed to reopen log file after rotation" << std::endl;
        return;
    }
    
#ifndef _WIN32
    chmod(log_filename.c_str(), 0600);
#endif
    
    log(Level::INFO, "Logger", "system", "Log file rotated");
}

void Logger::shutdown() {
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (log_file.is_open()) {
        log_file << "Logger shutting down" << std::endl;
        log_file.close();
    }
    
    initialized = false;
}
