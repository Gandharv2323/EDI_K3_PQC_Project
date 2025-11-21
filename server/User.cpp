#include "User.h"
#include "password_hash.h"
#include "Logger.h"

User::User() : username(""), password(""), authenticated(false) {}

User::User(const std::string& uname, const std::string& pwd) 
    : username(uname), password(pwd), authenticated(false) {}

std::string User::getUsername() const {
    return username;
}

std::string User::getPassword() const {
    return password;
}

bool User::isAuthenticated() const {
    return authenticated;
}

void User::setAuthenticated(bool auth) {
    authenticated = auth;
}

bool User::authenticate(const std::string& pwd) {
    // Use PasswordHash::verifyPassword which handles both hashed and plaintext (legacy)
    if (PasswordHash::verifyPassword(pwd, password)) {
        authenticated = true;
        
        // Log successful authentication with non-sensitive identifier
        std::string masked_user = Logger::maskUsername(username);
        Logger::security("User authentication", masked_user, "authentication successful");
        
        return true;
    }
    
    // Log failed authentication (omit username entirely for security)
    Logger::warn("User authentication", "[unknown]", "authentication failed: invalid credentials");
    return false;
}
