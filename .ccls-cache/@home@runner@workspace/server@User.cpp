#include "User.h"

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
    if (pwd == password) {
        authenticated = true;
        return true;
    }
    return false;
}
