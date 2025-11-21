#ifndef USER_H
#define USER_H

#include <string>

class User {
private:
    std::string username;
    std::string password;
    bool authenticated;

public:
    User();
    User(const std::string& uname, const std::string& pwd);
    
    std::string getUsername() const;
    std::string getPassword() const;
    bool isAuthenticated() const;
    void setAuthenticated(bool auth);
    
    bool authenticate(const std::string& pwd);
};

#endif
