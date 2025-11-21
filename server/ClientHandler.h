#ifndef CLIENTHANDLER_H
#define CLIENTHANDLER_H

#include "Connection.h"
#include "User.h"
#include <string>
#include <memory>
#include <atomic>

class Server;
 
class ClientHandler {
private:
    std::unique_ptr<Connection> connection;
    std::unique_ptr<User> user;
    Server* server;
    std::atomic<bool> running;
    
    bool authenticate();
    void handleCommands();
    void processCommand(const std::string& command);
    void handlePrivateMessage(const std::string& command);
    void handleBroadcast(const std::string& command);

public:
    ClientHandler(int clientSocket, Server* srv);
    ~ClientHandler();
    
    void run(std::shared_ptr<ClientHandler> self);
    void stop();
    
    bool sendMessage(const std::string& message);
    std::string getUsername() const;
    bool isAuthenticated() const;
};

#endif
