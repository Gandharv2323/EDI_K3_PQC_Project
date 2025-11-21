#ifndef SERVER_H
#define SERVER_H

#include "Connection.h"
#include "ClientHandler.h"
#include "User.h"
#include "Message.h"
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <fstream>
#include <atomic>

class Server {
private:
    int serverSocket;
    int port;
    std::atomic<bool> running;
    
    std::vector<std::unique_ptr<User>> validUsers;
    std::map<std::string, std::shared_ptr<ClientHandler>> activeClients;
    std::vector<std::thread> clientThreads;
    
    std::mutex clientsMutex;
    std::mutex threadsMutex;
    std::mutex logMutex;
    std::ofstream logFile;
    
    void loadUsers(const std::string& filename);
    void acceptClients();
    void handleClient(int clientSocket);
    
public:
    Server(int serverPort);
    ~Server();
    
    bool start();
    void stop();
    bool isRunning() const;
    
    std::unique_ptr<User> authenticateUser(const std::string& username, const std::string& password);
    
    void registerClient(const std::string& username, std::shared_ptr<ClientHandler> client);
    void unregisterClient(const std::string& username);
    
    bool sendPrivateMessage(const Message& msg);
    void broadcastMessage(const Message& msg, const std::string& excludeUser);
    
    void logMessage(const Message& msg);
    void logEvent(const std::string& event);
};

#endif
