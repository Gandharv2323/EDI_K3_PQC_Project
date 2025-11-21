#include "Server.h"
#include "encryption.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>
#include <algorithm>

Server::Server(int serverPort) 
    : serverSocket(-1), port(serverPort), running(false) {
    logFile.open("chat.log", std::ios::app);
    loadUsers("users.json");
}

bool Server::isRunning() const {
    return running.load();
}

Server::~Server() {
    stop();
    if (logFile.is_open()) {
        logFile.close();
    }
}

void Server::loadUsers(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open " << filename << std::endl;
        validUsers.push_back(std::make_unique<User>("admin", "admin"));
        return;
    }
    
    std::string line;
    std::string content;
    while (std::getline(file, line)) {
        content += line;
    }
    file.close();
    
    size_t usersPos = content.find("\"users\"");
    if (usersPos == std::string::npos) {
        std::cerr << "Invalid JSON format" << std::endl;
        return;
    }
    
    size_t arrayStart = content.find('[', usersPos);
    size_t arrayEnd = content.find(']', arrayStart);
    
    if (arrayStart == std::string::npos || arrayEnd == std::string::npos) {
        return;
    }
    
    std::string usersArray = content.substr(arrayStart + 1, arrayEnd - arrayStart - 1);
    
    size_t pos = 0;
    while (pos < usersArray.length()) {
        size_t objStart = usersArray.find('{', pos);
        if (objStart == std::string::npos) break;
        
        size_t objEnd = usersArray.find('}', objStart);
        if (objEnd == std::string::npos) break;
        
        std::string userObj = usersArray.substr(objStart, objEnd - objStart + 1);
        
        size_t unamePos = userObj.find("\"username\"");
        size_t passPos = userObj.find("\"password\"");
        
        if (unamePos != std::string::npos && passPos != std::string::npos) {
            size_t unameStart = userObj.find(':', unamePos);
            size_t unameQuote1 = userObj.find('"', unameStart + 1);
            size_t unameQuote2 = userObj.find('"', unameQuote1 + 1);
            
            size_t passStart = userObj.find(':', passPos);
            size_t passQuote1 = userObj.find('"', passStart + 1);
            size_t passQuote2 = userObj.find('"', passQuote1 + 1);
            
            if (unameQuote1 != std::string::npos && unameQuote2 != std::string::npos &&
                passQuote1 != std::string::npos && passQuote2 != std::string::npos) {
                
                std::string username = userObj.substr(unameQuote1 + 1, unameQuote2 - unameQuote1 - 1);
                std::string password = userObj.substr(passQuote1 + 1, passQuote2 - passQuote1 - 1);
                
                validUsers.push_back(std::make_unique<User>(username, password));
            }
        }
        
        pos = objEnd + 1;
    }
    
    std::cout << "Loaded " << validUsers.size() << " users from " << filename << std::endl;
}

bool Server::start() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }
    
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options" << std::endl;
        return false;
    }
    
    struct sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Failed to bind socket to port " << port << std::endl;
        return false;
    }
    
    if (listen(serverSocket, 10) < 0) {
        std::cerr << "Failed to listen on socket" << std::endl;
        return false;
    }
    
    running = true;
    std::cout << "Server started on port " << port << std::endl;
    logEvent("Server started on port " + std::to_string(port));
    
    acceptClients();
    
    return true;
}

void Server::acceptClients() {
    while (running) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        
        if (clientSocket < 0) {
            if (running) {
                std::cerr << "Failed to accept client connection" << std::endl;
            }
            continue;
        }
        
        std::cout << "New client connected from " 
                  << inet_ntoa(clientAddr.sin_addr) << std::endl;
        logEvent("New client connected from " + std::string(inet_ntoa(clientAddr.sin_addr)));
        
        std::lock_guard<std::mutex> lock(threadsMutex);
        clientThreads.emplace_back(&Server::handleClient, this, clientSocket);
    }
}

void Server::handleClient(int clientSocket) {
    auto handler = std::make_shared<ClientHandler>(clientSocket, this);
    
    handler->run(handler);
    
    if (handler->isAuthenticated()) {
        unregisterClient(handler->getUsername());
    }
}

std::unique_ptr<User> Server::authenticateUser(const std::string& username, const std::string& password) {
    for (const auto& user : validUsers) {
        if (user->getUsername() == username) {
            std::lock_guard<std::mutex> lock(clientsMutex);
            
            if (activeClients.find(username) != activeClients.end()) {
                return nullptr;
            }
            
            if (user->getPassword() == password) {
                auto authenticatedUser = std::make_unique<User>(username, user->getPassword());
                authenticatedUser->setAuthenticated(true);
                return authenticatedUser;
            }
            return nullptr;
        }
    }
    return nullptr;
}

void Server::registerClient(const std::string& username, std::shared_ptr<ClientHandler> client) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    activeClients[username] = client;
    std::cout << "Client registered: " << username << std::endl;
}

void Server::unregisterClient(const std::string& username) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    activeClients.erase(username);
    std::cout << "Client unregistered: " << username << std::endl;
}

bool Server::sendPrivateMessage(const Message& msg) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    auto it = activeClients.find(msg.getRecipient());
    if (it != activeClients.end()) {
        std::string formattedMsg = "[Private from " + msg.getSender() + "]: " + msg.getContent();
        return it->second->sendMessage(formattedMsg);
    }
    
    return false;
}

void Server::broadcastMessage(const Message& msg, const std::string& excludeUser) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    std::string formattedMsg;
    if (msg.getType() == MessageType::SYSTEM) {
        formattedMsg = "[SYSTEM]: " + msg.getContent();
    } else {
        formattedMsg = "[" + msg.getSender() + "]: " + msg.getContent();
    }
    
    for (auto& pair : activeClients) {
        if (pair.first != excludeUser) {
            pair.second->sendMessage(formattedMsg);
        }
    }
}

void Server::logMessage(const Message& msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (logFile.is_open()) {
        logFile << msg.toString() << std::endl;
        logFile.flush();
    }
}

void Server::logEvent(const std::string& event) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (logFile.is_open()) {
        time_t now = std::time(nullptr);
        std::tm* timeinfo = std::localtime(&now);
        char timestamp[64];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
        
        logFile << "[" << timestamp << "] " << event << std::endl;
        logFile.flush();
    }
    
    std::cout << event << std::endl;
}

void Server::stop() {
    bool expected = true;
    if (!running.compare_exchange_strong(expected, false)) {
        return;
    }
    
    logEvent("Server shutting down");
    
    if (serverSocket >= 0) {
        close(serverSocket);
        serverSocket = -1;
    }
    
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        for (auto& pair : activeClients) {
            pair.second->stop();
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(threadsMutex);
        for (auto& thread : clientThreads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        clientThreads.clear();
    }
}
