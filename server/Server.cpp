#include "Server.h"
#include "encryption.h"
#include "Logger.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <unistd.h>
#endif
#include <algorithm>

#ifdef _WIN32
    #define CLOSE_SOCKET closesocket
#else
    #define CLOSE_SOCKET close
#endif

Server::Server(int serverPort) 
    : serverSocket(-1), port(serverPort), running(false) {
#ifdef _WIN32
    // Initialize Winsock on Windows
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed with error: " << result << std::endl;
    }
#endif
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
#ifdef _WIN32
    // Cleanup Winsock on Windows
    WSACleanup();
#endif
}

void Server::loadUsers(const std::string& filename) {
    // Try multiple possible locations for users.json
    // Prioritize parent directory (server/) over current directory (server/build/)
    std::vector<std::string> possiblePaths = {
        "../" + filename,           // ../users.json (from build/ to server/)
        filename,                    // users.json (current directory)
        "../../" + filename,         // ../../users.json
        "../server/" + filename      // ../server/users.json
    };
    
    std::ifstream file;
    std::string actualPath;
    
    for (const auto& path : possiblePaths) {
        file.open(path);
        if (file.is_open()) {
            actualPath = path;
            usersFilePath = path;  // Store the actual path for saving later
            std::cout << "[INFO] Found users file at: " << path << std::endl;
            break;
        }
    }
    
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open " << filename << " in any expected location" << std::endl;
        std::cerr << "Tried paths: ";
        for (const auto& path : possiblePaths) {
            std::cerr << path << " ";
        }
        std::cerr << std::endl;
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

void Server::reloadUsers() {
    std::lock_guard<std::mutex> lock(usersMutex);
    
    // Clear existing users
    validUsers.clear();
    std::cout << "[INFO] Cleared user list, reloading from file..." << std::endl;
    
    // Reload from file
    std::ifstream file(usersFilePath);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Could not open users file at " << usersFilePath << " for reload" << std::endl;
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
        std::cerr << "[ERROR] Invalid JSON format during reload" << std::endl;
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
    
    std::cout << "[INFO] Reloaded " << validUsers.size() << " users from " << usersFilePath << std::endl;
}

bool Server::start() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }
    
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
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
    std::cout << "[SERVER] Creating ClientHandler for socket " << clientSocket << std::endl;
    
    try {
        auto handler = std::make_shared<ClientHandler>(clientSocket, this);
        std::cout << "[SERVER] ClientHandler created, calling run()" << std::endl;
        
        handler->run(handler);
        std::cout << "[SERVER] handler->run() returned" << std::endl;
        
        if (handler->isAuthenticated()) {
            std::cout << "[SERVER] Unregistering user: " << handler->getUsername() << std::endl;
            unregisterClient(handler->getUsername());
        }
    } catch (const std::exception& e) {
        std::cerr << "[SERVER] EXCEPTION in handleClient: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[SERVER] UNKNOWN exception in handleClient" << std::endl;
    }
    
    std::cout << "[SERVER] handleClient thread ending for socket " << clientSocket << std::endl;
}

std::unique_ptr<User> Server::authenticateUser(const std::string& username, const std::string& password) {
    Logger::info("User authentication", "[" + username + "]", "authentication attempt started");
    
    std::lock_guard<std::mutex> usersLock(usersMutex);
    
    for (const auto& user : validUsers) {
        if (user->getUsername() == username) {
            std::lock_guard<std::mutex> lock(clientsMutex);
            
            if (activeClients.find(username) != activeClients.end()) {
                Logger::warn("User authentication", "[" + username + "]", "user already logged in");
                return nullptr;
            }
            
            // Use User::authenticate() which handles both hashed and plaintext passwords
            auto authenticatedUser = std::make_unique<User>(username, user->getPassword());
            if (authenticatedUser->authenticate(password)) {
                Logger::security("User authentication", Logger::maskUsername(username), "authentication successful");
                return authenticatedUser;
            }
            Logger::warn("User authentication", "[" + username + "]", "authentication failed");
            return nullptr;
        }
    }
    Logger::warn("User authentication", "[" + username + "]", "username not found");
    return nullptr;
}

bool Server::registerNewUser(const std::string& username, const std::string& password) {
    // Check if username already exists and register user
    {
        std::lock_guard<std::mutex> lock(usersMutex);
        
        // Check if username already exists
        for (const auto& user : validUsers) {
            if (user->getUsername() == username) {
                logEvent("Registration failed - username '" + username + "' already exists");
                return false;
            }
        }
        
        // Validate username and password
        if (username.length() < 3 || username.length() > 20) {
            logEvent("Registration failed - invalid username length for '" + username + "'");
            return false;
        }
        
        if (password.length() < 4) {
            logEvent("Registration failed - password too short for '" + username + "'");
            return false;
        }
        
        // Create new user
        validUsers.push_back(std::make_unique<User>(username, password));
        logEvent("New user registered: " + username);
        
        // Save to file using the same path we loaded from (usersMutex already held)
        // If usersFilePath is empty (file not found during load), use the first attempted path (../users.json)
        // to ensure consistency with loadUsers() priority order
        saveUsersUnlocked(usersFilePath.empty() ? "../users.json" : usersFilePath);
    }  // Lock released here
    
    // Reload users from file to ensure consistency across all connections
    // This is done outside the lock to avoid deadlock
    std::cout << "[INFO] Reloading user database after registration of '" << username << "'..." << std::endl;
    reloadUsers();
    
    return true;
}

bool Server::saveUsersUnlocked(const std::string& filename) {
    /**
     * PRIVATE: Internal helper for saving users (assumes usersMutex is already held by caller)
     * 
     * Security:
     * - Caller MUST hold usersMutex before calling this function
     * - Writes User::getPassword() which contains PBKDF2-hashed passwords (not plaintext)
     * - Passwords are hashed by ClientHandler::authenticate() before registration
     * 
     * Note: This function assumes all passwords in validUsers are already hashed.
     * If called with plaintext passwords, it will persist them insecurely.
     */
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        logEvent("Failed to open users file for writing: " + filename);
        return false;
    }
    
    file << "{\n";
    file << "  \"users\": [\n";
    
    for (size_t i = 0; i < validUsers.size(); ++i) {
        file << "    {\n";
        file << "      \"username\": \"" << validUsers[i]->getUsername() << "\",\n";
        // Note: getPassword() returns PBKDF2 hash (format: pbkdf2$<iterations>$<salt>$<hash>)
        file << "      \"password\": \"" << validUsers[i]->getPassword() << "\"\n";
        file << "    }";
        
        if (i < validUsers.size() - 1) {
            file << ",";
        }
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    file.close();
    logEvent("Users saved to " + filename);
    return true;
}

bool Server::saveUsers(const std::string& filename) {
    /**
     * PUBLIC: Thread-safe user persistence to disk
     * 
     * Security:
     * - Acquires usersMutex internally to ensure thread-safety
     * - Writes User::getPassword() which contains PBKDF2-hashed passwords (not plaintext)
     * - Passwords are hashed by ClientHandler::authenticate() before registration
     * 
     * Note: This function assumes all passwords in validUsers are already hashed.
     * If called with plaintext passwords, it will persist them insecurely.
     */
    
    std::lock_guard<std::mutex> lock(usersMutex);
    return saveUsersUnlocked(filename);
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
    
    if (serverSocket >= 0) {
        CLOSE_SOCKET(serverSocket);
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
