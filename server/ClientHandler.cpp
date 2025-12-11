#include "ClientHandler.h"
#include "Server.h"
#include "Message.h"
#include "encryption_enhanced.h"
#include "password_hash.h"
#include <sstream>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

// commands

ClientHandler::ClientHandler(int clientSocket, Server* srv) 
    : connection(std::make_unique<Connection>()), 
      user(nullptr), 
      server(srv), 
      running(true) {
    connection->setSocketFd(clientSocket);
    
    // Generate unique session key for this connection 
    connection->generateSessionKey();
    
    // Note: Encryption will be enabled AFTER successful authentication
    // During auth, messages come from the bridge unencrypted
    // After auth, we derive a shared key and enable encryption
    std::cout << "[CRYPTO] Generated session key, will enable encryption after auth" << std::endl;
}

ClientHandler::~ClientHandler() {
    stop();
}

bool ClientHandler::authenticate() {
    connection->sendData("=== Chat Server Authentication ===");
    connection->sendData("1. Login");
    connection->sendData("2. Register");
    connection->sendData("Choose option (1 or 2): ");
    
    std::string choice;
    try {
        choice = connection->receiveData();
    } catch (const DecryptionError& e) {
        std::cerr << "[AUTH] Decryption error during authentication choice: " << e.what() << std::endl;
        connection->sendData("ERROR: Message authentication failed. Connection rejected.");
        return false;
    }
    
    if (choice.empty()) {
        return false;
    }
    
    // Handle login
    if (choice == "1" || choice == "login" || choice == "Login") {
        connection->sendData("=== Login ===");
        connection->sendData("Username: ");
        std::string username;
        try {
            username = connection->receiveData();
        } catch (const DecryptionError& e) {
            std::cerr << "[AUTH] Decryption error receiving username: " << e.what() << std::endl;
            connection->sendData("ERROR: Message authentication failed.");
            return false;
        }
        
        if (username.empty()) {
            return false;
        }
        
        connection->sendData("Password: ");
        std::string password;
        try {
            password = connection->receiveData();
        } catch (const DecryptionError& e) {
            std::cerr << "[AUTH] Decryption error receiving password: " << e.what() << std::endl;
            connection->sendData("ERROR: Message authentication failed.");
            return false;
        }
        
        if (password.empty()) {
            return false;
        }
        
        // Debug logging - don't log username (PII)
        std::cout << "[DEBUG] Login attempt (password length: " << password.length() << ")" << std::endl;
        
        user = server->authenticateUser(username, password);
        
        if (user && user->isAuthenticated()) {
            connection->sendData("Authentication successful! Welcome!");
            connection->sendData("Available commands:");
            connection->sendData("  /msg <username> <message> - Send private message");
            connection->sendData("  /broadcast <message> - Send message to all users");
            connection->sendData("  /quit - Disconnect from server");
            server->logEvent("Authentication successful");
            return true;
        } else {
            connection->sendData("Authentication failed. Invalid credentials or user already logged in.");
            server->logEvent("Authentication failed");
            return false;
        }
    }
    // Handle registration
    else if (choice == "2" || choice == "register" || choice == "Register") {
        connection->sendData("=== Registration ===");
        connection->sendData("Choose a username (3-20 characters): ");
        std::string username;
        try {
            username = connection->receiveData();
        } catch (const DecryptionError& e) {
            std::cerr << "[AUTH] Decryption error receiving registration username: " << e.what() << std::endl;
            connection->sendData("ERROR: Message authentication failed.");
            return false;
        }
        
        if (username.empty()) {
            return false;
        }
        
        connection->sendData("Choose a password (minimum 4 characters): ");
        std::string password;
        try {
            password = connection->receiveData();
        } catch (const DecryptionError& e) {
            std::cerr << "[AUTH] Decryption error receiving registration password: " << e.what() << std::endl;
            connection->sendData("ERROR: Message authentication failed.");
            return false;
        }
        
        if (password.empty()) {
            return false;
        }
        
        connection->sendData("Confirm password: ");
        std::string confirmPassword;
        try {
            confirmPassword = connection->receiveData();
        } catch (const DecryptionError& e) {
            std::cerr << "[AUTH] Decryption error receiving password confirmation: " << e.what() << std::endl;
            connection->sendData("ERROR: Message authentication failed.");
            return false;
        }
        
        if (confirmPassword.empty()) {
            return false;
        }
        
        if (password != confirmPassword) {
            connection->sendData("Passwords do not match. Registration failed.");
            server->logEvent("Failed registration attempt - password mismatch for '" + username + "'");
            return false;
        }
        
        // Hash the password before storing
        std::string hashedPassword;
        try {
            hashedPassword = PasswordHash::hashPassword(password);
            // Generate anonymized session ID from session key (first 8 chars)
            std::string sessionId = connection->getSessionKeyHex(8);
            std::cout << "[PASSWORD] Hashed new password for session: " << sessionId << std::endl;
        } catch (const std::exception& e) {
            connection->sendData("Registration failed due to server error.");
            server->logEvent("Password hashing failed for '" + username + "': " + e.what());
            return false;
        }
        
        if (server->registerNewUser(username, hashedPassword)) {
            connection->sendData("Registration successful! You can now login.");
            connection->sendData("Please reconnect and login with your new credentials.");
            server->logEvent("Registration completed - session: " + connection->getSessionKeyHex(8));
            return false; // Return false to disconnect and let them login
        } else {
            connection->sendData("Registration failed. Username may already exist or invalid credentials.");
            server->logEvent("Failed registration attempt for username '" + username + "'");
            return false;
        }
    }
    else {
        connection->sendData("Invalid choice. Disconnecting...");
        return false;
    }
}

void ClientHandler::run(std::shared_ptr<ClientHandler> self) {
    std::cout << "[CLIENT] Starting client handler thread" << std::endl;
    
    if (!authenticate()) {
        std::cout << "[CLIENT] Authentication failed, terminating" << std::endl;
        running = false;
        return;
    }
    
    std::cout << "[CLIENT] Authentication successful, enabling encryption" << std::endl;
    
    // Use NONCE-based key derivation for session key
    // The session key was generated in constructor - just enable encryption
    std::string username = user->getUsername();
    
    // Generate a random nonce and send to bridge for key derivation
    std::vector<unsigned char> nonce(16);
    if (!RAND_bytes(nonce.data(), 16)) {
        std::cerr << "[CRYPTO] ERROR: Failed to generate nonce" << std::endl;
        return;
    }
    
    // Send nonce to bridge
    std::string nonceB64 = EncryptionEnhanced::base64Encode(nonce);
    connection->sendRaw("NONCE:" + nonceB64 + "\n");
    std::cout << "[CRYPTO] Sent NONCE to bridge for key derivation" << std::endl;
    
    // Derive session key from username + nonce (must match bridge's derivation)
    std::string keyMaterial = username + std::string(nonce.begin(), nonce.end());
    std::string salt = "SECURECHAT_SESSION_SALT";
    
    // Use PBKDF2 to derive the session key (100000 iterations, 32 bytes output)
    std::vector<unsigned char> derivedKey(32);
    if (PKCS5_PBKDF2_HMAC(keyMaterial.c_str(), keyMaterial.length(),
                          reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                          100000, EVP_sha256(), 32, derivedKey.data()) != 1) {
        std::cerr << "[CRYPTO] ERROR: Failed to derive session key" << std::endl;
        return;
    }
    
    // Set the derived key
    connection->setSessionKeyFromString(std::string(derivedKey.begin(), derivedKey.end()));
    
    // Enable encryption
    connection->enableEncryption(true);
    std::string sessionId = connection->getSessionKeyHex(8);
    std::cout << "[CRYPTO] ✓ Encryption enabled, session: " << sessionId << std::endl;
    
    server->registerClient(user->getUsername(), self);
    
    server->broadcastMessage(
        Message("SYSTEM", "", 
                user->getUsername() + " has joined the chat", 
                MessageType::SYSTEM),
        ""
    );
    
    handleCommands();
}

void ClientHandler::handleCommands() {
    while (running) {
        std::string command;
        try {
            command = connection->receiveData();
        } catch (const DecryptionError& e) {
            std::cerr << "[COMMAND] Decryption error receiving command: " << e.what() << std::endl;
            std::cerr << "[COMMAND] Terminating connection due to message authentication failure" << std::endl;
            running = false;
            break;
        }
        
        if (command.empty()) {
            break;
        }
        
        processCommand(command);
    }
    
    stop();
}

void ClientHandler::processCommand(const std::string& command) {
    if (command.empty()) {
        return;
    }
    
    if (command == "/quit") {
        connection->sendData("Goodbye!");
        running = false;
        return;
    }
    
    if (command.find("/msg ") == 0) {
        handlePrivateMessage(command);
    } else if (command.find("/broadcast ") == 0) {
        handleBroadcast(command);
    } else {
        connection->sendData("Unknown command. Use /msg, /broadcast, or /quit");
    }
}

void ClientHandler::handlePrivateMessage(const std::string& command) {
    std::istringstream iss(command.substr(5));
    std::string recipient;
    iss >> recipient;
    
    std::string messageText;
    std::getline(iss, messageText);
    
    if (!messageText.empty() && messageText[0] == ' ') {
        messageText = messageText.substr(1);
    }
    
    if (recipient.empty() || messageText.empty()) {
        connection->sendData("Usage: /msg <username> <message>");
        return;
    }
    
    Message msg(user->getUsername(), recipient, messageText, MessageType::PRIVATE);
    
    bool sent = server->sendPrivateMessage(msg);
    
    if (sent) {
        connection->sendData("Message sent to " + recipient);
        server->logMessage(msg);
    } else {
        connection->sendData("Failed to send message. User '" + recipient + "' not found or offline.");
    }
}

void ClientHandler::handleBroadcast(const std::string& command) {
    std::string messageText = command.substr(11);
    
    if (messageText.empty()) {
        connection->sendData("Usage: /broadcast <message>");
        return;
    }
    
    Message msg(user->getUsername(), "", messageText, MessageType::BROADCAST);
    
    server->broadcastMessage(msg, user->getUsername());
    server->logMessage(msg);
    
    connection->sendData("Broadcast sent");
}

void ClientHandler::stop() {
    if (!running.exchange(false)) {
        return;
    }
    
    connection->closeConnection();
    
    if (user && user->isAuthenticated() && server->isRunning()) {
        server->broadcastMessage(
            Message("SYSTEM", "", 
                    user->getUsername() + " has left the chat", 
                    MessageType::SYSTEM),
            ""
        );
        server->logEvent("User '" + user->getUsername() + "' disconnected");
    }
}

bool ClientHandler::sendMessage(const std::string& message) {
    return connection->sendData(message);
}

std::string ClientHandler::getUsername() const {
    if (user) {
        return user->getUsername();
    }
    return "";
}

bool ClientHandler::isAuthenticated() const {
    return user && user->isAuthenticated();
}
