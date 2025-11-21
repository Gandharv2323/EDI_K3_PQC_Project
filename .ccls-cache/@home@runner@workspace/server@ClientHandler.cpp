#include "ClientHandler.h"
#include "Server.h"
#include "Message.h"
#include <sstream>
#include <iostream>

ClientHandler::ClientHandler(int clientSocket, Server* srv) 
    : connection(std::make_unique<Connection>()), 
      user(nullptr), 
      server(srv), 
      running(true) {
    connection->setSocketFd(clientSocket);
}

ClientHandler::~ClientHandler() {
    stop();
}

bool ClientHandler::authenticate() {
    connection->sendData("=== Chat Server Authentication ===");
    connection->sendData("Username: ");
    std::string username = connection->receiveData();
    
    if (username.empty()) {
        return false;
    }
    
    connection->sendData("Password: ");
    std::string password = connection->receiveData();
    
    if (password.empty()) {
        return false;
    }
    
    user = server->authenticateUser(username, password);
    
    if (user && user->isAuthenticated()) {
        connection->sendData("Authentication successful! Welcome " + username + "!");
        connection->sendData("Available commands:");
        connection->sendData("  /msg <username> <message> - Send private message");
        connection->sendData("  /broadcast <message> - Send message to all users");
        connection->sendData("  /quit - Disconnect from server");
        server->logEvent("User '" + username + "' authenticated successfully");
        return true;
    } else {
        connection->sendData("Authentication failed. Disconnecting...");
        server->logEvent("Failed authentication attempt for user '" + username + "'");
        return false;
    }
}

void ClientHandler::run(std::shared_ptr<ClientHandler> self) {
    if (!authenticate()) {
        running = false;
        return;
    }
    
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
        std::string command = connection->receiveData();
        
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
