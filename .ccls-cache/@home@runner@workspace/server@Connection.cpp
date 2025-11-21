#include "Connection.h"
#include <cstring>
#include <iostream>

Connection::Connection() : socketFd(-1) {
    std::memset(&address, 0, sizeof(address));
}

Connection::~Connection() {
    closeConnection();
}

int Connection::getSocketFd() const {
    return socketFd;
}

void Connection::setSocketFd(int fd) {
    socketFd = fd;
}

bool Connection::sendData(const std::string& data) {
    if (socketFd < 0) {
        return false;
    }
    
    std::string message = data + "\n";
    ssize_t sent = send(socketFd, message.c_str(), message.length(), 0);
    
    return sent > 0;
}

std::string Connection::receiveData() {
    if (socketFd < 0) {
        return "";
    }
    
    char buffer[4096];
    std::memset(buffer, 0, sizeof(buffer));
    
    ssize_t bytesReceived = recv(socketFd, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesReceived <= 0) {
        return "";
    }
    
    std::string data(buffer, bytesReceived);
    
    if (!data.empty() && data.back() == '\n') {
        data.pop_back();
    }
    if (!data.empty() && data.back() == '\r') {
        data.pop_back();
    }
    
    return data;
}

void Connection::closeConnection() {
    if (socketFd >= 0) {
        close(socketFd);
        socketFd = -1;
    }
}
