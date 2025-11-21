#include "Server.h"
#include <iostream>
#include <csignal>

Server* globalServer = nullptr;

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutting down server..." << std::endl;
        if (globalServer) {
            globalServer->stop();
        }
        exit(0);
    }
} 

int main(int argc, char* argv[]) {
    int port = 8080;
    
    if (argc > 1) {
        port = std::atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            std::cerr << "Invalid port number. Using default port 8080" << std::endl;
            port = 8080;
        }
    }
    
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    std::cout << "=== Multithreaded Chat Server ===" << std::endl;
    std::cout << "Starting server on port " << port << "..." << std::endl;
    
    Server server(port);
    globalServer = &server;
    
    if (!server.start()) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }
    
    return 0;
}
