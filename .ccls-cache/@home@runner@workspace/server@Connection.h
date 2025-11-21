#ifndef CONNECTION_H
#define CONNECTION_H

#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

class Connection {
protected:
    int socketFd;
    struct sockaddr_in address;
    
public:
    Connection();
    virtual ~Connection();
    
    int getSocketFd() const;
    void setSocketFd(int fd);
    
    bool sendData(const std::string& data);
    std::string receiveData();
    
    void closeConnection();
};

#endif
