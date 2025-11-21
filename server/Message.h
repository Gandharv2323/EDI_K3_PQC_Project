#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include <ctime>

enum class MessageType {
    PRIVATE,
    BROADCAST,
    SYSTEM
};

class Message {
private:
    std::string sender;
    std::string recipient;
    std::string content;
    MessageType type;
    time_t timestamp;

public:
    Message();
    Message(const std::string& from, const std::string& to, 
            const std::string& msg, MessageType msgType);
    
    std::string getSender() const;
    std::string getRecipient() const;
    std::string getContent() const;
    MessageType getType() const;
    time_t getTimestamp() const;
    
    std::string getFormattedTimestamp() const;
    std::string toString() const;
};

#endif
