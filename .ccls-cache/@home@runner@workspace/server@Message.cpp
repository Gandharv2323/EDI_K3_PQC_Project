#include "Message.h"
#include <sstream>
#include <iomanip>

Message::Message() 
    : sender(""), recipient(""), content(""), 
      type(MessageType::SYSTEM), timestamp(std::time(nullptr)) {}

Message::Message(const std::string& from, const std::string& to, 
                 const std::string& msg, MessageType msgType)
    : sender(from), recipient(to), content(msg), 
      type(msgType), timestamp(std::time(nullptr)) {}

std::string Message::getSender() const {
    return sender;
}

std::string Message::getRecipient() const {
    return recipient;
}

std::string Message::getContent() const {
    return content;
}

MessageType Message::getType() const {
    return type;
}

time_t Message::getTimestamp() const {
    return timestamp;
}

std::string Message::getFormattedTimestamp() const {
    std::tm* timeinfo = std::localtime(&timestamp);
    std::ostringstream oss;
    oss << std::put_time(timeinfo, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string Message::toString() const {
    std::ostringstream oss;
    oss << "[" << getFormattedTimestamp() << "] ";
    
    if (type == MessageType::PRIVATE) {
        oss << sender << " -> " << recipient << ": " << content;
    } else if (type == MessageType::BROADCAST) {
        oss << sender << " (broadcast): " << content;
    } else {
        oss << "SYSTEM: " << content;
    }
    
    return oss.str();
}
