cmake_minimum_required(VERSION 3.10)
project(ChatServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(chat_server
    main.cpp
    Server.cpp
    ClientHandler.cpp
    Connection.cpp
    Message.cpp
    User.cpp
    encryption.cpp
    encryption_enhanced.cpp
    password_hash.cpp
    Logger.cpp
)

# Link libraries
if(WIN32)
    target_link_libraries(chat_server PRIVATE Threads::Threads ws2_32 OpenSSL::SSL OpenSSL::Crypto)
else()
    target_link_libraries(chat_server PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
endif()

target_compile_options(chat_server PRIVATE -Wall -Wextra)

# Optional: Build encryption test
add_executable(test_encryption
    test_encryption.cpp
    encryption_enhanced.cpp
)

if(WIN32)
    target_link_libraries(test_encryption PRIVATE OpenSSL::SSL OpenSSL::Crypto)
else()
    target_link_libraries(test_encryption PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

