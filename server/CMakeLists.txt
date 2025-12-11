cmake_minimum_required(VERSION 3.10)
project(ChatServer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================
# Find Required Packages
# ============================================

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# ============================================
# liboqs (Post-Quantum Cryptography)
# ============================================

# Try to find liboqs via pkg-config first
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBOQS liboqs)
endif()

# If not found via pkg-config, try manual detection
if(NOT LIBOQS_FOUND)
    find_path(LIBOQS_INCLUDE_DIR
        NAMES oqs/oqs.h
        PATHS
            /usr/local/include
            /usr/include
            /opt/liboqs/include
            $ENV{LIBOQS_ROOT}/include
            ${CMAKE_SOURCE_DIR}/../liboqs/build/include
    )
    
    find_library(LIBOQS_LIBRARY
        NAMES oqs liboqs
        PATHS
            /usr/local/lib
            /usr/lib
            /usr/lib/x86_64-linux-gnu
            /opt/liboqs/lib
            $ENV{LIBOQS_ROOT}/lib
            ${CMAKE_SOURCE_DIR}/../liboqs/build/lib
    )
    
    if(LIBOQS_INCLUDE_DIR AND LIBOQS_LIBRARY)
        set(LIBOQS_FOUND TRUE)
        set(LIBOQS_INCLUDE_DIRS ${LIBOQS_INCLUDE_DIR})
        set(LIBOQS_LIBRARIES ${LIBOQS_LIBRARY})
        message(STATUS "Found liboqs: ${LIBOQS_LIBRARY}")
    else()
        message(WARNING "liboqs not found. PQC features will be disabled.")
        message(STATUS "To enable PQC, install liboqs:")
        message(STATUS "  - Linux: apt install liboqs-dev OR build from source")
        message(STATUS "  - macOS: brew install liboqs")
        message(STATUS "  - Windows: vcpkg install liboqs OR build from source")
        message(STATUS "  - Set LIBOQS_ROOT environment variable if installed elsewhere")
    endif()
endif()

# ============================================
# PQC Sources (only if liboqs is available)
# ============================================

if(LIBOQS_FOUND)
    set(PQC_SOURCES
        pq_kem.cpp
        pq_sign.cpp
    )
    set(PQC_HEADERS
        pq_kem.h
        pq_sign.h
    )
    add_definitions(-DPQC_ENABLED=1)
    message(STATUS "Post-Quantum Cryptography (PQC) ENABLED")
else()
    set(PQC_SOURCES "")
    set(PQC_HEADERS "")
    add_definitions(-DPQC_ENABLED=0)
    message(STATUS "Post-Quantum Cryptography (PQC) DISABLED")
endif()

# ============================================
# Main Chat Server Executable
# ============================================

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
    ${PQC_SOURCES}
)

# Link libraries
if(WIN32)
    target_link_libraries(chat_server PRIVATE 
        Threads::Threads 
        ws2_32 
        OpenSSL::SSL 
        OpenSSL::Crypto
    )
else()
    target_link_libraries(chat_server PRIVATE 
        Threads::Threads 
        OpenSSL::SSL 
        OpenSSL::Crypto
    )
endif()

# Add liboqs if available
if(LIBOQS_FOUND)
    target_include_directories(chat_server PRIVATE ${LIBOQS_INCLUDE_DIRS})
    target_link_libraries(chat_server PRIVATE ${LIBOQS_LIBRARIES})
endif()

target_compile_options(chat_server PRIVATE -Wall -Wextra)

# ============================================
# Classic Encryption Test (without PQC)
# ============================================

add_executable(test_encryption
    test_encryption.cpp
    encryption_enhanced.cpp
)

# Compile test_encryption WITHOUT PQC to avoid link errors
target_compile_definitions(test_encryption PRIVATE PQC_ENABLED=0)

if(WIN32)
    target_link_libraries(test_encryption PRIVATE OpenSSL::SSL OpenSSL::Crypto)
else()
    target_link_libraries(test_encryption PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

# ============================================
# PQC Test (only if liboqs is available)
# ============================================

if(LIBOQS_FOUND)
    add_executable(test_pqc
        test_pqc.cpp
        encryption_enhanced.cpp
        pq_kem.cpp
        pq_sign.cpp
    )
    
    target_include_directories(test_pqc PRIVATE ${LIBOQS_INCLUDE_DIRS})
    
    if(WIN32)
        target_link_libraries(test_pqc PRIVATE 
            OpenSSL::SSL 
            OpenSSL::Crypto
            ${LIBOQS_LIBRARIES}
        )
    else()
        target_link_libraries(test_pqc PRIVATE 
            OpenSSL::SSL 
            OpenSSL::Crypto
            ${LIBOQS_LIBRARIES}
        )
    endif()
    
    target_compile_options(test_pqc PRIVATE -Wall -Wextra)
    
    message(STATUS "PQC Test target: test_pqc")
endif()

# ============================================
# Encryption Enhanced PQC Library (for external use)
# ============================================

if(LIBOQS_FOUND)
    add_library(encryption_enhanced_pqc STATIC
        encryption_enhanced.cpp
        pq_kem.cpp
        pq_sign.cpp
    )
    
    target_include_directories(encryption_enhanced_pqc 
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
        PUBLIC ${LIBOQS_INCLUDE_DIRS}
    )
    
    target_link_libraries(encryption_enhanced_pqc
        PUBLIC OpenSSL::SSL OpenSSL::Crypto
        PUBLIC ${LIBOQS_LIBRARIES}
    )
    
    message(STATUS "Static library: encryption_enhanced_pqc")
endif()

# ============================================
# Installation (optional)
# ============================================

install(TARGETS chat_server DESTINATION bin)
install(TARGETS test_encryption DESTINATION bin)

if(LIBOQS_FOUND)
    install(TARGETS test_pqc DESTINATION bin)
    install(TARGETS encryption_enhanced_pqc DESTINATION lib)
    install(FILES 
        encryption_enhanced.h
        pq_kem.h
        pq_sign.h
        DESTINATION include/securechat
    )
endif()

# ============================================
# Build Summary
# ============================================

message(STATUS "")
message(STATUS "=== Build Configuration ===")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")
if(LIBOQS_FOUND)
    message(STATUS "liboqs: FOUND at ${LIBOQS_LIBRARIES}")
    message(STATUS "PQC Algorithms: Kyber-768, Dilithium-III")
else()
    message(STATUS "liboqs: NOT FOUND (PQC disabled)")
endif()
message(STATUS "===========================")
message(STATUS "")

