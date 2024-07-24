# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name
project(ImageLockdown)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find all .cpp files in the current directory
file(GLOB SOURCES "*.cpp")

# Include OpenSSL
find_package(OpenSSL REQUIRED)

# Add the executable
add_executable(ImageLockdown ${SOURCES})

# Link the OpenSSL libraries
target_link_libraries(ImageLockdown OpenSSL::SSL OpenSSL::Crypto)
