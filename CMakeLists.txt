# Minimum required version of CMake
cmake_minimum_required(VERSION 3.10)

# Name of the project and the language
project(MainProject CXX)

# Variable for the compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g")

# Find all .cpp files in the current directory
file(GLOB SOURCES "*.cpp")

# Specify the executable to be generated
add_executable(main ${SOURCES})

# Link the necessary libraries
target_link_libraries(main ssl crypto)

# Custom rule to clean the generated files
add_custom_target(clean_build
    COMMAND ${CMAKE_COMMAND} -E remove main
    COMMENT "Cleaning generated files..."
)
