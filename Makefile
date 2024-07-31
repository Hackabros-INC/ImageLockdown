# Name of the executable
TARGET = build/ImageLockdown

# Build directory
BUILD_DIR = build

# Libraries
LIBS = -lssl -lcrypto

# C++ compiler and options
CXX = g++
CXXFLAGS = -Wall -g

# Find all .cpp files in the current directory
SRC = $(wildcard *.cpp)

# Main rule to build the executable
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(SRC)
	@mkdir -p $(BUILD_DIR) # Create the build directory if it does not exist
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LIBS)

# Rule to clean generated files
clean:
	rm -f $(TARGET)

# Default rule when 'make' is called
.PHONY: all clean
