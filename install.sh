#!/bin/bash
# Exit on error
set -e
echo "Starting installation..."

# Function to check if a command was successful
check_status() {
    if [ $? -eq 0 ]; then
        echo "✓ Success: $1"
    else
        echo "✗ Error: $1 failed"
        exit 1
    fi
}

# Update system
echo "Updating system packages..."
sudo apt update && sudo apt upgrade -y
check_status "System update"

# Install required system dependencies
echo "Installing system dependencies..."
sudo apt-get install -y \
    build-essential \
    libcurl4-openssl-dev \
    libjson-c-dev \
    libgmp-dev \
    libssl-dev \
    libgcrypt20-dev \
    gcc \
    g++ \
    git
check_status "System dependencies installation"

# Compile the programs
echo "Compiling Electrum..."
gcc Electrum.c -o Electrum -lcurl -ljson-c -lgmp -lgcrypt -lssl
check_status "Electrum compilation"

echo "Compiling Run..."
g++ run.cpp -o Run -std=c++11
check_status "Run compilation"

# Cleanup old builds (optional)
echo "Cleaning up old builds..."
find . -type f -name '*.o' -delete
check_status "Cleanup completed"

# Set executables as executable
chmod +x Electrum
chmod +x Run
check_status "Executable permissions updated"

# Inform the user
echo "Installation and build completed successfully!"
echo "You can run the programs with:"
echo "./Electrum"
echo "./Run"

# Offer to run the program immediately
read -p "Would you like to Run now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ./Run
fi
