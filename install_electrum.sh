#!/bin/bash

# Exit on error
set -e

echo "Starting QuickNode program installation..."

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
    git
check_status "System dependencies installation"

# Clone the repository (if required)
WORK_DIR=~/quicknode_program
if [ ! -d "$WORK_DIR" ]; then
    echo "Creating program directory..."
    mkdir -p "$WORK_DIR"
    check_status "Directory creation"
fi

# Move to the working directory
cd "$WORK_DIR"

# Copy the program source code (assuming it's available in the same directory as this script)
echo "Copying source code to the program directory..."
cp "$(dirname "$0")/quicknode_rpc.c" "$WORK_DIR/"
check_status "Source code copied"

# Compile the program
echo "Compiling the program..."
gcc quicknode_rpc.c -o quicknode_rpc -lcurl -ljson-c -lgmp -lgcrypt -lssl
check_status "Program compilation"

# Cleanup old builds (optional)
echo "Cleaning up old builds..."
find . -type f -name '*.o' -delete
check_status "Cleanup completed"

# Inform the user
echo "Installation and build completed successfully!"
echo "You can run the program with: ./quicknode_rpc"

# Offer to run the program immediately
read -p "Would you like to run the program now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ./quicknode_rpc
fi
