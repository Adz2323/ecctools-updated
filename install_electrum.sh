#!/bin/bash

# Exit on error
set -e

echo "Starting Electrum installation..."

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

# Install system dependencies
echo "Installing system dependencies..."
sudo apt-get install -y \
    root-repo \
    git \
    build-essential \
    libssl-dev \
    libgcrypt20-dev \
    libgmp-dev \
    libjson-c-dev \
    libcurl4-openssl-dev \
    python3-pip \
    automake \
    autoconf \
    libtool \
    libsecp256k1-dev \
    python3-setuptools \
    python3-pyqt6 \
    python3-cryptography \
    python3-requests \
    gettext \
    qttools5-dev-tools
check_status "System dependencies installation"

# Create a directory for Electrum
echo "Creating installation directory..."
mkdir -p ~/electrum
cd ~/electrum
check_status "Directory creation"

# Clone Electrum repository
echo "Cloning Electrum repository..."
git clone https://github.com/spesmilo/electrum.git .
check_status "Repository cloning"

# Initialize and update git submodules
echo "Initializing git submodules..."
git submodule update --init
check_status "Git submodules initialization"

# Install Python dependencies
echo "Installing Python dependencies..."
python3 -m pip install --user -e ".[gui,crypto]"
check_status "Python dependencies installation"

# Pull locale files for translations
echo "Pulling locale files..."
./contrib/pull_locale
check_status "Locale files"

# Add ~/.local/bin to PATH if it's not already there
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    echo "Added ~/.local/bin to PATH"
fi

echo "Installation completed!"
echo "You can now run Electrum by typing 'electrum' in the terminal"
echo "Or run it directly with: ~/electrum/run_electrum"

# Provide option to run Electrum immediately
read -p "Would you like to run Electrum now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    ./run_electrum
fi
