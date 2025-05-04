#!/bin/bash

echo "[+] Setting up XSStrike++ environment..."

# Detect platform
if [[ "$OSTYPE" == "linux-android"* ]]; then
    echo "[*] Detected Termux environment."
    pkg update -y && pkg install -y python git curl
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "[*] Detected Linux environment."
    sudo apt update -y && sudo apt install -y python3 python3-pip git curl
elif [[ "$OSTYPE" == "msys" ]]; then
    echo "[*] Detected Windows Git Bash environment."
    echo "[!] Please ensure Python 3 and pip are installed and available in PATH."
else
    echo "[!] Unsupported OS: $OSTYPE"
    exit 1
fi

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip3 install -r requirements.txt || pip install -r requirements.txt

# Clone and install Arjun
echo "[+] Cloning Arjun from GitHub..."
git clone https://github.com/s0md3v/Arjun.git tools/Arjun

echo "[+] Installing Arjun..."
cd tools/Arjun
chmod +x setup.sh
./setup.sh
cd ../..

echo "[+] Setup complete."
echo "[*] Usage: python3 arjun_xsstrike.py <url>"
