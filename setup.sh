#!/bin/bash

echo "[+] Installing dependencies..."
sudo apt update
sudo apt install -y nmap masscan nikto dnsutils

# Check if testssl.sh is installed
if ! command -v testssl.sh &> /dev/null; then
    echo "[+] Installing testssl.sh..."
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
else
    echo "[✔] testssl.sh is already installed."
fi

# Install Python dependencies
pip install -r requirements.txt

echo "[+] Setup complete!"

