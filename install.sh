#!/bin/bash

# Basic Vulnerability Scanner Setup Script

# Install required packages
echo "[+] Installing system dependencies..."
sudo apt update && sudo apt install -y python3 python3-pip

# Install Python modules
echo "[+] Installing Python requirements..."
pip install aiohttp rich ollama

# Make scanner executable
echo "[+] Setting up scanner..."
chmod +x upgrade.py
sudo cp upgrade.py /usr/local/bin/vscan

# Create output directory
mkdir -p scan_results

echo "[+] Installation complete!"
echo "Run with: vscan [target]"
echo "Examples:"
echo "  vscan file.js              # Scan single file"
echo "  vscan /path/to/code        # Scan directory"
echo "  vscan http://example.com   # Scan URL"
