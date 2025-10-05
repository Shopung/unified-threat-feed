#!/bin/bash
# Unified Threat Feed - Setup Script

echo "[+] Setting up Unified Threat Feed environment..."

# Ensure Python and Git are available
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Please install it before continuing."
    exit 1
fi

if ! command -v git &> /dev/null; then
    echo "[!] Git not found. Please install it before continuing."
    exit 1
fi

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip install -r requirements.txt

# Initialize Git repository if not already
if [ ! -d ".git" ]; then
    echo "[+] Initializing Git repository..."
    git init
    git add .
    git commit -m "Initial commit - Unified Threat Feed Phase 1"
else
    echo "[i] Git repository already initialized."
fi

echo "[+] Setup complete! You can now push to your remote repository."
echo "   Example: git remote add origin <your_repo_url>"
echo "            git push -u origin main"
