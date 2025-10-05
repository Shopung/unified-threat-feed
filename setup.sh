#!/bin/bash
# Unified Threat Feed - Setup Script

echo "🚀 Setting up Unified Threat Feed environment..."
set -e  # Exit immediately on error

# --- Check dependencies ---
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install it before continuing."
    exit 1
fi

if ! command -v git &> /dev/null; then
    echo "❌ Git not found. Please install it before continuing."
    exit 1
fi

# --- Install Python dependencies ---
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# --- Initialize Git repo if needed ---
if [ ! -d ".git" ]; then
    echo "🧱 Initializing new Git repository..."
    git init
    git add .
    git commit -m "Initial commit - Unified Threat Feed Phase 1"
else
    echo "ℹ️  Git repository already exists."
fi

# --- Ensure main branch is active ---
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "🔀 Setting branch name to 'main'..."
    git branch -M main
else
    echo "✅ Branch already named 'main'."
fi

# --- Check for remote and push if available ---
if git remote | grep -q origin; then
    echo "📤 Pushing to remote 'origin'..."
    git push -u origin main || echo "⚠️  Push failed — check your remote or authentication."
else
    echo "ℹ️  No remote 'origin' found. You can add one with:"
    echo "    git remote add origin <your_repo_url>"
    echo "    git push -u origin main"
fi

echo "✅ Setup complete! Unified Threat Feed initialized successfully."
