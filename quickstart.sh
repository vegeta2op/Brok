#!/bin/bash

# Brok Quickstart Script
# This script helps you get started with Brok quickly

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║     ░░░░░██╗██╗███╗░░░███╗░█████╗░██████╗░░█████╗░░██╗░░░██╗║"
echo "║     ░░░░░██║██║████╗░████║██╔══██╗██╔══██╗██╔══██╗░██║░░░██║║"
echo "║     ░░░░░██║██║██╔████╔██║██║░░╚═╝██████╔╝██║░░██║░╚██╗░██╔╝║"
echo "║     ██╗░░██║██║██║╚██╔╝██║██║░░██╗██╔══██╗██║░░██║░░╚████╔╝░║"
echo "║     ╚█████╔╝██║██║░╚═╝░██║╚█████╔╝██║░░██║╚█████╔╝░░░╚██╔╝░░║"
echo "║     ░╚════╝░╚═╝╚═╝░░░░░╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░░░░░╚═╝░░░║"
echo "║                                                              ║"
echo "║          Autonomous Penetration Testing Agent                ║"
echo "║                  Quickstart Installer                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check Python version
echo "🔍 Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    echo "✓ Python $PYTHON_VERSION found"
    
    if [ "$PYTHON_VERSION" \< "3.11" ]; then
        echo "❌ Python 3.11 or higher is required"
        echo "   Current version: $PYTHON_VERSION"
        exit 1
    fi
else
    echo "❌ Python 3 is not installed"
    exit 1
fi

# Check Node.js version
echo "🔍 Checking Node.js version..."
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
    echo "✓ Node.js v$NODE_VERSION found"
    
    if [ "$NODE_VERSION" -lt 18 ]; then
        echo "⚠️  Node.js 18 or higher is recommended"
        echo "   Current version: v$NODE_VERSION"
    fi
else
    echo "⚠️  Node.js is not installed (required for web dashboard)"
fi

# Install Python dependencies
echo ""
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Install Playwright
echo ""
echo "🎭 Installing Playwright browsers..."
playwright install chromium

# Setup environment
echo ""
echo "⚙️  Setting up environment..."

if [ ! -f .env ]; then
    cp .env.example .env
    echo "✓ Created .env file"
    echo ""
    echo "⚠️  IMPORTANT: Edit .env with your API keys before running:"
    echo "   - Add at least one LLM provider API key (OpenAI, OpenRouter, or Gemini)"
    echo "   - Add Supabase credentials"
    echo ""
    echo "   Edit with: nano .env  (or your preferred editor)"
    echo ""
    read -p "Press Enter after you've configured .env..."
else
    echo "✓ .env file already exists"
fi

# Create config directory
mkdir -p config

if [ ! -f config/authorized_targets.yaml ]; then
    cp config/authorized_targets.yaml.example config/authorized_targets.yaml
    echo "✓ Created authorized targets config"
fi

# Install dashboard dependencies
if command -v npm &> /dev/null; then
    echo ""
    echo "📦 Installing dashboard dependencies..."
    cd dashboard
    npm install
    cd ..
    echo "✓ Dashboard dependencies installed"
fi

# Initialize database
echo ""
echo "🗄️  Initializing database..."
echo "   Note: This requires valid Supabase credentials in .env"
python3 -m backend.scripts.init_db || echo "⚠️  Database initialization failed. Please check your Supabase credentials."

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║              ✅ Installation Complete!                       ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🚀 Quick Start Commands:"
echo ""
echo "   # Launch Interactive TUI"
echo "   python3 -m cli.main tui"
echo ""
echo "   # Or start individual components:"
echo "   python3 -m backend.api.main          # Backend API"
echo "   cd dashboard && npm run dev          # Web Dashboard"
echo ""
echo "📚 Next Steps:"
echo "   1. Add authorized targets:"
echo "      python3 -m cli.main auth add example.com"
echo ""
echo "   2. Initialize knowledge base:"
echo "      python3 -m cli.main kb init"
echo ""
echo "   3. Start a scan:"
echo "      python3 -m cli.main scan https://example.com"
echo ""
echo "   4. Read the documentation:"
echo "      - INSTALL.md - Installation details"
echo "      - USER_GUIDE.md - Usage instructions"
echo "      - SECURITY.md - Safety and legal guidelines"
echo ""
echo "⚠️  LEGAL WARNING:"
echo "   Only scan applications you own or have explicit permission to test."
echo "   Unauthorized pentesting is illegal!"
echo ""
echo "Happy hacking! 🔒"

