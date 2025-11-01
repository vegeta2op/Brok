#!/bin/bash

# JimCrow Setup Script
# This script sets up the development environment for JimCrow

set -e  # Exit on error

echo "======================================"
echo "JimCrow - Pentesting Agent Setup"
echo "======================================"
echo

# Check Python version
echo "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "Found Python $PYTHON_VERSION"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo
    echo "Virtual environment already exists"
fi

# Activate virtual environment
echo
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo
echo "Upgrading pip..."
pip install --upgrade pip --quiet

# Install dependencies
echo
echo "Installing dependencies..."
echo "Note: This may take a few minutes..."

# Try installing all requirements first
if pip install -r requirements.txt --quiet 2>/dev/null; then
    echo "✓ All dependencies installed successfully"
else
    echo "⚠ Warning: Some dependencies could not be installed"
    echo "Installing core dependencies for CLI..."
    pip install typer rich pydantic pydantic-settings pyyaml --quiet
    echo "✓ Core CLI dependencies installed"
    echo
    echo "Note: Some backend dependencies may need manual installation"
    echo "See requirements.txt for the full list"
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "✓ .env file created"
    echo
    echo "⚠ IMPORTANT: Edit .env and add your API keys before running scans"
fi

# Create config directory if needed
mkdir -p config

echo
echo "======================================"
echo "Setup Complete!"
echo "======================================"
echo
echo "To get started:"
echo "  1. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo
echo "  2. Edit .env file with your API keys:"
echo "     nano .env"
echo
echo "  3. Add an authorized target:"
echo "     python -m cli.main auth add yourdomain.com"
echo
echo "  4. Run a scan:"
echo "     python -m cli.main scan https://yourdomain.com"
echo
echo "For help:"
echo "     python -m cli.main --help"
echo
