#!/bin/bash
# Quick setup script for Database Forensic Tool on Linux
# Usage: ./setup_linux.sh

set -e  # Exit on error

echo "=========================================="
echo "Database Forensic Tool - Linux Setup"
echo "=========================================="
echo ""

# Check Python version
echo "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed."
    echo "Please install Python 3.8 or higher:"
    echo "  Ubuntu/Debian: sudo apt-get install python3 python3-pip python3-venv"
    echo "  CentOS/RHEL:   sudo yum install python3 python3-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✓ Found Python $PYTHON_VERSION"

# Check pip
echo ""
echo "Checking pip installation..."
if ! command -v pip3 &> /dev/null; then
    echo "ERROR: pip3 is not installed."
    echo "Please install pip:"
    echo "  Ubuntu/Debian: sudo apt-get install python3-pip"
    echo "  CentOS/RHEL:   sudo yum install python3-pip"
    exit 1
fi
echo "✓ Found pip3"

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip --quiet
echo "✓ pip upgraded"

# Install dependencies
echo ""
echo "Installing dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --quiet
    echo "✓ Dependencies installed"
else
    echo "ERROR: requirements.txt not found"
    exit 1
fi

# Verify installation
echo ""
echo "Verifying installation..."
python3 -c "import pymysql; import pymongo; print('✓ All dependencies verified')" 2>/dev/null || {
    echo "WARNING: Some dependencies may not be properly installed"
}

echo ""
echo "=========================================="
echo "Setup completed successfully!"
echo "=========================================="
echo ""
echo "To use the tool:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run analysis: python3 -m db_forensic_tool <db_type> [options]"
echo ""
echo "Examples:"
echo "  python3 -m db_forensic_tool sqlite database.db --output report.json"
echo "  python3 -m db_forensic_tool mysql --host localhost --user root --database testdb"
echo "  python3 -m db_forensic_tool mongodb --host localhost --database testdb"
echo ""
echo "For detailed instructions, see LINUX_INSTALLATION.md"
echo ""

