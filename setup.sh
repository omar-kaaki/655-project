#!/bin/bash
# Installation script for Network Intrusion Detection System

set -e  # Exit on error

echo "=================================================="
echo "Network Intrusion Detection System - Setup"
echo "=================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo ""
echo "[1/6] Updating package lists..."
apt-get update

echo ""
echo "[2/6] Installing system dependencies..."
apt-get install -y python3 python3-pip python3-venv libpcap-dev tcpdump

echo ""
echo "[3/6] Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
else
    echo "Virtual environment already exists."
fi

echo ""
echo "[4/6] Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "[5/6] Making network_monitor.py executable..."
chmod +x network_monitor.py

echo ""
echo "[6/6] Setup complete!"
echo ""
echo "=================================================="
echo "Installation Summary"
echo "=================================================="
echo "Working directory: $SCRIPT_DIR"
echo "Virtual environment: $SCRIPT_DIR/venv"
echo "Main script: $SCRIPT_DIR/network_monitor.py"
echo ""
echo "To run the monitor manually:"
echo "  sudo $SCRIPT_DIR/venv/bin/python3 $SCRIPT_DIR/network_monitor.py"
echo ""
echo "To install as a system service:"
echo "  sudo bash install_service.sh"
echo ""
echo "To test the installation:"
echo "  sudo $SCRIPT_DIR/venv/bin/python3 $SCRIPT_DIR/network_monitor.py --help"
echo "=================================================="
