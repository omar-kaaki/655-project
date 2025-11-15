#!/bin/bash
# Install Network Monitor as a systemd service

set -e  # Exit on error

echo "=================================================="
echo "Installing Network Monitor as System Service"
echo "=================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Error: Virtual environment not found. Please run setup.sh first."
    exit 1
fi

echo ""
echo "[1/5] Updating service file paths..."
# Create a temporary service file with correct paths
cat > /tmp/network-monitor.service <<EOF
[Unit]
Description=Network Intrusion Detection System (LSTM Autoencoder)
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/venv/bin/python3 $SCRIPT_DIR/network_monitor.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/network-monitor.log
StandardError=append:/var/log/network-monitor-error.log

# Security settings
PrivateTmp=false
NoNewPrivileges=false
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

echo ""
echo "[2/5] Copying service file to systemd directory..."
cp /tmp/network-monitor.service /etc/systemd/system/network-monitor.service
rm /tmp/network-monitor.service

echo ""
echo "[3/5] Creating log files..."
touch /var/log/network-monitor.log
touch /var/log/network-monitor-error.log
chmod 644 /var/log/network-monitor.log
chmod 644 /var/log/network-monitor-error.log

echo ""
echo "[4/5] Reloading systemd daemon..."
systemctl daemon-reload

echo ""
echo "[5/5] Enabling service to start on boot..."
systemctl enable network-monitor.service

echo ""
echo "=================================================="
echo "Service Installation Complete!"
echo "=================================================="
echo ""
echo "Service Commands:"
echo "  Start:    sudo systemctl start network-monitor"
echo "  Stop:     sudo systemctl stop network-monitor"
echo "  Restart:  sudo systemctl restart network-monitor"
echo "  Status:   sudo systemctl status network-monitor"
echo "  Logs:     sudo journalctl -u network-monitor -f"
echo "            or"
echo "            sudo tail -f /var/log/network-monitor.log"
echo ""
echo "To start the service now:"
echo "  sudo systemctl start network-monitor"
echo ""
echo "=================================================="
