#!/bin/bash
# Clean startup script for Network Monitor
# Suppresses TensorFlow warnings

# Set environment variables to suppress TensorFlow messages
export TF_CPP_MIN_LOG_LEVEL=3  # 0=all, 1=info, 2=warning, 3=error only
export TF_ENABLE_ONEDNN_OPTS=0  # Disable oneDNN messages

# Clear the screen for clean output
clear

echo "Starting Network Intrusion Detection System..."
echo "Press Ctrl+C to stop"
echo ""

# Run the monitor
cd "$(dirname "$0")"
./venv/bin/python3 network_monitor.py "$@"
