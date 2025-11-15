#!/bin/bash
# Clean startup script for Network Monitor
# Suppresses TensorFlow warnings

# Set environment variables to suppress warnings
export TF_CPP_MIN_LOG_LEVEL=3        # TensorFlow: 0=all, 1=info, 2=warning, 3=error only
export TF_ENABLE_ONEDNN_OPTS=0       # Disable oneDNN messages
export PYTHONWARNINGS="ignore"       # Suppress Python warnings

# Clear the screen for clean output
clear

echo "Starting Network Intrusion Detection System..."
echo "Press Ctrl+C to stop"
echo ""

# Run the monitor with 10-second flow timeout for faster testing
# (unless user provides their own arguments)
cd "$(dirname "$0")"
if [ $# -eq 0 ]; then
    ./venv/bin/python3 network_monitor.py --flow-timeout 10
else
    ./venv/bin/python3 network_monitor.py "$@"
fi
