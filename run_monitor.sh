#!/bin/bash
# Clean startup script for Network Monitor
# Suppresses ALL warnings

# Clear the screen for clean output
clear

echo "Starting Network Intrusion Detection System..."
echo "Press Ctrl+C to stop"
echo ""

# Run the monitor with ALL stderr suppressed (no TensorFlow warnings)
# and environment variables set
cd "$(dirname "$0")"
if [ $# -eq 0 ]; then
    TF_CPP_MIN_LOG_LEVEL=3 TF_ENABLE_ONEDNN_OPTS=0 PYTHONWARNINGS=ignore \
    ./venv/bin/python3 network_monitor.py --flow-timeout 10 2>/dev/null
else
    TF_CPP_MIN_LOG_LEVEL=3 TF_ENABLE_ONEDNN_OPTS=0 PYTHONWARNINGS=ignore \
    ./venv/bin/python3 network_monitor.py "$@" 2>/dev/null
fi
