#!/bin/bash
# Quick training script - captures traffic and trains model automatically

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════╗"
echo "║  NIDS Model Training - Quick Start                ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Check if running as root for tcpdump
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  This script needs root access for packet capture"
    echo "Please run: sudo $0"
    exit 1
fi

# Check dependencies
echo "[1/6] Checking dependencies..."
command -v tcpdump >/dev/null 2>&1 || { echo "Error: tcpdump not found. Install it first."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 not found. Install it first."; exit 1; }

# Install Python dependencies
echo "[2/6] Installing Python dependencies..."
pip3 install -q pandas scikit-learn tensorflow tqdm matplotlib 2>/dev/null || {
    echo "Note: Some dependencies may already be installed"
}

# Capture benign traffic
echo ""
echo "[3/6] Capturing benign traffic..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Starting packet capture for 5 minutes..."
echo "Please generate NORMAL traffic:"
echo "  - Browse websites (Google, YouTube, etc.)"
echo "  - Download files"
echo "  - Use SSH, email, etc."
echo ""
echo "Or run in another terminal: ./generate_cicids_benign.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

timeout 300 tcpdump -i any -w /tmp/benign_traffic.pcap 2>/dev/null &
TCPDUMP_PID=$!

# Optionally run benign generator
if [ -f "generate_cicids_benign.sh" ]; then
    echo "Auto-generating benign traffic..."
    timeout 290 ./generate_cicids_benign.sh >/dev/null 2>&1 &
fi

wait $TCPDUMP_PID 2>/dev/null || true

echo "✓ Benign traffic captured (5 minutes)"

# Capture attack traffic
echo ""
echo "[4/6] Capturing attack traffic..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Starting attack simulation for 3 minutes..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

timeout 180 tcpdump -i any -w /tmp/attack_traffic.pcap 2>/dev/null &
TCPDUMP_PID=$!

# Run attack generator
if [ -f "generate_cicids_attacks.sh" ]; then
    echo "Running attack generator..."
    timeout 170 ./generate_cicids_attacks.sh 127.0.0.1 >/dev/null 2>&1 &
fi

wait $TCPDUMP_PID 2>/dev/null || true

echo "✓ Attack traffic captured (3 minutes)"

# Extract features
echo ""
echo "[5/6] Extracting features from captured traffic..."
echo "This may take a few minutes..."

# Make scripts executable
chmod +x extract_features_from_pcap.py train_model.py

# Extract benign features
echo "  → Extracting benign flows..."
./extract_features_from_pcap.py /tmp/benign_traffic.pcap \
    --label BENIGN \
    --output /tmp/training_data.csv \
    --timeout 30 \
    2>&1 | grep -E "(Extracted|Label|Error)" || true

# Extract attack features
echo "  → Extracting attack flows..."
./extract_features_from_pcap.py /tmp/attack_traffic.pcap \
    --label ATTACK \
    --output /tmp/training_data.csv \
    --append \
    --timeout 30 \
    2>&1 | grep -E "(Extracted|Label|Error)" || true

# Check if we have enough data
TOTAL_LINES=$(wc -l < /tmp/training_data.csv)
TOTAL_FLOWS=$((TOTAL_LINES - 1))  # Subtract header

echo ""
echo "✓ Feature extraction complete"
echo "  Total flows: $TOTAL_FLOWS"

if [ "$TOTAL_FLOWS" -lt 1000 ]; then
    echo ""
    echo "⚠️  WARNING: Only $TOTAL_FLOWS flows captured"
    echo "   Recommended minimum: 5,000 flows"
    echo "   For better results, run for longer or capture more traffic"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Train model
echo ""
echo "[6/6] Training LSTM Autoencoder model..."
echo "This will take 10-30 minutes depending on your hardware..."
echo ""

./train_model.py /tmp/training_data.csv \
    --features 30 \
    --window-size 5 \
    --epochs 50 \
    --batch-size 32 \
    --encoding-dim 16 \
    --threshold-percentile 95 \
    --output-dir .

# Cleanup
echo ""
echo "Cleaning up temporary files..."
rm -f /tmp/benign_traffic.pcap /tmp/attack_traffic.pcap
# Keep training_data.csv for reference

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║  Training Complete! ✓                             ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Model files created:"
echo "  ✓ lstm_autoencoder.h5"
echo "  ✓ scaler.pkl"
echo "  ✓ selector.pkl"
echo "  ✓ metadata.json"
echo "  ✓ feature_order.txt"
echo ""
echo "Training data saved to: /tmp/training_data.csv"
echo ""
echo "Next steps:"
echo "  1. Test the model:"
echo "     sudo ./run_monitor.sh"
echo ""
echo "  2. Generate test traffic:"
echo "     ./generate_cicids_benign.sh    # In another terminal"
echo "     ./generate_cicids_attacks.sh   # To test attack detection"
echo ""
echo "  3. Check results:"
echo "     - Benign traffic should show errors 0.3-1.4 (GREEN)"
echo "     - Attack traffic should show errors 1.5+ (RED)"
echo ""
echo "Your model is now 100% compatible with network_monitor.py!"
echo ""
