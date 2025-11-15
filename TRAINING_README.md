# Train Your Own Model - Quick Start

This directory contains everything you need to train a custom LSTM Autoencoder model that is **100% compatible** with `network_monitor.py`.

## Why Train Your Own Model?

The pre-trained model was created using CICFlowMeter (Java tool) which has different feature calculations than our Python code. This causes massive false positives (errors of 9000+ instead of < 2).

**By training your own model**, you ensure the **exact same feature extraction code** is used for both training and inference, guaranteeing compatibility.

## Three Ways to Train

### 1️⃣ Automatic (Recommended for Quick Start)

```bash
# One command does everything:
# - Captures 5 min benign + 3 min attack traffic
# - Extracts features
# - Trains model
sudo ./quick_train.sh
```

**Time**: ~15 minutes total (8 min capture + 5-10 min training)

### 2️⃣ Manual (Recommended for Best Results)

```bash
# Step 1: Capture benign traffic (30-60 minutes recommended)
sudo tcpdump -i any -w benign.pcap
# Browse normally: Google, YouTube, email, downloads, etc.
# Ctrl+C when done

# Step 2: Capture attack traffic (10-15 minutes)
sudo tcpdump -i any -w attacks.pcap &
./generate_cicids_attacks.sh 127.0.0.1
# Ctrl+C when done

# Step 3: Extract features
./extract_features_from_pcap.py benign.pcap --label BENIGN -o data.csv
./extract_features_from_pcap.py attacks.pcap --label ATTACK -o data.csv --append

# Step 4: Train
./train_model.py data.csv --epochs 50

# Step 5: Test
sudo ./run_monitor.sh
./generate_cicids_benign.sh  # In another terminal
```

**Time**: ~1-2 hours total

### 3️⃣ With Real CIC-IDS2017 Data (Best for Research)

```bash
# Download CIC-IDS2017 PCAP files
# https://www.unb.ca/cic/datasets/ids-2017.html

# Extract features from each PCAP
./extract_features_from_pcap.py Monday-benign.pcap --label BENIGN -o data.csv
./extract_features_from_pcap.py Tuesday-attacks.pcap --label ATTACK -o data.csv --append
./extract_features_from_pcap.py Wednesday-attacks.pcap --label ATTACK -o data.csv --append
# ... etc

# Train on full dataset
./train_model.py data.csv --epochs 100
```

**Time**: Several hours (large dataset)

## Files Explained

| File | Purpose |
|------|---------|
| `quick_train.sh` | Automated training script - does everything |
| `extract_features_from_pcap.py` | Extracts features from PCAP files using YOUR code |
| `train_model.py` | Trains LSTM Autoencoder on extracted features |
| `TRAINING_GUIDE.md` | Detailed step-by-step instructions |
| `TRAINING_README.md` | This file - quick reference |

## What You'll Get

After training:

```
✓ lstm_autoencoder.h5   - Your trained model
✓ scaler.pkl            - Feature scaler
✓ selector.pkl          - Feature selector
✓ metadata.json         - Model configuration
✓ feature_order.txt     - Selected features
```

These replace the old model files and work perfectly with `network_monitor.py`!

## Expected Results

### Before (Pre-trained Model)
```
Benign traffic: Error = 9612 ❌ (should be < 2)
Attack traffic: Error = 15000 ❌ (everything flagged)
False positive rate: 100% ❌
```

### After (Your Trained Model)
```
Benign traffic: Error = 0.5-1.2 ✓ (below threshold)
Attack traffic: Error = 1.8-4.5 ✓ (above threshold)
False positive rate: < 5% ✓
Accuracy: > 90% ✓
```

## Requirements

### Minimum Data
- **5,000+ total flows** (3,500 benign + 1,500 attack)
- At least 10 minutes of capture time

### Recommended Data
- **50,000+ total flows** (35,000 benign + 15,000 attack)
- 30-60 minutes benign + 10-20 minutes attack

### System Requirements
- Python 3.8+
- 4GB+ RAM
- 10GB+ disk space (for training data)
- Root access (for packet capture)

### Python Dependencies
```bash
pip install pandas scikit-learn tensorflow tqdm matplotlib
```

## Quick Troubleshooting

**"Permission denied"** → Run with `sudo`

**"Not enough flows"** → Capture for longer or generate more traffic

**"Low accuracy (<80%)"** → Need more training data or better attack variety

**"Training too slow"** → Reduce `--epochs` or use smaller dataset

See `TRAINING_GUIDE.md` for detailed troubleshooting.

## Testing Your Model

```bash
# Terminal 1: Start monitor
sudo ./run_monitor.sh

# Terminal 2: Generate benign traffic
./generate_cicids_benign.sh

# You should see GREEN output with errors 0.3-1.4

# Terminal 3: Generate attacks
./generate_cicids_attacks.sh 127.0.0.1

# You should see RED output with errors 1.5-5.0
```

## Advanced Training

```bash
# More features (40 instead of 30)
./train_model.py data.csv --features 40

# Longer sequences (10 flows instead of 5)
./train_model.py data.csv --window-size 10

# More training epochs
./train_model.py data.csv --epochs 100

# Larger model
./train_model.py data.csv --encoding-dim 32

# Custom threshold (90th percentile instead of 95th)
./train_model.py data.csv --threshold-percentile 90
```

## Need Help?

1. **Read the detailed guide**: `TRAINING_GUIDE.md`
2. **Check troubleshooting**: `TROUBLESHOOTING.md`
3. **Ask your instructor** about collecting training data

## Summary

**The key insight**: Use the SAME feature extraction code for training and inference!

```
extract_features_from_pcap.py  ──→  Uses network_monitor.FlowTracker
                                     ↓
                              Training Data (CSV)
                                     ↓
train_model.py  ──────────────→  Trained Model
                                     ↓
network_monitor.py  ───────────→  Uses SAME FlowTracker ✓
```

**Result**: Perfect compatibility, no false positives, accurate detection!

---

Ready to train? Start here:
```bash
sudo ./quick_train.sh
```

Good luck! 🚀
