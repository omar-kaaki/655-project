# Complete Training Guide: Train Your Own NIDS Model

This guide shows you how to train a model from scratch using **YOUR exact feature extraction code**, guaranteeing 100% compatibility with `network_monitor.py`.

## Quick Overview

```
Step 1: Collect benign traffic → benign.pcap
Step 2: Collect attack traffic → attacks.pcap
Step 3: Extract features → training_data.csv
Step 4: Train model → lstm_autoencoder.h5 + scaler.pkl + selector.pkl
Step 5: Test with network_monitor.py → 100% compatible!
```

---

## Step 1: Collect Benign Traffic

You need **benign (normal) network traffic** for training.

### Option A: Capture Your Own Traffic (Recommended)

```bash
# Start packet capture (run for 10-30 minutes)
sudo tcpdump -i any -w benign_traffic.pcap

# While capturing, generate normal traffic:
# - Browse websites (Google, YouTube, Facebook, etc.)
# - Check email
# - Download files
# - Use SSH, FTP
# - Stream videos
# - Use messaging apps

# Stop with Ctrl+C after 10-30 minutes
```

### Option B: Use CIC-IDS2017 Benign Data

```bash
# Download Monday benign traffic from CIC-IDS2017
# https://www.unb.ca/cic/datasets/ids-2017.html

# Example for Monday benign:
wget https://...../Monday-WorkingHours.pcap_ISCX.csv
# Then you'd need to convert CSV back to PCAP or use CSV directly
```

### Option C: Generate Synthetic Traffic

```bash
# Use the benign traffic generator for 30 minutes
./generate_cicids_benign.sh &
GENERATOR_PID=$!

# Capture the traffic
sudo tcpdump -i any -w benign_traffic.pcap &
TCPDUMP_PID=$!

# Wait 30 minutes
sleep 1800

# Stop both
kill $GENERATOR_PID $TCPDUMP_PID
```

**Goal**: Get at least 10,000-50,000 benign network flows

---

## Step 2: Collect Attack Traffic

You need **attack traffic** for validation and testing.

### Option A: Run Attack Simulations (Recommended)

```bash
# Start capture
sudo tcpdump -i any -w attack_traffic.pcap &
TCPDUMP_PID=$!

# Run attack generator
./generate_cicids_attacks.sh 127.0.0.1

# Let it run for 10-15 minutes
sleep 900

# Stop capture
kill $TCPDUMP_PID
```

### Option B: Create Specific Attack Types

```bash
# Capture different attack types separately

# 1. Port Scan
sudo tcpdump -i any -w portscan.pcap &
nmap -sT -p 1-1000 127.0.0.1
killall tcpdump

# 2. DoS Attack
sudo tcpdump -i any -w dos.pcap &
hping3 -S --flood -p 80 127.0.0.1 &
sleep 60
killall hping3 tcpdump

# 3. SSH Brute Force
sudo tcpdump -i any -w ssh_bruteforce.pcap &
for i in {1..100}; do
    ssh -o ConnectTimeout=1 root@127.0.0.1 2>/dev/null
    sleep 0.1
done
killall tcpdump

# 4. Web Attack
sudo tcpdump -i any -w webattack.pcap &
for i in {1..50}; do
    curl "http://127.0.0.1/?id=1' OR '1'='1" 2>/dev/null
done
killall tcpdump
```

### Option C: Use CIC-IDS2017 Attack Data

```bash
# Download attack days from CIC-IDS2017
# Tuesday: Brute Force
# Wednesday: DoS
# Thursday: Web Attacks
# Friday: Port Scans, DDoS, Botnet
```

**Goal**: Get at least 5,000-20,000 attack flows

---

## Step 3: Extract Features from PCAP Files

Now extract features using **your exact code**:

```bash
# Make extraction script executable
chmod +x extract_features_from_pcap.py

# Extract benign features
./extract_features_from_pcap.py benign_traffic.pcap \
    --label BENIGN \
    --output training_data.csv \
    --timeout 120

# Extract attack features (append to same file)
./extract_features_from_pcap.py attack_traffic.pcap \
    --label ATTACK \
    --output training_data.csv \
    --append \
    --timeout 120

# If you have multiple attack PCAPs:
./extract_features_from_pcap.py portscan.pcap dos.pcap ssh_bruteforce.pcap \
    --label ATTACK \
    --output training_data.csv \
    --append \
    --timeout 120
```

**Check the data:**
```bash
# View CSV
head -20 training_data.csv

# Count flows
wc -l training_data.csv

# Check label distribution
tail -n +2 training_data.csv | cut -d',' -f79 | sort | uniq -c
```

**Expected output:**
```
15000 ATTACK
35000 BENIGN
```

**Minimum requirements:**
- At least **10,000 benign flows**
- At least **2,000 attack flows**
- At least **5,000 total flows**

More data = better model!

---

## Step 4: Train the Model

```bash
# Make training script executable
chmod +x train_model.py

# Install additional dependencies
pip install pandas scikit-learn tensorflow tqdm matplotlib

# Train the model
./train_model.py training_data.csv \
    --features 30 \
    --window-size 5 \
    --epochs 50 \
    --batch-size 32 \
    --encoding-dim 16 \
    --threshold-percentile 95 \
    --output-dir .
```

### Training Parameters Explained

- `--features 30`: Select top 30 features (from 78) using SelectKBest
- `--window-size 5`: Use 5 consecutive flows as input to LSTM
- `--epochs 50`: Train for up to 50 epochs (early stopping applies)
- `--batch-size 32`: Process 32 sequences at a time
- `--encoding-dim 16`: Bottleneck dimension (compression)
- `--threshold-percentile 95`: Set threshold at 95th percentile of benign errors
- `--output-dir .`: Save model files in current directory

### What Gets Created

After training, you'll have:

```
✓ lstm_autoencoder.h5   - Trained LSTM model
✓ scaler.pkl            - Feature scaler (trained on YOUR data)
✓ selector.pkl          - Feature selector (trained on YOUR data)
✓ metadata.json         - Model configuration
✓ feature_order.txt     - Selected feature names
```

These files **replace** the old model files and are 100% compatible with `network_monitor.py`!

### Expected Training Output

```
Loading data from training_data.csv...
Loaded 50000 samples
Features: 78
Label distribution:
BENIGN    35000
ATTACK    15000

Preparing data...
Selecting top 30 features...
Selected features: 30

Train set: 40000 samples
Test set: 10000 samples

Creating sequences with window size 5...
Created 39996 sequences
Benign sequences: 28000
Attack sequences: 11996

Building LSTM Autoencoder...

Training model...
Training on 28000 benign sequences
Epoch 1/50
875/875 [==============================] - 45s - loss: 2.3456 - val_loss: 1.2345
...
Epoch 25/50
875/875 [==============================] - 42s - loss: 0.8234 - val_loss: 0.7123

Calculating threshold...
Benign reconstruction errors:
  Min: 0.2134
  Max: 1.8234
  Mean: 0.6234
  Median: 0.5834
  95th percentile: 1.2345

Evaluating model...
Test Results:
  Accuracy: 0.9456
  Precision: 0.9234
  Recall: 0.9123
  F1-Score: 0.9178

Saving model...
  ✓ Saved lstm_autoencoder.h5
  ✓ Saved scaler.pkl
  ✓ Saved selector.pkl
  ✓ Saved metadata.json
  ✓ Saved feature_order.txt

Training complete!
Threshold: 1.234568
```

**Good metrics:**
- Accuracy > 90%
- Precision > 85%
- Recall > 80%
- F1-Score > 85%

If metrics are poor, try:
- Collecting more training data
- Increasing `--epochs`
- Adjusting `--features` (try 20 or 40)
- Ensuring good mix of benign/attack flows

---

## Step 5: Test Your New Model

Now test with live traffic:

```bash
# Start the monitor (uses your new model automatically)
sudo ./run_monitor.sh

# In another terminal, generate benign traffic
./generate_cicids_benign.sh
```

### Expected Results (With Your Trained Model)

```
[FLOW COMPLETE] TCP 192.168.1.100:54321 → 93.184.216.34:80 | Packets: 15 | Progress: 5/5 flows

✓ Benign traffic - 192.168.1.100:54321 → 93.184.216.34:80 | Error: 0.5234

[... more benign flows ...]

Stats - Packets: 1000 | Flows: 20 | Benign: 18 | Attacks: 2 | Uptime: 0:02:15
```

**Perfect! Errors are 0.3-1.2 for benign traffic** (not 9000!)

### Test with Attack Traffic

```bash
# In another terminal
./generate_cicids_attacks.sh 127.0.0.1
```

**Expected output:**
```
⚠️  ATTACK DETECTED!
Source:      192.168.1.200:12345
Destination: 127.0.0.1:22
Protocol:    TCP
Packets:     150
Duration:    2.34s
Error:       2.3456 (Threshold: 1.2346)
Confidence:  90.0% above threshold
```

**Perfect! Attack errors are 1.5-5.0** (above threshold of ~1.2)

---

## Advanced: Fine-Tuning

### Adjust Threshold

If you see too many false positives:
```bash
# Increase threshold
sudo ./run_monitor.sh --threshold 1.8
```

If you're missing attacks:
```bash
# Decrease threshold
sudo ./run_monitor.sh --threshold 1.0
```

### Retrain with More Data

```bash
# Capture more traffic
sudo tcpdump -i any -w more_benign.pcap
# ... (browse for 30 minutes) ...

# Extract and append
./extract_features_from_pcap.py more_benign.pcap \
    --label BENIGN \
    --output training_data.csv \
    --append

# Retrain
./train_model.py training_data.csv --epochs 50
```

### Try Different Architectures

```bash
# More features
./train_model.py training_data.csv --features 40

# Larger encoding
./train_model.py training_data.csv --encoding-dim 32

# Longer sequences
./train_model.py training_data.csv --window-size 10
```

---

## Troubleshooting

### "Not enough benign data"

**Problem**: Training fails with "Not enough benign sequences"

**Solution**: Capture more benign traffic
```bash
# Run capture for longer (60 minutes)
sudo tcpdump -i any -w benign_long.pcap
```

### "Model overfits"

**Problem**: Training loss decreases but validation loss increases

**Solution**:
- Collect more diverse training data
- Reduce model complexity (`--encoding-dim 8`)
- Add more regularization (edit train_model.py)

### "Low accuracy"

**Problem**: Test accuracy < 80%

**Solutions**:
1. Check label balance:
   ```bash
   tail -n +2 training_data.csv | cut -d',' -f79 | sort | uniq -c
   ```
   Should be roughly 70% BENIGN, 30% ATTACK

2. Collect more attack variety (different attack types)

3. Increase training epochs: `--epochs 100`

4. Try different feature counts: `--features 20` or `--features 40`

### "Training is slow"

**Problem**: Training takes hours

**Solutions**:
- Reduce data size (use first 10,000 flows)
- Reduce batch size: `--batch-size 16`
- Reduce epochs: `--epochs 30`
- Use GPU if available (TensorFlow auto-detects)

---

## Summary: Complete Workflow

```bash
# 1. Collect data
sudo tcpdump -i any -w benign.pcap  # (run 30 min with normal browsing)
./generate_cicids_attacks.sh 127.0.0.1 &
sudo tcpdump -i any -w attacks.pcap  # (run 15 min)

# 2. Extract features
chmod +x extract_features_from_pcap.py
./extract_features_from_pcap.py benign.pcap --label BENIGN -o data.csv
./extract_features_from_pcap.py attacks.pcap --label ATTACK -o data.csv --append

# 3. Train model
chmod +x train_model.py
pip install pandas scikit-learn tensorflow tqdm matplotlib
./train_model.py data.csv --epochs 50

# 4. Test live
sudo ./run_monitor.sh
./generate_cicids_benign.sh  # In another terminal

# 5. Verify
# You should see:
# - Benign errors: 0.3-1.4
# - Attack errors: 1.5-5.0
# - Accuracy > 90%
```

---

## Why This Works

**Before** (using pre-trained model):
```
CICFlowMeter (Java) → Features → Train Model
    ❌ Different tool
Your Python code → Features → Use Model ← MISMATCH! (errors 9000+)
```

**After** (your trained model):
```
Your Python code → Features → Train Model
    ✓ Same code
Your Python code → Features → Use Model ← PERFECT MATCH! (errors 0.3-1.4)
```

The `extract_features_from_pcap.py` script uses **the exact same `extract_features()` function** as `network_monitor.py`, guaranteeing 100% compatibility!

---

## Next Steps

1. **Collect diverse traffic**: More attack types = better detection
2. **Collect more data**: 100,000+ flows = more robust model
3. **Experiment**: Try different parameters to optimize for your use case
4. **Deploy**: Use as systemd service for continuous monitoring

Good luck with your training! 🚀
