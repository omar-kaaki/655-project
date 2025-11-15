# Training Instructions for CIC-IDS2017 Dataset

**For:** Project Partner
**Goal:** Train a working NIDS model that detects real attacks on live network traffic
**Time:** 2-3 hours (mostly downloading)

---

## What You'll Achieve

After following these steps, the NIDS will correctly detect:

✅ **BENIGN (Normal Traffic)**:
- Pinging from another machine
- Browsing websites (Google, YouTube, etc.)
- SSH connections
- Normal downloads
- DNS queries

❌ **ATTACKS (Malicious Traffic)**:
- Nmap port scans
- DDoS attacks
- Brute force attempts
- Suspicious connection patterns

---

## Prerequisites

**What you need:**
- Ubuntu VM with the project code
- 20 GB free disk space
- Stable internet connection
- 2-4 hours of time

**Install dependencies:**
```bash
cd ~/655-project
sudo apt-get update
sudo apt-get install -y python3-pip unzip wget
pip3 install pandas scikit-learn tensorflow tqdm matplotlib
```

---

## Step 1: Download CIC-IDS2017 Dataset

The CIC-IDS2017 dataset contains real network traffic with labeled attacks.

### Download Links

**Option A: Download from Official Source**

Go to: https://www.unb.ca/cic/datasets/ids-2017.html

Or use direct links:

```bash
# Create data directory
mkdir -p ~/cicids2017_data
cd ~/cicids2017_data

# Download PCAP files (these are large!)
# You can use wget or download via browser

# Monday (Benign only) - ~11 GB
wget https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Monday-WorkingHours.pcap

# Tuesday (Benign + Brute Force) - ~12 GB
wget https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap

# Wednesday (Benign + DoS) - ~14 GB
wget https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Wednesday-WorkingHours.pcap

# Thursday (Benign + Web Attacks) - ~10 GB
wget https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Thursday-WorkingHours.pcap

# Friday (Benign + Port Scan + DDoS + Botnet) - ~16 GB
wget https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Friday-WorkingHours.pcap
```

**Note:** If direct download doesn't work, you may need to:
1. Visit the website
2. Request access
3. Download via their provided links

**Option B: Use Kaggle Dataset** (Easier but CSV format)

```bash
# If you have CSV files instead of PCAP, see Alternative Method below
```

### Minimum Download

If disk space is limited, download at least:
- **Monday** (benign only) - Required
- **Wednesday** (DoS attacks) - Required
- **Friday** (Port scans, DDoS) - Recommended

---

## Step 2: Understand the Dataset Structure

**CIC-IDS2017 Traffic by Day:**

| Day | Traffic Type | Attacks Included |
|-----|-------------|------------------|
| **Monday** | 100% Benign | Normal traffic only |
| **Tuesday** | Benign + Attack | FTP Brute Force, SSH Brute Force |
| **Wednesday** | Benign + Attack | DoS Hulk, DoS GoldenEye, DoS Slowloris, Heartbleed |
| **Thursday** | Benign + Attack | Web Attacks, SQL Injection, XSS |
| **Friday** | Benign + Attack | Port Scans, DDoS, Botnet |

**We need:**
- Lots of BENIGN data (for model to learn normal patterns)
- Various ATTACK data (for testing and validation)

---

## Step 3: Extract Features from PCAP Files

Now use the project's feature extraction script:

```bash
cd ~/655-project

# Extract features from Monday (BENIGN only)
echo "Extracting Monday benign traffic..."
./extract_features_from_pcap.py \
    ~/cicids2017_data/Monday-WorkingHours.pcap \
    --label BENIGN \
    --output ~/cicids2017_features.csv \
    --timeout 120

# This will take 30-60 minutes depending on file size
```

**Expected output:**
```
Reading Monday-WorkingHours.pcap...
Processing 5234567 packets...
Extracting features: 100%|████████████| 5234567/5234567
Extracted 234521 flows from Monday-WorkingHours.pcap
Label: BENIGN
Saved 234521 flows to ~/cicids2017_features.csv
```

### Extract Attack Traffic

**For Wednesday (DoS attacks):**
```bash
echo "Extracting Wednesday DoS attacks..."
./extract_features_from_pcap.py \
    ~/cicids2017_data/Wednesday-WorkingHours.pcap \
    --label ATTACK \
    --output ~/cicids2017_features.csv \
    --append \
    --timeout 120
```

**For Friday (Port Scans, DDoS, Botnet):**
```bash
echo "Extracting Friday attacks..."
./extract_features_from_pcap.py \
    ~/cicids2017_data/Friday-WorkingHours.pcap \
    --label ATTACK \
    --output ~/cicids2017_features.csv \
    --append \
    --timeout 120
```

**Optional - Extract all days:**
```bash
# Tuesday (Brute Force)
./extract_features_from_pcap.py \
    ~/cicids2017_data/Tuesday-WorkingHours.pcap \
    --label ATTACK \
    --output ~/cicids2017_features.csv \
    --append \
    --timeout 120

# Thursday (Web Attacks)
./extract_features_from_pcap.py \
    ~/cicids2017_data/Thursday-WorkingHours.pcap \
    --label ATTACK \
    --output ~/cicids2017_features.csv \
    --append \
    --timeout 120
```

**Check your data:**
```bash
# Count total flows
wc -l ~/cicids2017_features.csv

# Check label distribution
tail -n +2 ~/cicids2017_features.csv | cut -d',' -f79 | sort | uniq -c

# Should show something like:
#  150000 ATTACK
#  250000 BENIGN
```

**Goal:** At least 100,000 BENIGN and 50,000 ATTACK flows

---

## Step 4: Train the Model

Now train using the CIC-IDS2017 features:

```bash
cd ~/655-project

# Train the model (this takes 30-60 minutes)
./train_model.py ~/cicids2017_features.csv \
    --features 30 \
    --window-size 5 \
    --epochs 50 \
    --batch-size 32 \
    --encoding-dim 16 \
    --threshold-percentile 95 \
    --output-dir .
```

### What to Expect During Training

```
Loading data from /home/user/cicids2017_features.csv...
Loaded 400000 samples
Features: 78
Label distribution:
BENIGN    250000
ATTACK    150000

Preparing data...
Selecting top 30 features...
Selected features: 30

Train set: 320000 samples
Test set: 80000 samples

Creating sequences with window size 5...
Created 319996 sequences

Building LSTM Autoencoder...
Input shape: (5, 30)

Training model...
Training on 200000 benign sequences
Epoch 1/50
6250/6250 [==============================] - 52s - loss: 3.4567 - val_loss: 1.8234
Epoch 2/50
6250/6250 [==============================] - 48s - loss: 1.6543 - val_loss: 1.2345
...
Epoch 35/50
6250/6250 [==============================] - 47s - loss: 0.5234 - val_loss: 0.4567

Calculating threshold...
Benign reconstruction errors:
  Min: 0.1234
  Max: 2.3456
  Mean: 0.5234
  Median: 0.4567
  95th percentile: 1.1234

Evaluating model...
Test Results:
  Accuracy: 0.9567
  Precision: 0.9234
  Recall: 0.9456
  F1-Score: 0.9344

Saving model...
  ✓ Saved lstm_autoencoder.h5
  ✓ Saved scaler.pkl
  ✓ Saved selector.pkl
  ✓ Saved metadata.json
  ✓ Saved feature_order.txt

Training complete!
Threshold: 1.123456
```

**Good results:**
- Accuracy: > 90%
- Precision: > 85%
- Recall: > 85%
- Threshold: 0.8 - 1.5 (typical range)

**If you get poor results (<80% accuracy):**
- Extract more data from the PCAP files
- Try `--epochs 100`
- Check that you have good balance (60-70% BENIGN, 30-40% ATTACK)

---

## Step 5: Test with Real Live Traffic

Now test that it actually works with real network activity!

### Test Setup

You need **TWO machines**:
1. **Monitor VM** - Running the NIDS
2. **Attack VM** or another computer on the network

### Test 1: Normal Traffic (Should be BENIGN)

**On Monitor VM (Terminal 1):**
```bash
cd ~/655-project
sudo ./run_monitor.sh
```

**On Attack VM or Another Computer:**
```bash
# Ping the monitor VM
ping -c 20 <MONITOR_VM_IP>

# Browse from the monitor VM
# Open Firefox/Chrome and visit:
# - https://www.google.com
# - https://www.youtube.com
# - https://www.github.com

# SSH to another machine
ssh user@some-server.com

# Download a file
wget https://www.google.com/robots.txt
```

**Expected on Monitor VM:**
```
✓ Benign traffic - 192.168.1.50:54321 → 8.8.8.8:53 | Error: 0.5234
✓ Benign traffic - 192.168.1.100:12345 → 142.250.185.46:443 | Error: 0.7234
✓ Benign traffic - 192.168.1.100:45678 → 172.217.19.46:443 | Error: 0.8234

Stats - Packets: 2000 | Flows: 45 | Benign: 43 | Attacks: 2 | Uptime: 0:03:45
```

✅ **Success:** Green output, errors 0.3-1.2, mostly benign

### Test 2: Port Scan (Should be ATTACK)

**On Attack VM:**
```bash
# Simple port scan
nmap -sT 192.168.1.100

# More aggressive scan
nmap -sT -p 1-1000 192.168.1.100

# Fast scan
nmap -F 192.168.1.100
```

**Expected on Monitor VM:**
```
⚠️  ATTACK DETECTED!
================================================================================
Source:      192.168.1.50:45678
Destination: 192.168.1.100:22
Protocol:    TCP
Packets:     45
Duration:    0.23s
Error:       2.3456 (Threshold: 1.1235)
Confidence:  108.7% above threshold
================================================================================

⚠️  ATTACK DETECTED!
Source:      192.168.1.50:56789
Destination: 192.168.1.100:80
Protocol:    TCP
Packets:     12
Duration:    0.15s
Error:       1.8234 (Threshold: 1.1235)
Confidence:  62.3% above threshold
================================================================================
```

✅ **Success:** Red output, errors 1.3-4.0, flagged as attacks

### Test 3: DoS Attack (Should be ATTACK)

**On Attack VM:**
```bash
# Install hping3 if needed
sudo apt-get install hping3

# SYN flood (run for 10 seconds)
sudo hping3 -S --flood -p 80 192.168.1.100 &
sleep 10
sudo killall hping3

# HTTP flood
for i in {1..1000}; do
    curl http://192.168.1.100/ &
done
sleep 5
killall curl
```

**Expected on Monitor VM:**
```
⚠️  ATTACK DETECTED!
⚠️  ATTACK DETECTED!
⚠️  ATTACK DETECTED!
[Multiple attack alerts with high errors 2.5-5.0]

Stats - Packets: 50000 | Flows: 234 | Benign: 12 | Attacks: 222 | Uptime: 0:05:32
```

✅ **Success:** Many red alerts, high attack count

### Test 4: SSH Brute Force (Should be ATTACK)

**On Attack VM:**
```bash
# Rapid SSH connection attempts
for i in {1..50}; do
    timeout 1 ssh root@192.168.1.100 2>/dev/null &
    sleep 0.2
done
```

**Expected on Monitor VM:**
```
⚠️  ATTACK DETECTED!
Source:      192.168.1.50:various
Destination: 192.168.1.100:22
[Multiple alerts for SSH brute force pattern]
```

✅ **Success:** Detected as attack

---

## Step 6: Verify Everything Works

### Final Verification Checklist

Run all these tests and check results:

- [ ] **Ping test**: `ping <monitor_ip>` → Should show BENIGN (green)
- [ ] **Web browsing**: Visit Google, YouTube → Should show BENIGN (green)
- [ ] **Normal SSH**: `ssh user@server` → Should show BENIGN (green)
- [ ] **Port scan**: `nmap <monitor_ip>` → Should show ATTACK (red)
- [ ] **DoS attack**: Use hping3 or curl flood → Should show ATTACK (red)
- [ ] **Brute force**: Rapid SSH attempts → Should show ATTACK (red)

### Expected Metrics

After running tests for 10-15 minutes:

```
Stats - Packets: 50000 | Flows: 1234 | Benign: 1050 | Attacks: 184 | Uptime: 0:15:23

Detection Rate:
  - Normal traffic: 85-95% classified as BENIGN
  - Attack traffic: 90-98% classified as ATTACK
  - False positive rate: < 10%
```

**Good results:**
- Most normal traffic is green (benign)
- Attack traffic is red (attack)
- Errors make sense (benign: 0.3-1.2, attacks: 1.3-5.0)

**Poor results:**
- Everything is red → Threshold too low, try `--threshold 1.5`
- Everything is green → Threshold too high, retrain with `--threshold-percentile 90`
- Random classification → Need more training data

---

## Troubleshooting

### "Not enough memory during training"

**Problem:** Training fails with memory error

**Solution:**
```bash
# Use smaller batch size
./train_model.py ~/cicids2017_features.csv --batch-size 16

# Or reduce data size
head -100000 ~/cicids2017_features.csv > smaller_dataset.csv
./train_model.py smaller_dataset.csv --epochs 50
```

### "Feature extraction is very slow"

**Problem:** Processing PCAP takes many hours

**Solution:**
- This is normal for large files (10+ GB)
- Run overnight
- Or extract only part of the file:
```bash
# Split large PCAP into smaller chunks
tcpdump -r Monday-WorkingHours.pcap -w monday_part1.pcap -c 1000000
./extract_features_from_pcap.py monday_part1.pcap --label BENIGN -o data.csv
```

### "Everything is flagged as attack"

**Problem:** All traffic shows red alerts

**Solution:**
```bash
# Increase threshold
sudo ./run_monitor.sh --threshold 1.5

# Or retrain with different percentile
./train_model.py ~/cicids2017_features.csv --threshold-percentile 98
```

### "No attacks are detected"

**Problem:** Port scans and DoS attacks show as benign

**Solution:**
```bash
# Decrease threshold
sudo ./run_monitor.sh --threshold 0.8

# Or check if you trained on enough attack data
tail -n +2 ~/cicids2017_features.csv | cut -d',' -f79 | sort | uniq -c
# Should have at least 30% ATTACK flows
```

### "Download links don't work"

**Problem:** Cannot download CIC-IDS2017 PCAP files

**Solution:**
1. Visit https://www.unb.ca/cic/datasets/ids-2017.html
2. Fill out the data request form
3. They'll email you working download links

**Alternative:** Use the CSV files:
- Download CSV files from Kaggle or official source
- Skip feature extraction (already have features)
- Train directly:
```bash
# If you have the processed CSV with labels
./train_model.py CICIDS2017_processed.csv --epochs 50
```

---

## Alternative Method: Using CSV Files

If you have CSV files instead of PCAP files:

### The CSV Files Already Have Features

The CIC-IDS2017 dataset provides pre-extracted CSV files. **Problem:** These use the Java CICFlowMeter tool which won't match our feature extraction.

**Better approach:** Use PCAP files as described above

**But if you MUST use CSV:**

1. Download CSV files
2. Map their feature names to our 78 features
3. Train on their features (won't be 100% compatible but might work)

This is **NOT recommended** because it will have the same mismatch problem as the pre-trained model.

---

## Summary

### What You Did

1. ✅ Downloaded CIC-IDS2017 PCAP files (real network traffic dataset)
2. ✅ Extracted features using `extract_features_from_pcap.py` (uses YOUR code)
3. ✅ Trained LSTM model using `train_model.py` on CIC-IDS2017 data
4. ✅ Tested with real live traffic (ping, browsing, nmap, DoS)
5. ✅ Verified detection works correctly

### What You Have Now

A trained model that:
- ✅ Detects normal traffic (ping, browsing, SSH) as BENIGN
- ✅ Detects attacks (nmap, DoS, brute force) as ATTACK
- ✅ Works with real live network traffic
- ✅ Has 90%+ accuracy
- ✅ Is 100% compatible with the monitoring scripts

### Files Created

```
~/655-project/
  ✓ lstm_autoencoder.h5   - Trained on CIC-IDS2017
  ✓ scaler.pkl            - Trained on CIC-IDS2017
  ✓ selector.pkl          - Trained on CIC-IDS2017
  ✓ metadata.json         - Model config
  ✓ feature_order.txt     - Selected features

~/cicids2017_features.csv  - Extracted features (can keep for retraining)
```

### Next Steps

1. **Document your results:**
   - Take screenshots of benign traffic (green)
   - Take screenshots of attack detection (red)
   - Note the accuracy and metrics

2. **Run continuous monitoring:**
   ```bash
   sudo ./run_monitor.sh
   # Leave running to monitor all network traffic
   ```

3. **Generate report:**
   - Show detection of normal traffic vs attacks
   - Include accuracy metrics from training
   - Demonstrate real-world detection

---

## Questions?

**If training fails:** Check the troubleshooting section above

**If detection is wrong:** Adjust threshold or retrain with more data

**If you can't download CIC-IDS2017:** Ask instructor for alternative dataset or access

**For any other issues:** Check the main `TRAINING_GUIDE.md` or `TROUBLESHOOTING.md`

---

**Good luck! The model should work perfectly with real live traffic testing.** 🚀
