# Testing Quick Reference Card

**After training the model, use these commands to verify it works with real traffic.**

---

## Setup

**Monitor VM (Terminal 1):**
```bash
cd ~/655-project
sudo ./run_monitor.sh
```

**Attack VM or Second Machine:**
Use the commands below

---

## Test 1: BENIGN Traffic (Should be GREEN)

```bash
# Ping
ping -c 20 <MONITOR_VM_IP>

# Browse websites on monitor VM
# - Open browser and visit Google, YouTube, GitHub

# Download file
wget https://www.google.com/robots.txt

# SSH (if you have another server)
ssh user@some-server.com
```

**Expected:** Green "✓ Benign traffic" with errors 0.3-1.2

---

## Test 2: Port Scan ATTACK (Should be RED)

```bash
# Install nmap
sudo apt-get install nmap

# Simple scan
nmap -sT <MONITOR_VM_IP>

# Scan first 1000 ports
nmap -sT -p 1-1000 <MONITOR_VM_IP>

# Fast scan
nmap -F <MONITOR_VM_IP>
```

**Expected:** Red "⚠️ ATTACK DETECTED!" with errors 1.5-4.0

---

## Test 3: DoS ATTACK (Should be RED)

```bash
# Install hping3
sudo apt-get install hping3

# SYN flood for 10 seconds
sudo hping3 -S --flood -p 80 <MONITOR_VM_IP> &
sleep 10
sudo killall hping3

# HTTP flood
for i in {1..500}; do curl http://<MONITOR_VM_IP>/ & done
sleep 5
killall curl
```

**Expected:** Multiple red "⚠️ ATTACK DETECTED!" alerts

---

## Test 4: Brute Force ATTACK (Should be RED)

```bash
# Rapid SSH attempts
for i in {1..50}; do
    timeout 1 ssh root@<MONITOR_VM_IP> 2>/dev/null &
    sleep 0.2
done

# Rapid FTP attempts
for i in {1..30}; do
    timeout 1 ftp <MONITOR_VM_IP> 2>/dev/null &
    sleep 0.3
done
```

**Expected:** Red alerts for brute force pattern

---

## Test 5: Mixed Traffic (Realistic)

**Run simultaneously:**

```bash
# Terminal 1: Normal browsing/activity
while true; do
    ping -c 5 <MONITOR_VM_IP>
    wget https://www.google.com/robots.txt -O /dev/null 2>/dev/null
    sleep 10
done

# Terminal 2: Occasional attack
while true; do
    sleep 60  # Wait 1 minute
    nmap -F <MONITOR_VM_IP> >/dev/null 2>&1
    sleep 120  # Wait 2 minutes
done
```

**Expected:**
- Normal traffic = Green (benign)
- Port scans = Red (attack)
- Good mix in statistics

---

## What Good Results Look Like

```
Monitor Output:

✓ Benign traffic - 192.168.1.50:54321 → 8.8.8.8:53 | Error: 0.5234
✓ Benign traffic - 192.168.1.100:12345 → 142.250.185.46:443 | Error: 0.7234

⚠️  ATTACK DETECTED!
Source:      192.168.1.50:45678
Destination: 192.168.1.100:22
Error:       2.3456 (Threshold: 1.1235)

✓ Benign traffic - 192.168.1.100:45678 → 172.217.19.46:443 | Error: 0.8234

Stats - Packets: 5000 | Flows: 125 | Benign: 108 | Attacks: 17
```

**Good metrics:**
- Benign errors: 0.3 - 1.2 ✓
- Attack errors: 1.3 - 5.0 ✓
- 85-95% of normal traffic classified correctly
- 90-98% of attacks detected
- False positive rate < 10%

---

## Troubleshooting Quick Fixes

**Everything shows as attack (all red):**
```bash
sudo ./run_monitor.sh --threshold 1.5
```

**Nothing detected as attack (all green):**
```bash
sudo ./run_monitor.sh --threshold 0.8
```

**Want more/less sensitive:**
```bash
# More sensitive (lower threshold)
sudo ./run_monitor.sh --threshold 1.0

# Less sensitive (higher threshold)
sudo ./run_monitor.sh --threshold 2.0
```

---

## Using Provided Traffic Generators

Instead of manually testing, you can use the included scripts:

```bash
# Terminal 1: Monitor
sudo ./run_monitor.sh

# Terminal 2: Benign traffic
./generate_cicids_benign.sh

# Terminal 3: Attack traffic
./generate_cicids_attacks.sh <MONITOR_VM_IP>
```

These simulate CIC-IDS2017 traffic patterns automatically.

---

## Expected Timeline

| Activity | Duration | What You See |
|----------|----------|--------------|
| Normal browsing | 5 min | Mostly green, errors 0.3-1.2 |
| Port scan | 1-2 min | Red alerts, errors 1.5-3.0 |
| DoS attack | 30 sec | Many red alerts, errors 2.0-5.0 |
| Brute force | 2-3 min | Red alerts, errors 1.5-4.0 |
| Mixed traffic | 10+ min | Mix of green and red |

---

## Screenshot Locations for Report

Capture these for your project report:

1. **Normal traffic detection** (green output)
2. **Port scan detection** (red output with details)
3. **DoS attack detection** (multiple red alerts)
4. **Statistics summary** (packets, flows, benign, attacks)
5. **Training results** (accuracy, precision, recall from train_model.py)

---

**Remember:** Replace `<MONITOR_VM_IP>` with your actual monitor VM IP address (e.g., 192.168.1.100)

To find your monitor VM IP:
```bash
ip addr show | grep "inet " | grep -v 127.0.0.1
```
