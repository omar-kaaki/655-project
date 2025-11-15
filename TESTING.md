# Testing the Network Intrusion Detection System

This guide shows you how to test the NIDS and verify it's detecting both normal and malicious traffic.

## Quick Start - Clean Output

Use the clean startup script to avoid TensorFlow warnings:

```bash
sudo ./run_monitor.sh
```

Or set environment variables manually:
```bash
export TF_CPP_MIN_LOG_LEVEL=3
export TF_ENABLE_ONEDNN_OPTS=0
sudo ./venv/bin/python3 network_monitor.py
```

---

## Understanding Flow Detection

The system detects **completed flows**, not individual packets. A flow completes when:
- **TCP FIN flags** are exchanged (normal connection close)
- **TCP RST flag** is sent (connection reset)
- **Timeout** occurs (default: **10 seconds** when using `./run_monitor.sh`, **30 seconds** otherwise)
- **Minimum 5 packets** in the flow

**Important:** You need **5 completed flows** before the system starts detecting anomalies (sliding window requirement).

**New in this version:** Flows now complete quickly! When you run `./run_monitor.sh`, flows timeout after just 10 seconds, so you'll see results within 15-20 seconds of generating traffic.

### Activity Monitoring

Every 100 packets, you'll see activity updates like:
```
INFO - Activity - Packets: 100 | Active Flows: 3 | Completed Flows: 0
INFO - Activity - Packets: 200 | Active Flows: 5 | Completed Flows: 2
```

This shows the system is working even before flows complete!

---

## Test 1: Generate Normal Traffic

### From the Same VM

Open another terminal and run these commands to generate benign traffic:

```bash
# DNS queries
for i in {1..10}; do nslookup google.com; sleep 1; done

# ICMP (ping)
ping -c 20 8.8.8.8

# HTTP requests
for i in {1..10}; do curl -s http://example.com > /dev/null; sleep 1; done

# HTTPS requests
for i in {1..10}; do curl -s https://www.google.com > /dev/null; sleep 1; done
```

**Expected Output:**
```
INFO - ✓ Benign traffic - 192.168.1.100:54321 -> 8.8.8.8:53 | Error: 0.42
INFO - ✓ Benign traffic - 192.168.1.100:443 -> 142.250.80.46:443 | Error: 0.38
```

---

## Test 2: Simulate Malicious Activity

### Prerequisites for Attack Simulation

You'll need **another VM** or **another machine** on the same network. Get your VM's IP:

```bash
# Find your VM's IP address
ip addr show

# Common interfaces: eth0, ens33, wlan0
# Look for "inet 192.168.x.x" or "inet 10.0.x.x"
```

Let's say your VM IP is: **192.168.1.100**

### Attack Type 1: Port Scan (from another VM/machine)

**High probability of detection**

From the attacking machine:
```bash
# Install nmap if needed
sudo apt-get install nmap

# SYN scan (common port scan)
nmap -sS 192.168.1.100

# Aggressive scan (more likely to trigger detection)
nmap -A -T4 192.168.1.100

# Scan all ports (very suspicious)
nmap -p- 192.168.1.100

# Fast scan (sends many packets quickly)
nmap -T5 192.168.1.100
```

**Expected Output on Victim VM:**
```
WARNING - ⚠️  ATTACK DETECTED! Flow: 192.168.1.200:54321 -> 192.168.1.100:22 | Error: 2.89 | Threshold: 1.44 | Confidence: 101%
WARNING - ⚠️  ATTACK DETECTED! Flow: 192.168.1.200:54322 -> 192.168.1.100:80 | Error: 3.12 | Threshold: 1.44 | Confidence: 117%
```

### Attack Type 2: SSH Brute Force (from another VM)

**High probability of detection**

From the attacking machine:
```bash
# Install hydra if needed
sudo apt-get install hydra

# Create a small password list
echo -e "password\nadmin\n123456\nroot\ntest" > passwords.txt

# Brute force SSH (replace with your VM's IP)
hydra -l root -P passwords.txt ssh://192.168.1.100
```

**Expected Output:**
```
WARNING - ⚠️  ATTACK DETECTED! Flow: 192.168.1.200:45123 -> 192.168.1.100:22 | Error: 4.56 | Threshold: 1.44 | Confidence: 217%
```

### Attack Type 3: SYN Flood (from another VM)

**Very high probability of detection**

From the attacking machine (requires root):
```bash
# Install hping3
sudo apt-get install hping3

# SYN flood attack (sends many SYN packets)
sudo hping3 -S -p 80 --flood 192.168.1.100

# More controlled SYN flood (10 packets/sec)
sudo hping3 -S -p 80 -i u100000 192.168.1.100
```

**Expected Output:**
```
WARNING - ⚠️  ATTACK DETECTED! Flow: 192.168.1.200:random -> 192.168.1.100:80 | Error: 5.23 | Threshold: 1.44 | Confidence: 264%
```

### Attack Type 4: Slowloris (HTTP DoS)

From the attacking machine:
```bash
# Install slowloris
git clone https://github.com/gkbrk/slowloris.git
cd slowloris

# Run slowloris attack
python3 slowloris.py 192.168.1.100 -p 80 -s 200
```

---

## Test 3: Network Scan from Kali Linux

If you have **Kali Linux** as your attacking VM:

```bash
# Metasploit port scanner
msfconsole
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.100
set PORTS 1-1000
run

# Nmap with aggressive options
nmap -A -T4 -v 192.168.1.100

# Vulnerability scan
nmap --script vuln 192.168.1.100
```

---

## Test 4: Generate Mixed Traffic

Create a script to generate both normal and suspicious traffic:

```bash
#!/bin/bash
# Save as test_traffic.sh

TARGET_IP="192.168.1.100"  # Your victim VM

echo "Generating mixed traffic patterns..."

# Normal traffic
echo "1. Normal web browsing..."
curl -s https://www.google.com > /dev/null
sleep 2

# Suspicious: Port scan
echo "2. Port scanning..."
nmap -sS -p 22,80,443,8080 $TARGET_IP

sleep 2

# Normal traffic
echo "3. Normal DNS queries..."
nslookup google.com

sleep 2

# Suspicious: Rapid connections
echo "4. Rapid connection attempts..."
for i in {1..50}; do
    timeout 0.1 nc -zv $TARGET_IP 22 2>&1 | grep -v "Connection refused"
done

echo "Traffic generation complete!"
```

---

## Monitoring and Verification

### View Live Logs

```bash
# In another terminal, watch the log file
tail -f network_monitor.log

# Filter for attacks only
tail -f network_monitor.log | grep "ATTACK"

# Filter for benign traffic only
tail -f network_monitor.log | grep "Benign"
```

### Check Statistics

The monitor prints statistics every 1000 packets:
```
INFO - Stats - Packets: 5000 | Flows: 234 | Benign: 230 | Attacks: 4 | Uptime: 0:05:15
```

---

## Understanding the Output

### Benign Traffic Example:
```
2025-11-15 18:51:30 - INFO - ✓ Benign traffic - 192.168.1.100:54321 -> 8.8.8.8:53 | Error: 0.3421
```
- Source: 192.168.1.100:54321 (your VM)
- Destination: 8.8.8.8:53 (Google DNS)
- Reconstruction Error: 0.3421 (well below threshold of 1.436)

### Attack Detected Example:
```
2025-11-15 18:52:45 - WARNING - ⚠️  ATTACK DETECTED! Flow: 192.168.1.200:12345 -> 192.168.1.100:22 | Error: 2.8934 | Threshold: 1.4360 | Confidence: 101.52%
```
- Source: 192.168.1.200:12345 (attacker)
- Destination: 192.168.1.100:22 (your SSH port)
- Reconstruction Error: 2.8934 (above threshold)
- Confidence: 101.52% (how much higher than threshold)

---

## Troubleshooting

### No Traffic Appearing

**Problem:** Monitor is running but no flows appear

**Solutions:**
1. Generate more traffic (flows need to complete)
2. Wait 2-3 minutes for flows to timeout
3. Use TCP connections (UDP flows may not complete quickly)
4. Check you're monitoring the right interface:
   ```bash
   # List interfaces
   ip link show

   # Monitor specific interface
   sudo ./run_monitor.sh -i eth0
   ```

### No Attacks Detected

**Problem:** Running attacks but all flows marked as benign

**Possible reasons:**
1. Not enough flows yet (need 5 flows for sliding window)
2. Attack pattern too similar to training data
3. Try more aggressive attacks (port scans, brute force)
4. Lower the threshold:
   ```bash
   sudo ./run_monitor.sh -t 1.0  # More sensitive
   ```

### Too Many False Positives

**Problem:** Normal traffic flagged as attacks

**Solution:** Increase the threshold:
```bash
sudo ./run_monitor.sh -t 2.0  # Less sensitive
```

---

## Quick Test Script

Save this as `quick_test.sh` in your project folder:

```bash
#!/bin/bash
echo "Quick NIDS Test"
echo "==============="
echo ""
echo "This will generate traffic to test the NIDS..."
echo ""

# Normal traffic
echo "[1/3] Generating normal traffic..."
ping -c 10 8.8.8.8 > /dev/null 2>&1 &
curl -s https://www.google.com > /dev/null
nslookup google.com > /dev/null

sleep 5

# Suspicious traffic (self-scan)
echo "[2/3] Generating suspicious traffic (self-scan)..."
nmap -sS -p 22,80,443 localhost > /dev/null 2>&1

sleep 5

# More normal traffic
echo "[3/3] More normal traffic..."
for i in {1..5}; do
    curl -s https://example.com > /dev/null
    sleep 1
done

echo ""
echo "Test complete! Check the monitor output for detections."
```

---

## Network Setup for Attack Testing

### Recommended Setup:

```
┌─────────────────┐         ┌─────────────────┐
│   Attacker VM   │────────▶│   Victim VM     │
│  (Kali Linux)   │  LAN    │  (Your Ubuntu)  │
│  192.168.1.200  │         │  192.168.1.100  │
└─────────────────┘         └─────────────────┘
                                    │
                                    │ Running NIDS
                                    ▼
                            [Monitor Output]
```

### VirtualBox/VMware Network Settings:
- Use **Bridged Network** or **NAT Network** (NOT NAT alone)
- This allows VMs to see each other
- Both VMs should be on the same network

---

## Expected Timeline

```
Time 0s:     Start monitor
Time 10s:    First normal flows complete
Time 30s:    First 5 flows collected → anomaly detection begins
Time 60s:    Port scan from attacker → ATTACK DETECTED
Time 90s:    More normal traffic → Benign
Time 120s:   SSH brute force → ATTACK DETECTED
```

Remember: You need **5 completed flows** before the system starts classifying!
