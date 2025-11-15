#!/bin/bash
# Attack Simulation Script for NIDS Testing
# Generates both normal and malicious traffic patterns

echo "╔════════════════════════════════════════════════════╗"
echo "║  Attack Simulation - NIDS Testing                 ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Get target (localhost for self-testing)
TARGET_IP="${1:-127.0.0.1}"

echo "Target: $TARGET_IP"
echo "This script simulates various attack patterns."
echo "Make sure the NIDS is running!"
echo ""
read -p "Press Enter to start attack simulation..."
echo ""

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "⚠️  Warning: nmap not installed. Installing..."
    sudo apt-get update > /dev/null 2>&1
    sudo apt-get install -y nmap > /dev/null 2>&1
fi

# Attack 1: Port Scan (TCP SYN Scan)
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[ATTACK 1/5] PORT SCAN - TCP SYN Scan"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Scanning common ports on $TARGET_IP..."
nmap -sT -p 21,22,23,25,80,443,3306,3389,8080 $TARGET_IP > /dev/null 2>&1 &
echo "✓ Port scan initiated"
sleep 3

# Normal traffic interlude
echo ""
echo "[NORMAL] Generating benign traffic..."
curl -s http://example.com > /dev/null 2>&1
nslookup google.com > /dev/null 2>&1
sleep 2

# Attack 2: Aggressive Port Scan
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[ATTACK 2/5] AGGRESSIVE PORT SCAN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Fast scan with version detection..."
nmap -T4 -A -p 1-100 $TARGET_IP > /dev/null 2>&1 &
echo "✓ Aggressive scan initiated"
sleep 3

# Normal traffic
echo ""
echo "[NORMAL] More benign traffic..."
ping -c 5 8.8.8.8 > /dev/null 2>&1 &
curl -s https://www.google.com > /dev/null 2>&1
sleep 2

# Attack 3: Rapid Connection Attempts (DoS simulation)
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[ATTACK 3/5] RAPID CONNECTION ATTEMPTS (DoS Simulation)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Flooding target with connection attempts..."
for i in {1..100}; do
    timeout 0.05 bash -c "echo '' > /dev/tcp/$TARGET_IP/80" 2>/dev/null &
    timeout 0.05 bash -c "echo '' > /dev/tcp/$TARGET_IP/443" 2>/dev/null &
done
echo "✓ Sent 200 rapid connection attempts"
sleep 3

# Normal traffic
echo ""
echo "[NORMAL] Regular web browsing..."
curl -s http://example.com > /dev/null 2>&1
nslookup facebook.com > /dev/null 2>&1
sleep 2

# Attack 4: Service Enumeration
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[ATTACK 4/5] SERVICE ENUMERATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Detecting services and versions..."
nmap -sV -p 22,80,443 $TARGET_IP > /dev/null 2>&1 &
echo "✓ Service enumeration started"
sleep 3

# Normal traffic
echo ""
echo "[NORMAL] DNS lookups..."
for domain in google.com facebook.com github.com amazon.com; do
    nslookup $domain > /dev/null 2>&1
done
sleep 2

# Attack 5: Multiple Port Scans (Persistence)
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[ATTACK 5/5] PERSISTENT SCANNING"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Repeated scans to evade detection..."
for i in {1..3}; do
    nmap -sT -p 20-30 $TARGET_IP > /dev/null 2>&1 &
    sleep 1
done
echo "✓ Persistent scanning pattern executed"
sleep 3

# Final normal traffic
echo ""
echo "[NORMAL] Final benign traffic..."
ping -c 10 8.8.8.8 > /dev/null 2>&1 &
curl -s https://www.google.com > /dev/null 2>&1
nslookup google.com > /dev/null 2>&1

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║  Attack simulation complete!                      ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Attack patterns simulated:"
echo "  1. TCP SYN Port Scan"
echo "  2. Aggressive Port Scan with Version Detection"
echo "  3. Rapid Connection Attempts (DoS)"
echo "  4. Service Enumeration"
echo "  5. Persistent Scanning"
echo ""
echo "Normal traffic was also generated between attacks."
echo "Check the NIDS monitor for detections!"
echo ""
echo "Wait 15-30 seconds for flows to complete and be analyzed."
echo ""
