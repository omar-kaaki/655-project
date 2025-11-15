#!/bin/bash
# Quick traffic generator for testing the NIDS

echo "╔════════════════════════════════════════════════════╗"
echo "║  Network Traffic Generator - NIDS Testing          ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Check if running as root for some tests
if [ "$EUID" -ne 0 ]; then
    echo "Note: Some tests require sudo. Run with 'sudo' for full testing."
    echo ""
fi

echo "This script generates network traffic to test the NIDS."
echo "Make sure the NIDS is running in another terminal!"
echo ""
read -p "Press Enter to start..."

# Test 1: Normal DNS traffic
echo ""
echo "[Test 1/5] Generating DNS queries (normal traffic)..."
for i in {1..10}; do
    nslookup google.com > /dev/null 2>&1
    echo -n "."
    sleep 0.5
done
echo " Done!"
sleep 2

# Test 2: Normal HTTP/HTTPS traffic
echo ""
echo "[Test 2/5] Generating HTTP/HTTPS requests (normal traffic)..."
for i in {1..10}; do
    curl -s http://example.com > /dev/null 2>&1
    echo -n "."
    sleep 0.5
done
echo " Done!"
sleep 2

# Test 3: ICMP ping
echo ""
echo "[Test 3/5] Generating ICMP ping traffic (normal traffic)..."
ping -c 20 8.8.8.8 > /dev/null 2>&1 &
echo "Pinging 8.8.8.8... Done!"
sleep 5

# Test 4: Self port scan (suspicious)
echo ""
echo "[Test 4/5] Running port scan on localhost (suspicious)..."
if command -v nmap &> /dev/null; then
    nmap -sT -p 22,80,443,8080 localhost > /dev/null 2>&1
    echo "Port scan complete!"
else
    echo "Nmap not installed. Skipping port scan test."
    echo "Install with: sudo apt-get install nmap"
fi
sleep 2

# Test 5: Rapid connection attempts (suspicious)
echo ""
echo "[Test 5/5] Rapid connection attempts to common ports (suspicious)..."
for port in 22 80 443 8080; do
    for i in {1..5}; do
        timeout 0.1 bash -c "echo '' > /dev/tcp/127.0.0.1/$port" 2>/dev/null
        echo -n "."
    done
done
echo " Done!"

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║  Traffic generation complete!                      ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Check the NIDS monitor output for detections."
echo ""
echo "Tips:"
echo "  - Wait 30-60 seconds for flows to complete"
echo "  - You need 5+ completed flows before anomaly detection starts"
echo "  - Check the log file: tail -f network_monitor.log"
echo ""
echo "For testing from another VM (attacks):"
echo "  1. Find this VM's IP: ip addr show"
echo "  2. From attacker VM run: nmap -sS <this_vm_ip>"
echo "  3. Or run SSH brute force: hydra -l root -P passwords.txt ssh://<this_vm_ip>"
echo ""
