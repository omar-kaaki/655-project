#!/bin/bash
# Continuous traffic generator - keeps generating traffic in a loop
# Perfect for testing the NIDS

echo "╔════════════════════════════════════════════════════╗"
echo "║  Continuous Traffic Generator - NIDS Testing       ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "This script continuously generates network traffic."
echo "Make sure the NIDS is running in another terminal!"
echo ""
echo "Press Ctrl+C to stop"
echo ""
sleep 2

counter=1
while true; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Round $counter - Generating traffic..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # DNS queries
    echo "[1/4] DNS queries..."
    for i in {1..5}; do
        nslookup google.com > /dev/null 2>&1
        nslookup facebook.com > /dev/null 2>&1
        nslookup github.com > /dev/null 2>&1
    done

    # HTTP requests
    echo "[2/4] HTTP/HTTPS requests..."
    for i in {1..5}; do
        curl -s http://example.com > /dev/null 2>&1
        curl -s https://www.google.com > /dev/null 2>&1
    done

    # Ping
    echo "[3/4] ICMP ping..."
    ping -c 10 8.8.8.8 > /dev/null 2>&1 &

    # Connection attempts (slightly suspicious)
    echo "[4/4] Connection attempts..."
    for port in 80 443 22 8080; do
        timeout 0.1 bash -c "echo '' > /dev/tcp/127.0.0.1/$port" 2>/dev/null
    done

    echo "✓ Round $counter complete. Waiting 5 seconds..."
    echo ""
    sleep 5

    counter=$((counter + 1))
done
