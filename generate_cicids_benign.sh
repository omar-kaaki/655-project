#!/bin/bash
# Generate benign traffic matching CIC-IDS2017 dataset patterns
# Based on Monday benign traffic from the dataset

echo "╔════════════════════════════════════════════════════╗"
echo "║  CIC-IDS2017 Benign Traffic Generator             ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Simulating benign traffic patterns from CIC-IDS2017 dataset"
echo "Press Ctrl+C to stop"
echo ""
sleep 2

counter=1
while true; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Round $counter - CIC-IDS2017 Benign Traffic"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # 1. HTTP Web Browsing (common in CIC-IDS2017)
    echo "[1/5] HTTP/HTTPS web browsing..."
    curl -s http://www.google.com > /dev/null 2>&1
    sleep 0.5
    curl -s https://www.facebook.com > /dev/null 2>&1
    sleep 0.5
    curl -s https://www.youtube.com > /dev/null 2>&1
    sleep 0.5
    curl -s https://www.amazon.com > /dev/null 2>&1
    sleep 0.5
    curl -s https://www.wikipedia.org > /dev/null 2>&1
    sleep 1

    # 2. HTTPS connections (most common in dataset)
    echo "[2/5] HTTPS traffic to popular sites..."
    for site in github.com stackoverflow.com reddit.com twitter.com; do
        curl -s https://$site > /dev/null 2>&1
        sleep 0.3
    done
    sleep 1

    # 3. DNS queries (to external DNS, not local)
    echo "[3/5] DNS queries to public DNS..."
    for domain in google.com facebook.com youtube.com amazon.com github.com; do
        nslookup $domain 8.8.8.8 > /dev/null 2>&1
    done
    sleep 1

    # 4. Simulated file downloads (HTTP GET requests)
    echo "[4/5] Downloading small files..."
    curl -s -o /dev/null http://ipv4.download.thinkbroadband.com/5MB.zip &
    sleep 2
    pkill -f download.thinkbroadband 2>/dev/null
    sleep 1

    # 5. Mixed web activity
    echo "[5/5] Mixed web activity..."
    # Sequential page loads (simulating browsing)
    curl -s https://www.bing.com > /dev/null 2>&1
    sleep 1
    curl -s https://www.msn.com > /dev/null 2>&1
    sleep 1
    curl -s https://www.yahoo.com > /dev/null 2>&1
    sleep 1

    echo "✓ Round $counter complete (benign). Waiting 3 seconds..."
    echo ""
    sleep 3

    counter=$((counter + 1))
done
