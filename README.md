# Network Intrusion Detection System (NIDS)

Real-time network intrusion detection system using LSTM Autoencoder for anomaly detection. This system continuously monitors live network traffic on Ubuntu and detects potential attacks and security threats.

## Overview

This project implements an advanced network intrusion detection system that:
- **Captures live network traffic** from all interfaces or specific interfaces
- **Extracts network flow features** (30 features including packet statistics, timing, and TCP flags)
- **Detects anomalies** using a pre-trained LSTM Autoencoder model
- **Classifies traffic** as BENIGN or ATTACK in real-time
- **Runs continuously** as a system service or standalone application

### How It Works

1. **Packet Capture**: Uses Scapy to capture live network packets
2. **Flow Tracking**: Groups packets into network flows (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
3. **Feature Extraction**: Calculates 30 network flow features for each completed flow
4. **Normalization**: Scales features using pre-trained scaler
5. **Sequence Creation**: Creates sliding windows of flows (window size: 5)
6. **Anomaly Detection**: LSTM Autoencoder reconstructs the flow sequence
7. **Classification**: Compares reconstruction error to threshold (1.436)
   - **Low error** → BENIGN traffic
   - **High error** → ATTACK detected

## Model Details

- **Model Type**: LSTM Autoencoder
- **Framework**: TensorFlow 2.19.0 / scikit-learn 1.5.2
- **Features**: 30 network flow features
- **Window Size**: 5 flows
- **Anomaly Threshold**: 1.436 (95th percentile of benign reconstruction errors)
- **Training**: Trained on Monday benign flows, validated on Wednesday mixed flows

### Network Flow Features (30)

The system extracts the following features from each network flow:

**Port & Duration:**
- Destination Port
- Flow Duration

**Packet Length Statistics:**
- Fwd Packet Length Min
- Bwd Packet Length Max/Min/Mean/Std
- Min/Max/Mean/Std/Variance Packet Length
- Average Packet Size
- Avg Bwd Segment Size

**Inter-Arrival Time (IAT) Statistics:**
- Flow IAT Mean/Std/Max
- Fwd IAT Total/Mean/Std/Max
- Bwd IAT Std/Max

**TCP Flags:**
- FIN Flag Count
- ACK Flag Count
- URG Flag Count

**Other Metrics:**
- Down/Up Ratio
- Idle Mean/Max/Min

## Installation

### Prerequisites

- Ubuntu Linux (tested on Ubuntu 18.04+)
- Python 3.8+
- Root/sudo access (required for packet capture)
- Active network interface

### Quick Install

```bash
# 1. Clone or download this repository
cd 655-project

# 2. Run the setup script
sudo bash setup.sh
```

The setup script will:
- Install system dependencies (python3, libpcap-dev, tcpdump)
- Create a Python virtual environment
- Install all required Python packages
- Make the monitor script executable

### Manual Installation

If you prefer manual installation:

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv libpcap-dev tcpdump

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

### Method 1: Run Manually (Recommended for Testing)

```bash
# Monitor all network interfaces
sudo ./venv/bin/python3 network_monitor.py

# Monitor specific interface (e.g., eth0, wlan0, ens33)
sudo ./venv/bin/python3 network_monitor.py -i eth0

# Use custom anomaly threshold
sudo ./venv/bin/python3 network_monitor.py -t 1.5

# Monitor specific interface with custom threshold
sudo ./venv/bin/python3 network_monitor.py -i wlan0 -t 1.2

# Get help
sudo ./venv/bin/python3 network_monitor.py --help
```

**Example Output:**
```
2025-11-15 10:30:45 - INFO - Network Intrusion Detection System - STARTED
2025-11-15 10:30:45 - INFO - Model: LSTM_autoencoder
2025-11-15 10:30:45 - INFO - Features: 30
2025-11-15 10:30:45 - INFO - Window Size: 5
2025-11-15 10:30:45 - INFO - Anomaly Threshold: 1.4359582803933857
2025-11-15 10:30:45 - INFO - Starting packet capture...
2025-11-15 10:31:12 - INFO - ✓ Benign traffic - 192.168.1.100:54321 -> 8.8.8.8:53 | Error: 0.3421
2025-11-15 10:31:45 - WARNING - ⚠️  ATTACK DETECTED! Flow: 192.168.1.200:12345 -> 192.168.1.1:22 | Error: 2.8934 | Threshold: 1.4360 | Confidence: 101.52%
```

### Method 2: Run as System Service (Recommended for Production)

Install as a systemd service to run continuously in the background:

```bash
# Install the service
sudo bash install_service.sh

# Start the service
sudo systemctl start network-monitor

# Check status
sudo systemctl status network-monitor

# View live logs
sudo journalctl -u network-monitor -f
# or
sudo tail -f /var/log/network-monitor.log

# Stop the service
sudo systemctl stop network-monitor

# Restart the service
sudo systemctl restart network-monitor

# Disable service (prevent auto-start on boot)
sudo systemctl disable network-monitor
```

The service will:
- Start automatically on system boot
- Restart automatically if it crashes
- Log all output to `/var/log/network-monitor.log`
- Log errors to `/var/log/network-monitor-error.log`

## Configuration

### Command-Line Options

```
usage: network_monitor.py [-h] [-i INTERFACE] [-t THRESHOLD] [-m MODEL_DIR]

optional arguments:
  -h, --help            Show help message and exit
  -i, --interface       Network interface to monitor (e.g., eth0, wlan0)
                        Default: all interfaces
  -t, --threshold       Anomaly detection threshold
                        Default: 1.4359582803933857 (from metadata.json)
  -m, --model-dir       Directory containing model files
                        Default: current directory
```

### Finding Your Network Interface

To find available network interfaces on your system:

```bash
# List all network interfaces
ip link show

# Or use ifconfig
ifconfig -a

# Common interface names:
# - eth0, eth1: Ethernet
# - wlan0, wlan1: Wireless
# - ens33, ens34: VirtualBox/VMware
# - enp0s3: Some modern systems
```

### Adjusting the Threshold

The anomaly detection threshold determines sensitivity:

- **Lower threshold** (e.g., 1.0): More sensitive, may have false positives
- **Higher threshold** (e.g., 2.0): Less sensitive, may miss subtle attacks
- **Default** (1.436): Balanced, set at 95th percentile of benign traffic

To experiment with thresholds:

```bash
# More sensitive (more alerts)
sudo ./venv/bin/python3 network_monitor.py -t 1.0

# Less sensitive (fewer alerts)
sudo ./venv/bin/python3 network_monitor.py -t 2.0
```

## Logs and Monitoring

### Log Files

When running as a service, logs are stored in:
- `/var/log/network-monitor.log` - Main application log
- `/var/log/network-monitor-error.log` - Error log
- System journal (viewable with `journalctl`)

When running manually, logs are stored in:
- `network_monitor.log` - In the project directory

### Log Format

Each log entry includes:
- Timestamp
- Log level (INFO, WARNING, ERROR)
- Message with flow details

**Benign Traffic:**
```
2025-11-15 10:31:12 - INFO - ✓ Benign traffic - 192.168.1.100:54321 -> 8.8.8.8:53 | Error: 0.3421
```

**Attack Detected:**
```
2025-11-15 10:31:45 - WARNING - ⚠️  ATTACK DETECTED! Flow: 192.168.1.200:12345 -> 192.168.1.1:22 | Error: 2.8934 | Threshold: 1.4360 | Confidence: 101.52%
```

**Statistics (every 1000 packets):**
```
2025-11-15 10:32:00 - INFO - Stats - Packets: 5000 | Flows: 234 | Benign: 230 | Attacks: 4 | Uptime: 0:05:15
```

### Monitoring in Real-Time

```bash
# Follow the main log
sudo tail -f /var/log/network-monitor.log

# Filter for attacks only
sudo tail -f /var/log/network-monitor.log | grep "ATTACK DETECTED"

# View system journal
sudo journalctl -u network-monitor -f

# View last 100 lines
sudo journalctl -u network-monitor -n 100
```

## Troubleshooting

### Common Issues

**1. Permission Denied / Not running as root**
```
Error: This script must be run as root (use sudo)
```
**Solution**: Always use `sudo` when running the monitor

**2. No network interface found**
```
Error: Interface 'eth0' not found
```
**Solution**: Check available interfaces with `ip link show` and use the correct name

**3. Model files not found**
```
Error: No such file or directory: 'lstm_autoencoder.h5'
```
**Solution**: Ensure you're running from the project directory or use `-m` to specify the model directory

**4. Python module not found**
```
ImportError: No module named 'scapy'
```
**Solution**: Activate the virtual environment or reinstall dependencies:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

**5. Service won't start**
```bash
# Check service status
sudo systemctl status network-monitor

# Check logs for errors
sudo journalctl -u network-monitor -n 50

# Verify paths in service file
sudo cat /etc/systemd/system/network-monitor.service
```

### Testing the Installation

```bash
# 1. Test basic functionality
sudo ./venv/bin/python3 network_monitor.py --help

# 2. Run for 30 seconds and stop (Ctrl+C)
sudo ./venv/bin/python3 network_monitor.py

# 3. Generate some traffic to test detection
ping -c 10 8.8.8.8  # In another terminal

# 4. Check logs
cat network_monitor.log
```

## Performance Considerations

- **CPU Usage**: The LSTM model inference requires moderate CPU. On modern systems, expect 10-30% CPU usage.
- **Memory Usage**: Approximately 500MB-1GB RAM (model + flow tracking)
- **Packet Loss**: At very high traffic rates (>10,000 pps), some packets may be dropped. Consider:
  - Monitoring specific high-priority interfaces only
  - Adjusting flow timeout (default: 120 seconds)
  - Running on dedicated hardware

## Security Notes

- This system requires **root privileges** to capture network packets
- The service runs with `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities
- All traffic is analyzed locally; no data is sent externally
- Logs may contain IP addresses and port information

## Project Structure

```
655-project/
├── network_monitor.py           # Main monitoring script
├── lstm_autoencoder.h5          # Pre-trained LSTM model
├── scaler.pkl                   # Feature scaler
├── selector.pkl                 # Feature selector
├── metadata.json                # Model configuration
├── feature_order.txt            # Feature ordering
├── requirements.txt             # Python dependencies
├── setup.sh                     # Installation script
├── install_service.sh           # Service installation script
├── network-monitor.service      # systemd service template
├── network_monitor.log          # Application log (created at runtime)
└── README.md                    # This file
```

## Technical Details

### Flow Tracking

- Flows are identified by 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
- Flows are completed when:
  - FIN flags are received (TCP connection close)
  - RST flag is received (TCP reset)
  - Timeout is reached (default: 120 seconds)
  - Minimum 5 packets per flow

### Sliding Window

- Window size: 5 consecutive flows
- Stride: 1 (overlapping windows)
- Anomaly detection starts after 5 flows are collected

### Model Architecture

The LSTM Autoencoder:
- Learns normal traffic patterns from benign flows
- Reconstructs input sequences
- High reconstruction error indicates anomalous behavior
- Threshold at 95th percentile ensures 5% false positive rate on benign traffic

## Contributing

This is a course project. For questions or issues, contact the project maintainer.

## License

This project is for educational purposes as part of course 655.

## Acknowledgments

- CICFlowMeter for feature definitions
- TensorFlow and Keras for deep learning framework
- Scapy for packet capture capabilities

---

**Last Updated**: November 15, 2025
**Version**: 1.0
**Course**: 655 Network Security
