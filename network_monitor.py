#!/usr/bin/env python3
"""
Real-time Network Intrusion Detection System
Uses LSTM Autoencoder to detect anomalous network traffic
"""

import os
import sys
import json
import pickle
import logging
import argparse
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP
import numpy as np
import tensorflow as tf
from tensorflow import keras

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class FlowTracker:
    """Track network flows and extract features"""

    def __init__(self, timeout=120):
        self.flows = defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'last_time': None,
            'fwd_packets': [],
            'bwd_packets': [],
            'flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0},
            'fwd_flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0},
            'bwd_flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0},
            'idle_times': []
        })
        self.timeout = timeout
        self.completed_flows = deque(maxlen=1000)

    def get_flow_key(self, packet):
        """Generate unique flow key from packet"""
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 6
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 17
        else:
            return None

        # Normalize flow direction (smaller IP first)
        if src_ip < dst_ip:
            return (src_ip, dst_ip, src_port, dst_port, protocol, 'fwd')
        elif src_ip > dst_ip:
            return (dst_ip, src_ip, dst_port, src_port, protocol, 'bwd')
        else:
            # Same IP, use port to determine direction
            if src_port < dst_port:
                return (src_ip, dst_ip, src_port, dst_port, protocol, 'fwd')
            else:
                return (dst_ip, src_ip, dst_port, src_port, protocol, 'bwd')

    def update_flow(self, packet, timestamp):
        """Update flow statistics with new packet"""
        flow_info = self.get_flow_key(packet)
        if not flow_info:
            return None

        flow_key = flow_info[:5]
        direction = flow_info[5]
        flow = self.flows[flow_key]

        # Initialize flow
        if flow['start_time'] is None:
            flow['start_time'] = timestamp

        # Update last seen time
        if flow['last_time'] is not None:
            idle_time = timestamp - flow['last_time']
            if idle_time > 0.001:  # More than 1ms
                flow['idle_times'].append(idle_time)

        flow['last_time'] = timestamp

        # Get packet length
        pkt_len = len(packet)

        # Add to appropriate direction
        if direction == 'fwd':
            flow['fwd_packets'].append({'time': timestamp, 'length': pkt_len})
        else:
            flow['bwd_packets'].append({'time': timestamp, 'length': pkt_len})

        flow['packets'].append({'time': timestamp, 'length': pkt_len, 'direction': direction})

        # Update TCP flags
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            if tcp_flags.F:
                flow['flags']['FIN'] += 1
                if direction == 'fwd':
                    flow['fwd_flags']['FIN'] += 1
                else:
                    flow['bwd_flags']['FIN'] += 1
            if tcp_flags.S:
                flow['flags']['SYN'] += 1
                if direction == 'fwd':
                    flow['fwd_flags']['SYN'] += 1
                else:
                    flow['bwd_flags']['SYN'] += 1
            if tcp_flags.R:
                flow['flags']['RST'] += 1
                if direction == 'fwd':
                    flow['fwd_flags']['RST'] += 1
                else:
                    flow['bwd_flags']['RST'] += 1
            if tcp_flags.P:
                flow['flags']['PSH'] += 1
                if direction == 'fwd':
                    flow['fwd_flags']['PSH'] += 1
                else:
                    flow['bwd_flags']['PSH'] += 1
            if tcp_flags.A:
                flow['flags']['ACK'] += 1
                if direction == 'fwd':
                    flow['fwd_flags']['ACK'] += 1
                else:
                    flow['bwd_flags']['ACK'] += 1
            if tcp_flags.U:
                flow['flags']['URG'] += 1
                if direction == 'fwd':
                    flow['fwd_flags']['URG'] += 1
                else:
                    flow['bwd_flags']['URG'] += 1

        # Check if flow should be completed (has FIN or RST, or timeout)
        flow_duration = timestamp - flow['start_time']
        if (flow['flags']['FIN'] >= 2 or flow['flags']['RST'] > 0) and len(flow['packets']) >= 5:
            return self.complete_flow(flow_key)
        elif flow_duration > self.timeout and len(flow['packets']) >= 5:
            return self.complete_flow(flow_key)

        return None

    def complete_flow(self, flow_key):
        """Complete a flow and extract features"""
        flow = self.flows.pop(flow_key)
        features = self.extract_features(flow, flow_key)
        self.completed_flows.append(features)
        return features

    def extract_features(self, flow, flow_key):
        """Extract the 30 required features from a flow"""
        features = {}

        # Basic flow info
        src_ip, dst_ip, src_port, dst_port, protocol = flow_key
        features['src_ip'] = src_ip
        features['dst_ip'] = dst_ip
        features['src_port'] = src_port
        features['dst_port'] = dst_port
        features['protocol'] = protocol

        # Destination Port
        features['Destination Port'] = dst_port

        # Flow Duration (in microseconds)
        if flow['start_time'] and flow['last_time']:
            features['Flow Duration'] = int((flow['last_time'] - flow['start_time']) * 1_000_000)
        else:
            features['Flow Duration'] = 0

        # Packet lengths
        all_lengths = [p['length'] for p in flow['packets']]
        fwd_lengths = [p['length'] for p in flow['fwd_packets']]
        bwd_lengths = [p['length'] for p in flow['bwd_packets']]

        # Forward packet length stats
        features['Fwd Packet Length Min'] = min(fwd_lengths) if fwd_lengths else 0

        # Backward packet length stats
        features['Bwd Packet Length Max'] = max(bwd_lengths) if bwd_lengths else 0
        features['Bwd Packet Length Min'] = min(bwd_lengths) if bwd_lengths else 0
        features['Bwd Packet Length Mean'] = np.mean(bwd_lengths) if bwd_lengths else 0
        features['Bwd Packet Length Std'] = np.std(bwd_lengths) if bwd_lengths else 0

        # Inter-arrival times (IAT)
        flow_iats = []
        fwd_iats = []
        bwd_iats = []

        # Calculate flow IATs
        for i in range(1, len(flow['packets'])):
            iat = (flow['packets'][i]['time'] - flow['packets'][i-1]['time']) * 1_000_000  # microseconds
            flow_iats.append(iat)

        # Calculate forward IATs
        for i in range(1, len(flow['fwd_packets'])):
            iat = (flow['fwd_packets'][i]['time'] - flow['fwd_packets'][i-1]['time']) * 1_000_000
            fwd_iats.append(iat)

        # Calculate backward IATs
        for i in range(1, len(flow['bwd_packets'])):
            iat = (flow['bwd_packets'][i]['time'] - flow['bwd_packets'][i-1]['time']) * 1_000_000
            bwd_iats.append(iat)

        # Flow IAT stats
        features['Flow IAT Mean'] = np.mean(flow_iats) if flow_iats else 0
        features['Flow IAT Std'] = np.std(flow_iats) if flow_iats else 0
        features['Flow IAT Max'] = max(flow_iats) if flow_iats else 0

        # Forward IAT stats
        features['Fwd IAT Total'] = sum(fwd_iats) if fwd_iats else 0
        features['Fwd IAT Mean'] = np.mean(fwd_iats) if fwd_iats else 0
        features['Fwd IAT Std'] = np.std(fwd_iats) if fwd_iats else 0
        features['Fwd IAT Max'] = max(fwd_iats) if fwd_iats else 0

        # Backward IAT stats
        features['Bwd IAT Std'] = np.std(bwd_iats) if bwd_iats else 0
        features['Bwd IAT Max'] = max(bwd_iats) if bwd_iats else 0

        # Min/Max/Mean packet lengths
        features['Min Packet Length'] = min(all_lengths) if all_lengths else 0
        features['Max Packet Length'] = max(all_lengths) if all_lengths else 0
        features['Packet Length Mean'] = np.mean(all_lengths) if all_lengths else 0
        features['Packet Length Std'] = np.std(all_lengths) if all_lengths else 0
        features['Packet Length Variance'] = np.var(all_lengths) if all_lengths else 0

        # TCP Flags
        features['FIN Flag Count'] = flow['flags']['FIN']
        features['ACK Flag Count'] = flow['flags']['ACK']
        features['URG Flag Count'] = flow['flags']['URG']

        # Down/Up Ratio
        total_fwd_bytes = sum(fwd_lengths) if fwd_lengths else 0
        total_bwd_bytes = sum(bwd_lengths) if bwd_lengths else 0
        features['Down/Up Ratio'] = total_bwd_bytes / total_fwd_bytes if total_fwd_bytes > 0 else 0

        # Average packet size
        total_bytes = sum(all_lengths)
        total_packets = len(all_lengths)
        features['Average Packet Size'] = total_bytes / total_packets if total_packets > 0 else 0

        # Average backward segment size
        features['Avg Bwd Segment Size'] = np.mean(bwd_lengths) if bwd_lengths else 0

        # Idle time stats
        idle_times = [t * 1_000_000 for t in flow['idle_times']]  # Convert to microseconds
        features['Idle Mean'] = np.mean(idle_times) if idle_times else 0
        features['Idle Max'] = max(idle_times) if idle_times else 0
        features['Idle Min'] = min(idle_times) if idle_times else 0

        return features


class NetworkMonitor:
    """Main network monitoring and anomaly detection system"""

    def __init__(self, model_dir='.', interface=None, alert_threshold=None):
        self.model_dir = model_dir
        self.interface = interface

        # Load metadata
        metadata_path = os.path.join(model_dir, 'metadata.json')
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)

        # Set threshold
        self.threshold = alert_threshold if alert_threshold else self.metadata['threshold']
        self.window_size = self.metadata['window_size']
        self.feature_order = self.metadata['feature_order']

        # Load model
        logger.info("Loading LSTM autoencoder model...")
        model_path = os.path.join(model_dir, self.metadata['model_file'])
        self.model = keras.models.load_model(model_path)
        logger.info(f"Model loaded from {model_path}")

        # Load scaler
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        logger.info(f"Scaler loaded from {scaler_path}")

        # Load feature selector
        selector_path = os.path.join(model_dir, 'selector.pkl')
        with open(selector_path, 'rb') as f:
            self.selector = pickle.load(f)
        logger.info(f"Feature selector loaded from {selector_path}")

        # Initialize flow tracker
        self.flow_tracker = FlowTracker()

        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'benign_flows': 0,
            'attack_flows': 0,
            'start_time': datetime.now()
        }

        # Sliding window for sequences
        self.flow_window = deque(maxlen=self.window_size)

        logger.info(f"Network Monitor initialized with threshold: {self.threshold}")
        logger.info(f"Monitoring interface: {interface if interface else 'all interfaces'}")

    def features_to_array(self, features):
        """Convert feature dictionary to ordered numpy array"""
        return np.array([features.get(feat, 0) for feat in self.feature_order])

    def predict_anomaly(self, features_array):
        """Run inference and detect anomaly"""
        # Reshape for model input: (1, window_size, num_features)
        X = features_array.reshape(1, self.window_size, -1)

        # Get reconstruction
        reconstruction = self.model.predict(X, verbose=0)

        # Calculate reconstruction error (MSE)
        mse = np.mean(np.square(X - reconstruction))

        # Classify
        is_attack = mse > self.threshold

        return {
            'is_attack': is_attack,
            'reconstruction_error': float(mse),
            'threshold': self.threshold,
            'confidence': float(abs(mse - self.threshold) / self.threshold)
        }

    def process_flow(self, flow_features):
        """Process a completed flow"""
        if flow_features is None:
            return

        self.stats['total_flows'] += 1

        # Convert to feature array
        features_array = self.features_to_array(flow_features)

        # Scale features
        features_scaled = self.scaler.transform(features_array.reshape(1, -1))

        # Add to sliding window
        self.flow_window.append(features_scaled[0])

        # Only predict when we have enough flows for a sequence
        if len(self.flow_window) == self.window_size:
            # Create sequence
            sequence = np.array(list(self.flow_window))

            # Predict
            result = self.predict_anomaly(sequence)

            # Log result
            if result['is_attack']:
                self.stats['attack_flows'] += 1
                logger.warning(
                    f"⚠️  ATTACK DETECTED! "
                    f"Flow: {flow_features['src_ip']}:{flow_features['src_port']} -> "
                    f"{flow_features['dst_ip']}:{flow_features['dst_port']} | "
                    f"Error: {result['reconstruction_error']:.4f} | "
                    f"Threshold: {result['threshold']:.4f} | "
                    f"Confidence: {result['confidence']:.2%}"
                )
            else:
                self.stats['benign_flows'] += 1
                logger.info(
                    f"✓ Benign traffic - "
                    f"{flow_features['src_ip']}:{flow_features['src_port']} -> "
                    f"{flow_features['dst_ip']}:{flow_features['dst_port']} | "
                    f"Error: {result['reconstruction_error']:.4f}"
                )

    def packet_handler(self, packet):
        """Handle each captured packet"""
        try:
            self.stats['total_packets'] += 1

            # Get timestamp
            timestamp = float(packet.time)

            # Update flow and check if completed
            flow_features = self.flow_tracker.update_flow(packet, timestamp)

            # Process completed flow
            if flow_features:
                self.process_flow(flow_features)

            # Print stats every 1000 packets
            if self.stats['total_packets'] % 1000 == 0:
                self.print_stats()

        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)

    def print_stats(self):
        """Print monitoring statistics"""
        uptime = datetime.now() - self.stats['start_time']
        logger.info(
            f"Stats - Packets: {self.stats['total_packets']} | "
            f"Flows: {self.stats['total_flows']} | "
            f"Benign: {self.stats['benign_flows']} | "
            f"Attacks: {self.stats['attack_flows']} | "
            f"Uptime: {uptime}"
        )

    def start(self):
        """Start monitoring network traffic"""
        logger.info("=" * 80)
        logger.info("Network Intrusion Detection System - STARTED")
        logger.info("=" * 80)
        logger.info(f"Model: {self.metadata['model_type']}")
        logger.info(f"Features: {len(self.feature_order)}")
        logger.info(f"Window Size: {self.window_size}")
        logger.info(f"Anomaly Threshold: {self.threshold}")
        logger.info("=" * 80)

        try:
            # Start packet capture
            logger.info("Starting packet capture... (Press Ctrl+C to stop)")
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                filter="ip"
            )
        except KeyboardInterrupt:
            logger.info("\nStopping network monitor...")
            self.print_stats()
            logger.info("Network monitor stopped.")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}", exc_info=True)
            raise


def main():
    parser = argparse.ArgumentParser(
        description='Real-time Network Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all interfaces
  sudo python3 network_monitor.py

  # Monitor specific interface
  sudo python3 network_monitor.py -i eth0

  # Use custom threshold
  sudo python3 network_monitor.py -t 1.5

  # Monitor specific interface with custom threshold
  sudo python3 network_monitor.py -i wlan0 -t 1.2
        """
    )

    parser.add_argument(
        '-i', '--interface',
        help='Network interface to monitor (e.g., eth0, wlan0). If not specified, monitors all interfaces.',
        default=None
    )

    parser.add_argument(
        '-t', '--threshold',
        type=float,
        help=f'Anomaly detection threshold (default: from metadata.json)',
        default=None
    )

    parser.add_argument(
        '-m', '--model-dir',
        help='Directory containing model files (default: current directory)',
        default='.'
    )

    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        logger.error("This script must be run as root (use sudo)")
        sys.exit(1)

    # Create and start monitor
    monitor = NetworkMonitor(
        model_dir=args.model_dir,
        interface=args.interface,
        alert_threshold=args.threshold
    )

    monitor.start()


if __name__ == '__main__':
    main()
