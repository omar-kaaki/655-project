#!/usr/bin/env python3
"""
Real-time Network Intrusion Detection System
Uses LSTM Autoencoder to detect anomalous network traffic
"""

# Set environment variables FIRST before any imports
import os
import sys
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['PYTHONWARNINGS'] = 'ignore'

import json
import pickle
import logging
import argparse
from datetime import datetime
from collections import defaultdict, deque

# Suppress ALL warnings
import warnings
warnings.filterwarnings('ignore')

from scapy.all import sniff, IP, TCP, UDP
import numpy as np

# Suppress TensorFlow stderr output
import sys
stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')
import tensorflow as tf
from tensorflow import keras
sys.stderr = stderr

import joblib  # Alternative to pickle for sklearn objects

# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

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
        self.timeout = timeout
        self.flows = defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'last_time': None,
            'fwd_packets': [],
            'bwd_packets': [],
            'flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWR': 0, 'ECE': 0},
            'fwd_flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWR': 0, 'ECE': 0},
            'bwd_flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWR': 0, 'ECE': 0},
            'idle_times': []
        })
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
            if tcp_flags.C:  # CWR flag
                flow['flags']['CWR'] += 1
                if direction == 'fwd':
                    flow['fwd_flags']['CWR'] += 1
                else:
                    flow['bwd_flags']['CWR'] += 1
            if tcp_flags.E:  # ECE flag
                flow['flags']['ECE'] += 1
                if direction == 'fwd':
                    flow['fwd_flags']['ECE'] += 1
                else:
                    flow['bwd_flags']['ECE'] += 1

        # Check if flow should be completed (has FIN or RST, or timeout)
        flow_duration = timestamp - flow['start_time']
        min_packets = 3  # Reduced from 5 to allow more flows to complete

        # Complete on TCP termination flags
        if (flow['flags']['FIN'] >= 2 or flow['flags']['RST'] > 0) and len(flow['packets']) >= min_packets:
            return self.complete_flow(flow_key)
        # Complete on timeout
        elif flow_duration > self.timeout and len(flow['packets']) >= min_packets:
            return self.complete_flow(flow_key)

        return None

    def complete_flow(self, flow_key):
        """Complete a flow and extract features"""
        flow = self.flows.pop(flow_key)
        features = self.extract_features(flow, flow_key)
        self.completed_flows.append(features)
        return features

    def check_timeouts(self, current_time):
        """Check for and complete timed-out flows"""
        timed_out_flows = []
        min_packets = 3  # Minimum packets needed for a flow
        for flow_key, flow in list(self.flows.items()):
            if flow['last_time'] is None:
                continue
            flow_duration = current_time - flow['start_time']
            idle_time = current_time - flow['last_time']
            # Complete if flow has been idle for timeout period and has enough packets
            if idle_time > self.timeout and len(flow['packets']) >= min_packets:
                timed_out_flows.append(flow_key)

        # Complete all timed-out flows
        completed = []
        for flow_key in timed_out_flows:
            features = self.complete_flow(flow_key)
            completed.append(features)

        return completed

    def extract_features(self, flow, flow_key):
        """Extract all 78 CICFlowMeter features from a flow"""
        features = {}

        # Basic flow info
        src_ip, dst_ip, src_port, dst_port, protocol = flow_key
        features['src_ip'] = src_ip
        features['dst_ip'] = dst_ip
        features['src_port'] = src_port
        features['dst_port'] = dst_port
        features['protocol'] = protocol
        features['packets'] = flow['packets']  # Store for detailed logging

        # Packet lengths
        all_lengths = [p['length'] for p in flow['packets']]
        fwd_lengths = [p['length'] for p in flow['fwd_packets']]
        bwd_lengths = [p['length'] for p in flow['bwd_packets']]

        # Calculate byte totals
        total_fwd_bytes = sum(fwd_lengths) if fwd_lengths else 0
        total_bwd_bytes = sum(bwd_lengths) if bwd_lengths else 0
        total_bytes = sum(all_lengths)

        # Calculate packet counts
        total_fwd_packets = len(fwd_lengths)
        total_bwd_packets = len(bwd_lengths)
        total_packets = len(all_lengths)

        # Flow Duration (in microseconds)
        if flow['start_time'] and flow['last_time']:
            flow_duration_us = (flow['last_time'] - flow['start_time']) * 1_000_000
            flow_duration_s = flow['last_time'] - flow['start_time']
        else:
            flow_duration_us = 0
            flow_duration_s = 0.000001  # Avoid division by zero

        features['Flow Duration'] = int(flow_duration_us)

        # 1. Destination Port
        features['Destination Port'] = dst_port
        # 2-3. Total packets
        features['Total Fwd Packet'] = total_fwd_packets
        features['Total Bwd packets'] = total_bwd_packets
        # 5-6. Total length
        features['Total Length of Fwd Packet'] = total_fwd_bytes
        features['Total Length of Bwd Packet'] = total_bwd_bytes

        # 7-10. Forward packet length stats
        features['Fwd Packet Length Min'] = min(fwd_lengths) if fwd_lengths else 0
        features['Fwd Packet Length Max'] = max(fwd_lengths) if fwd_lengths else 0
        features['Fwd Packet Length Mean'] = np.mean(fwd_lengths) if fwd_lengths else 0
        features['Fwd Packet Length Std'] = np.std(fwd_lengths) if fwd_lengths else 0

        # 11-14. Backward packet length stats
        features['Bwd Packet Length Min'] = min(bwd_lengths) if bwd_lengths else 0
        features['Bwd Packet Length Max'] = max(bwd_lengths) if bwd_lengths else 0
        features['Bwd Packet Length Mean'] = np.mean(bwd_lengths) if bwd_lengths else 0
        features['Bwd Packet Length Std'] = np.std(bwd_lengths) if bwd_lengths else 0

        # 15-16. Flow rates
        features['Flow Bytes/s'] = total_bytes / flow_duration_s if flow_duration_s > 0 else 0
        features['Flow Packets/s'] = total_packets / flow_duration_s if flow_duration_s > 0 else 0

        # Inter-arrival times (IAT)
        flow_iats = []
        fwd_iats = []
        bwd_iats = []

        # Calculate flow IATs
        for i in range(1, len(flow['packets'])):
            iat = (flow['packets'][i]['time'] - flow['packets'][i-1]['time']) * 1_000_000
            flow_iats.append(iat)

        # Calculate forward IATs
        for i in range(1, len(flow['fwd_packets'])):
            iat = (flow['fwd_packets'][i]['time'] - flow['fwd_packets'][i-1]['time']) * 1_000_000
            fwd_iats.append(iat)

        # Calculate backward IATs
        for i in range(1, len(flow['bwd_packets'])):
            iat = (flow['bwd_packets'][i]['time'] - flow['bwd_packets'][i-1]['time']) * 1_000_000
            bwd_iats.append(iat)

        # 17-20. Flow IAT stats
        features['Flow IAT Mean'] = np.mean(flow_iats) if flow_iats else 0
        features['Flow IAT Std'] = np.std(flow_iats) if flow_iats else 0
        features['Flow IAT Max'] = max(flow_iats) if flow_iats else 0
        features['Flow IAT Min'] = min(flow_iats) if flow_iats else 0

        # 21-25. Forward IAT stats
        features['Fwd IAT Min'] = min(fwd_iats) if fwd_iats else 0
        features['Fwd IAT Max'] = max(fwd_iats) if fwd_iats else 0
        features['Fwd IAT Mean'] = np.mean(fwd_iats) if fwd_iats else 0
        features['Fwd IAT Std'] = np.std(fwd_iats) if fwd_iats else 0
        features['Fwd IAT Total'] = sum(fwd_iats) if fwd_iats else 0

        # 26-30. Backward IAT stats
        features['Bwd IAT Min'] = min(bwd_iats) if bwd_iats else 0
        features['Bwd IAT Max'] = max(bwd_iats) if bwd_iats else 0
        features['Bwd IAT Mean'] = np.mean(bwd_iats) if bwd_iats else 0
        features['Bwd IAT Std'] = np.std(bwd_iats) if bwd_iats else 0
        features['Bwd IAT Total'] = sum(bwd_iats) if bwd_iats else 0

        # 31-34. PSH and URG flags (forward/backward)
        features['Fwd PSH Flags'] = flow['fwd_flags'].get('PSH', 0)
        features['Bwd PSH Flags'] = flow['bwd_flags'].get('PSH', 0)
        features['Fwd URG Flags'] = flow['fwd_flags'].get('URG', 0)
        features['Bwd URG Flags'] = flow['bwd_flags'].get('URG', 0)

        # 35-36. Header lengths (estimate: TCP=20, UDP=8)
        header_len = 20 if protocol == 6 else 8
        features['Fwd Header Length'] = total_fwd_packets * header_len
        features['Bwd Header Length'] = total_bwd_packets * header_len

        # 37-38. Packets per second
        features['Fwd Packets/s'] = total_fwd_packets / flow_duration_s if flow_duration_s > 0 else 0
        features['Bwd Packets/s'] = total_bwd_packets / flow_duration_s if flow_duration_s > 0 else 0

        # 39-43. Min/Max/Mean packet lengths
        features['Min Packet Length'] = min(all_lengths) if all_lengths else 0
        features['Max Packet Length'] = max(all_lengths) if all_lengths else 0
        features['Packet Length Mean'] = np.mean(all_lengths) if all_lengths else 0
        features['Packet Length Std'] = np.std(all_lengths) if all_lengths else 0
        features['Packet Length Variance'] = np.var(all_lengths) if all_lengths else 0

        # 44-51. TCP Flags (all types)
        features['FIN Flag Count'] = flow['flags'].get('FIN', 0)
        features['SYN Flag Count'] = flow['flags'].get('SYN', 0)
        features['RST Flag Count'] = flow['flags'].get('RST', 0)
        features['PSH Flag Count'] = flow['flags'].get('PSH', 0)
        features['ACK Flag Count'] = flow['flags'].get('ACK', 0)
        features['URG Flag Count'] = flow['flags'].get('URG', 0)
        features['CWR Flag Count'] = flow['flags'].get('CWR', 0)
        features['ECE Flag Count'] = flow['flags'].get('ECE', 0)

        # 52-54. Packet size averages
        features['Down/Up Ratio'] = total_bwd_bytes / total_fwd_bytes if total_fwd_bytes > 0 else 0
        features['Average Packet Size'] = total_bytes / total_packets if total_packets > 0 else 0
        features['Fwd Segment Size Avg'] = np.mean(fwd_lengths) if fwd_lengths else 0
        features['Bwd Segment Size Avg'] = np.mean(bwd_lengths) if bwd_lengths else 0

        # 55-60. Bulk transfer metrics (simplified - we don't track bulk transfers)
        features['Fwd Bytes/Bulk Avg'] = 0
        features['Fwd Packet/Bulk Avg'] = 0
        features['Fwd Bulk Rate Avg'] = 0
        features['Bwd Bytes/Bulk Avg'] = 0
        features['Bwd Packet/Bulk Avg'] = 0
        features['Bwd Bulk Rate Avg'] = 0

        # 61-64. Subflow metrics (we treat whole flow as one subflow)
        features['Subflow Fwd Packets'] = total_fwd_packets
        features['Subflow Fwd Bytes'] = total_fwd_bytes
        features['Subflow Bwd Packets'] = total_bwd_packets
        features['Subflow Bwd Bytes'] = total_bwd_bytes

        # 65-66. Initial window bytes (simplified - use first packet)
        features['Fwd Init Win Bytes'] = fwd_lengths[0] if fwd_lengths else 0
        features['Bwd Init Win Bytes'] = bwd_lengths[0] if bwd_lengths else 0

        # 67. Forward active data packets (packets with payload)
        features['Fwd Act Data Pkts'] = total_fwd_packets
        # 68. Forward segment size min
        features['Fwd Seg Size Min'] = min(fwd_lengths) if fwd_lengths else 0

        # 69-72. Active time stats (using inter-packet times for activity)
        active_times = [iat for iat in flow_iats if iat < 1000000]  # < 1 second = active
        features['Active Min'] = min(active_times) if active_times else 0
        features['Active Mean'] = np.mean(active_times) if active_times else 0
        features['Active Max'] = max(active_times) if active_times else 0
        features['Active Std'] = np.std(active_times) if active_times else 0

        # 73-76. Idle time stats
        idle_times = [t * 1_000_000 for t in flow['idle_times']]
        if not idle_times:  # Use long IATs as idle times
            idle_times = [iat for iat in flow_iats if iat >= 1000000]
        features['Idle Min'] = min(idle_times) if idle_times else 0
        features['Idle Mean'] = np.mean(idle_times) if idle_times else 0
        features['Idle Max'] = max(idle_times) if idle_times else 0
        features['Idle Std'] = np.std(idle_times) if idle_times else 0

        # 77-78. Protocol and Label (we add protocol as numeric)
        features['Protocol'] = protocol

        return features


class NetworkMonitor:
    """Main network monitoring and anomaly detection system"""

    def __init__(self, model_dir='.', interface=None, alert_threshold=None, flow_timeout=30):
        self.model_dir = model_dir
        self.interface = interface
        self.flow_timeout = flow_timeout

        # Load metadata
        metadata_path = os.path.join(model_dir, 'metadata.json')
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)

        # Set threshold
        self.threshold = alert_threshold if alert_threshold else self.metadata['threshold']
        self.window_size = self.metadata['window_size']

        # Load comprehensive CICFlowMeter feature order (78 features)
        cicflowmeter_features_path = os.path.join(model_dir, 'cicflowmeter_features.txt')
        if os.path.exists(cicflowmeter_features_path):
            with open(cicflowmeter_features_path, 'r') as f:
                self.feature_order = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(self.feature_order)} CICFlowMeter features")
        else:
            # Fallback to metadata (legacy)
            self.feature_order = self.metadata['feature_order']
            logger.warning(f"cicflowmeter_features.txt not found, using {len(self.feature_order)} features from metadata")

        # Load model
        logger.info("Loading LSTM autoencoder model...")
        model_path = os.path.join(model_dir, self.metadata['model_file'])
        # Load without compilation since we only need inference (not training)
        self.model = keras.models.load_model(model_path, compile=False)
        logger.info(f"Model loaded from {model_path}")

        # Load scaler with multiple fallback methods
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        logger.info(f"Loading scaler from {scaler_path}")
        self.scaler = self._load_pickle_safe(scaler_path, 'scaler')

        # Load feature selector with multiple fallback methods
        selector_path = os.path.join(model_dir, 'selector.pkl')
        logger.info(f"Loading feature selector from {selector_path}")
        self.selector = self._load_pickle_safe(selector_path, 'selector')

        # Initialize flow tracker
        self.flow_tracker = FlowTracker(timeout=self.flow_timeout)

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
        logger.info(f"Flow timeout: {self.flow_timeout} seconds")
        logger.info(f"Monitoring interface: {interface if interface else 'all interfaces'}")

    def _load_pickle_safe(self, file_path, obj_name):
        """Safely load pickle files with multiple fallback methods"""
        # Method 1: Try joblib (best for sklearn objects)
        try:
            obj = joblib.load(file_path)
            logger.info(f"{obj_name} loaded successfully using joblib")
            return obj
        except Exception as e:
            logger.debug(f"joblib loading failed: {e}")

        # Method 2: Try pickle with latin1 encoding
        try:
            with open(file_path, 'rb') as f:
                obj = pickle.load(f, encoding='latin1')
            logger.info(f"{obj_name} loaded successfully using pickle with latin1")
            return obj
        except Exception as e:
            logger.debug(f"pickle with latin1 failed: {e}")

        # Method 3: Try pickle with bytes encoding
        try:
            with open(file_path, 'rb') as f:
                obj = pickle.load(f, encoding='bytes')
            logger.info(f"{obj_name} loaded successfully using pickle with bytes")
            return obj
        except Exception as e:
            logger.debug(f"pickle with bytes failed: {e}")

        # Method 4: Try standard pickle
        try:
            with open(file_path, 'rb') as f:
                obj = pickle.load(f)
            logger.info(f"{obj_name} loaded successfully using standard pickle")
            return obj
        except Exception as e:
            logger.error(f"All loading methods failed for {obj_name}: {e}")
            raise RuntimeError(f"Could not load {obj_name} from {file_path}")

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

        # Check for NaN or inf values
        if np.any(np.isnan(features_array)) or np.any(np.isinf(features_array)):
            logger.warning(f"NaN or inf values detected in features, replacing with 0")
            features_array = np.nan_to_num(features_array, nan=0.0, posinf=0.0, neginf=0.0)

        # Apply feature selector (critical step that was missing!)
        features_selected = self.selector.transform(features_array.reshape(1, -1))

        # Scale selected features
        features_scaled = self.scaler.transform(features_selected)

        # Add to sliding window
        self.flow_window.append(features_scaled[0])

        # Get protocol name
        protocol_name = "TCP" if flow_features['protocol'] == 6 else "UDP" if flow_features['protocol'] == 17 else "OTHER"

        # Log flow completion
        flows_needed = self.window_size - len(self.flow_window)
        if flows_needed > 0:
            print(
                f"{Colors.CYAN}[FLOW COMPLETE]{Colors.RESET} "
                f"{Colors.BLUE}{protocol_name}{Colors.RESET} "
                f"{flow_features['src_ip']}:{flow_features['src_port']} "
                f"{Colors.YELLOW}→{Colors.RESET} "
                f"{flow_features['dst_ip']}:{flow_features['dst_port']} | "
                f"Packets: {len(flow_features.get('packets', []))} | "
                f"Progress: {Colors.BOLD}{len(self.flow_window)}/{self.window_size}{Colors.RESET} flows "
                f"({Colors.YELLOW}{flows_needed} more needed{Colors.RESET})"
            )
            sys.stdout.flush()

        # Only predict when we have enough flows for a sequence
        if len(self.flow_window) == self.window_size:
            # Create sequence
            sequence = np.array(list(self.flow_window))

            # Predict
            result = self.predict_anomaly(sequence)

            # Log result with detailed information
            if result['is_attack']:
                self.stats['attack_flows'] += 1
                print(
                    f"\n{Colors.RED}{Colors.BOLD}{'='*80}{Colors.RESET}\n"
                    f"{Colors.RED}{Colors.BOLD}⚠️  ATTACK DETECTED!{Colors.RESET}\n"
                    f"{Colors.RED}{'='*80}{Colors.RESET}\n"
                    f"{Colors.BOLD}Source:{Colors.RESET}      {flow_features['src_ip']}:{flow_features['src_port']}\n"
                    f"{Colors.BOLD}Destination:{Colors.RESET} {flow_features['dst_ip']}:{flow_features['dst_port']}\n"
                    f"{Colors.BOLD}Protocol:{Colors.RESET}    {protocol_name}\n"
                    f"{Colors.BOLD}Packets:{Colors.RESET}     {len(flow_features.get('packets', []))}\n"
                    f"{Colors.BOLD}Duration:{Colors.RESET}    {flow_features['Flow Duration']/1_000_000:.2f}s\n"
                    f"{Colors.RED}{Colors.BOLD}Error:{Colors.RESET}       {result['reconstruction_error']:.4f} "
                    f"(Threshold: {result['threshold']:.4f})\n"
                    f"{Colors.RED}{Colors.BOLD}Confidence:{Colors.RESET}  {result['confidence']:.1%} above threshold\n"
                    f"{Colors.RED}{'='*80}{Colors.RESET}\n"
                )
                sys.stdout.flush()
            else:
                self.stats['benign_flows'] += 1
                print(
                    f"{Colors.GREEN}✓ [BENIGN]{Colors.RESET} "
                    f"{Colors.BLUE}{protocol_name}{Colors.RESET} "
                    f"{flow_features['src_ip']}:{flow_features['src_port']} "
                    f"{Colors.YELLOW}→{Colors.RESET} "
                    f"{flow_features['dst_ip']}:{flow_features['dst_port']} | "
                    f"Packets: {len(flow_features.get('packets', []))} | "
                    f"Error: {Colors.GREEN}{result['reconstruction_error']:.4f}{Colors.RESET}"
                )
                sys.stdout.flush()

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

            # Check for timed-out flows every 10 packets (more frequent)
            if self.stats['total_packets'] % 10 == 0:
                timed_out = self.flow_tracker.check_timeouts(timestamp)
                for flow_features in timed_out:
                    self.process_flow(flow_features)

            # Print stats every 100 packets (more frequent feedback)
            if self.stats['total_packets'] % 100 == 0:
                active_flows = len(self.flow_tracker.flows)
                logger.info(
                    f"Activity - Packets: {self.stats['total_packets']} | "
                    f"Active Flows: {active_flows} | "
                    f"Completed Flows: {self.stats['total_flows']}"
                )

            # Print detailed stats every 1000 packets
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

  # Quick testing with 10-second flow timeout
  sudo python3 network_monitor.py --flow-timeout 10
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
        '--flow-timeout',
        type=int,
        help='Flow timeout in seconds (default: 30). Lower values complete flows faster for testing.',
        default=30
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
        alert_threshold=args.threshold,
        flow_timeout=args.flow_timeout
    )

    monitor.start()


if __name__ == '__main__':
    main()
