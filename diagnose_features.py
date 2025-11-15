#!/usr/bin/env python3
"""Diagnose feature extraction issues"""
import json
import joblib
import numpy as np
from network_monitor import FlowTracker
from scapy.all import rdpcap, IP, TCP, UDP

print("=" * 80)
print("Feature Extraction Diagnostics")
print("=" * 80)

# Load model components
print("\n1. Loading model components...")
metadata = json.load(open('metadata.json'))
selector = joblib.load('selector.pkl')
scaler = joblib.load('scaler.pkl')

print(f"   Selector expects: {selector.n_features_in_} features")
print(f"   Selector outputs: {selector.n_features_out_ if hasattr(selector, 'n_features_out_') else np.sum(selector.get_support())} features")
print(f"   Scaler expects: {scaler.n_features_in_} features")

# Load feature list
with open('cicflowmeter_features.txt', 'r') as f:
    feature_list = [line.strip() for line in f if line.strip()]
print(f"   Feature list has: {len(feature_list)} features")

# Check selector selection
if hasattr(selector, 'get_support'):
    selected_mask = selector.get_support()
    selected_indices = np.where(selected_mask)[0]
    print(f"\n2. Selector selects {len(selected_indices)} features from indices:")
    print(f"   {selected_indices[:10]}... (showing first 10)")

    print(f"\n3. Selected feature names (first 10):")
    for i, idx in enumerate(selected_indices[:10]):
        if idx < len(feature_list):
            print(f"   [{i}] Index {idx}: {feature_list[idx]}")

# Check scaler statistics
print(f"\n4. Scaler statistics (first 5 features):")
if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
    for i in range(min(5, len(scaler.mean_))):
        print(f"   Feature {i}: mean={scaler.mean_[i]:.2f}, scale={scaler.scale_[i]:.2f}")

# Create a test flow
print(f"\n5. Testing feature extraction on sample flow...")
tracker = FlowTracker(timeout=10)

# Simulate a simple HTTP flow
print("   Creating simulated benign HTTP flow...")
test_flow = {
    'packets': [
        {'time': 0.0, 'length': 60, 'direction': 'fwd'},
        {'time': 0.1, 'length': 1500, 'direction': 'bwd'},
        {'time': 0.2, 'length': 60, 'direction': 'fwd'},
        {'time': 0.3, 'length': 1500, 'direction': 'bwd'},
        {'time': 0.4, 'length': 60, 'direction': 'fwd'},
    ],
    'fwd_packets': [
        {'time': 0.0, 'length': 60},
        {'time': 0.2, 'length': 60},
        {'time': 0.4, 'length': 60},
    ],
    'bwd_packets': [
        {'time': 0.1, 'length': 1500},
        {'time': 0.3, 'length': 1500},
    ],
    'start_time': 0.0,
    'last_time': 0.4,
    'flags': {'FIN': 2, 'SYN': 2, 'RST': 0, 'PSH': 2, 'ACK': 5, 'URG': 0, 'CWR': 0, 'ECE': 0},
    'fwd_flags': {'FIN': 1, 'SYN': 1, 'RST': 0, 'PSH': 1, 'ACK': 3, 'URG': 0, 'CWR': 0, 'ECE': 0},
    'bwd_flags': {'FIN': 1, 'SYN': 1, 'RST': 0, 'PSH': 1, 'ACK': 2, 'URG': 0, 'CWR': 0, 'ECE': 0},
    'idle_times': []
}
flow_key = ('192.168.1.100', '93.184.216.34', 54321, 80, 6)  # HTTP flow

# Extract features
features = tracker.extract_features(test_flow, flow_key)

# Convert to array
features_array = np.array([features.get(feat, 0) for feat in feature_list])

print(f"\n6. Extracted features (first 10):")
for i, feat_name in enumerate(feature_list[:10]):
    print(f"   {feat_name}: {features.get(feat_name, 0)}")

print(f"\n7. Feature array shape: {features_array.shape}")
print(f"   Contains NaN: {np.any(np.isnan(features_array))}")
print(f"   Contains Inf: {np.any(np.isinf(features_array))}")
print(f"   Min value: {np.min(features_array):.2f}")
print(f"   Max value: {np.max(features_array):.2e}")
print(f"   Mean value: {np.mean(features_array):.2f}")

# Apply selector
try:
    features_selected = selector.transform(features_array.reshape(1, -1))
    print(f"\n8. After selector: shape={features_selected.shape}")
    print(f"   First 5 selected values: {features_selected[0][:5]}")

    # Apply scaler
    features_scaled = scaler.transform(features_selected)
    print(f"\n9. After scaler: shape={features_scaled.shape}")
    print(f"   First 5 scaled values: {features_scaled[0][:5]}")
    print(f"   Min: {np.min(features_scaled):.2f}, Max: {np.max(features_scaled):.2f}")

    # Check if values are reasonable
    if np.max(np.abs(features_scaled)) > 100:
        print(f"\n   ⚠️  WARNING: Scaled features have very large values!")
        print(f"   This suggests feature extraction doesn't match training data.")
        extreme_idx = np.argmax(np.abs(features_scaled[0]))
        print(f"   Most extreme feature at index {extreme_idx}: {features_scaled[0][extreme_idx]:.2f}")
        if extreme_idx < len(selected_indices):
            orig_idx = selected_indices[extreme_idx]
            if orig_idx < len(feature_list):
                print(f"   This corresponds to: {feature_list[orig_idx]}")
                print(f"   Original value: {features_array[orig_idx]:.2e}")

except Exception as e:
    print(f"\n   ✗ ERROR: {e}")

print("\n" + "=" * 80)
print("DIAGNOSIS:")
print("=" * 80)
print("If you see very large scaled values (>100), the problem is:")
print("1. Feature calculation methods don't match CICFlowMeter")
print("2. Feature units might be wrong (microseconds vs seconds)")
print("3. Feature order might not match what selector expects")
print("=" * 80)
