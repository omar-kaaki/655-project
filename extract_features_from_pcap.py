#!/usr/bin/env python3
"""
Extract features from PCAP files using the same method as network_monitor.py
This ensures training and inference use IDENTICAL feature extraction
"""

import sys
import argparse
import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP
from network_monitor import FlowTracker
from tqdm import tqdm
import json

def extract_features_from_pcap(pcap_file, label='BENIGN', timeout=120):
    """
    Extract features from a PCAP file using FlowTracker

    Args:
        pcap_file: Path to PCAP file
        label: Label for this traffic (BENIGN or attack type)
        timeout: Flow timeout in seconds

    Returns:
        DataFrame with extracted features and labels
    """
    print(f"Reading {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP: {e}")
        return None

    print(f"Processing {len(packets)} packets...")
    tracker = FlowTracker(timeout=timeout)

    # Load feature list
    with open('cicflowmeter_features.txt', 'r') as f:
        feature_list = [line.strip() for line in f if line.strip()]

    all_features = []

    # Process packets
    for i, packet in enumerate(tqdm(packets, desc="Extracting features")):
        if IP not in packet:
            continue

        timestamp = float(packet.time)

        # Update flow
        flow_features = tracker.update_flow(packet, timestamp)

        if flow_features:
            # Convert to feature array in correct order
            features_dict = flow_features.copy()
            features_array = [features_dict.get(feat, 0) for feat in feature_list]

            # Add label
            features_array.append(label)
            all_features.append(features_array)

        # Check for timeouts periodically
        if i % 100 == 0:
            timed_out = tracker.check_timeouts(timestamp)
            for flow_feat in timed_out:
                if flow_feat:
                    features_dict = flow_feat.copy()
                    features_array = [features_dict.get(feat, 0) for feat in feature_list]
                    features_array.append(label)
                    all_features.append(features_array)

    # Complete any remaining flows
    final_time = float(packets[-1].time) if packets else 0
    remaining = tracker.check_timeouts(final_time + timeout + 1)
    for flow_feat in remaining:
        if flow_feat:
            features_dict = flow_feat.copy()
            features_array = [features_dict.get(feat, 0) for feat in feature_list]
            features_array.append(label)
            all_features.append(features_array)

    # Create DataFrame
    columns = feature_list + ['Label']
    df = pd.DataFrame(all_features, columns=columns)

    print(f"Extracted {len(df)} flows from {pcap_file}")
    print(f"Label: {label}")

    return df

def main():
    parser = argparse.ArgumentParser(description='Extract features from PCAP files')
    parser.add_argument('pcap_files', nargs='+', help='PCAP file(s) to process')
    parser.add_argument('--label', default='BENIGN', help='Label for this traffic (BENIGN or attack type)')
    parser.add_argument('--output', '-o', required=True, help='Output CSV file')
    parser.add_argument('--timeout', type=int, default=120, help='Flow timeout in seconds')
    parser.add_argument('--append', action='store_true', help='Append to existing CSV')

    args = parser.parse_args()

    all_dfs = []

    for pcap_file in args.pcap_files:
        df = extract_features_from_pcap(pcap_file, args.label, args.timeout)
        if df is not None and not df.empty:
            all_dfs.append(df)

    if not all_dfs:
        print("No features extracted!")
        return 1

    # Combine all dataframes
    combined_df = pd.concat(all_dfs, ignore_index=True)

    # Replace inf and nan values
    combined_df.replace([np.inf, -np.inf], 0, inplace=True)
    combined_df.fillna(0, inplace=True)

    # Save
    mode = 'a' if args.append else 'w'
    header = not args.append
    combined_df.to_csv(args.output, mode=mode, header=header, index=False)

    print(f"\nSaved {len(combined_df)} flows to {args.output}")
    print(f"Label distribution:")
    print(combined_df['Label'].value_counts())

    return 0

if __name__ == '__main__':
    sys.exit(main())
