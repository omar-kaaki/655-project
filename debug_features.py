#!/usr/bin/env python3
"""Debug script to inspect feature extraction and values"""
import json
import pickle
import joblib
import numpy as np

print("=" * 80)
print("Feature Pipeline Debug")
print("=" * 80)

# Load metadata
with open('metadata.json', 'r') as f:
    metadata = json.load(f)

print(f"\n1. Metadata:")
print(f"   - Window size: {metadata['window_size']}")
print(f"   - Threshold: {metadata['threshold']}")
print(f"   - Number of features: {len(metadata['feature_order'])}")

# Load scaler
print(f"\n2. Loading scaler...")
scaler = joblib.load('scaler.pkl')
print(f"   - Scaler type: {type(scaler).__name__}")
print(f"   - Expected input shape: {scaler.n_features_in_ if hasattr(scaler, 'n_features_in_') else 'unknown'}")
if hasattr(scaler, 'mean_'):
    print(f"   - Scaler mean shape: {scaler.mean_.shape}")
    print(f"   - Scaler scale shape: {scaler.scale_.shape}")

# Load selector
print(f"\n3. Loading selector...")
selector = joblib.load('selector.pkl')
print(f"   - Selector type: {type(selector).__name__}")
if hasattr(selector, 'n_features_in_'):
    print(f"   - Expected input features: {selector.n_features_in_}")
if hasattr(selector, 'get_support'):
    selected_mask = selector.get_support()
    print(f"   - Number of features selected: {np.sum(selected_mask)}")
    print(f"   - Selection mask shape: {selected_mask.shape}")

# Check if selector actually selects features or passes all through
if hasattr(selector, 'get_support'):
    if np.all(selected_mask):
        print(f"   ⚠️  WARNING: Selector selects ALL features (identity transform)")
    else:
        print(f"   - Selector reduces from {len(selected_mask)} to {np.sum(selected_mask)} features")

# Test with dummy data
print(f"\n4. Testing pipeline with dummy 30-feature input:")
dummy_features = np.random.randn(1, 30)  # 1 sample, 30 features
print(f"   - Input shape: {dummy_features.shape}")

try:
    # Try selector first
    if hasattr(selector, 'transform'):
        selected = selector.transform(dummy_features)
        print(f"   - After selector: {selected.shape}")

        # Then scaler
        scaled = scaler.transform(selected)
        print(f"   - After scaler: {scaled.shape}")
        print(f"   ✓ Pipeline works: 30 features → {selected.shape[1]} features → {scaled.shape[1]} features")
except Exception as e:
    print(f"   ✗ ERROR in pipeline: {e}")

try:
    # Try scaler directly (current buggy behavior)
    scaled_direct = scaler.transform(dummy_features)
    print(f"\n5. Current code (scaler without selector):")
    print(f"   - Direct scaler output shape: {scaled_direct.shape}")
    if hasattr(scaler, 'n_features_in_'):
        expected = scaler.n_features_in_
        if expected != 30:
            print(f"   ✗ ERROR: Scaler expects {expected} features but we're giving it 30!")
        else:
            print(f"   ✓ Scaler input dimension matches")
except Exception as e:
    print(f"   ✗ ERROR with direct scaler: {e}")

print("\n" + "=" * 80)
print("DIAGNOSIS:")
print("=" * 80)
print("If you see dimension mismatches above, the issue is:")
print("1. The selector needs to be applied BEFORE the scaler")
print("2. The processing pipeline should be:")
print("   features_array → selector.transform() → scaler.transform() → model")
print("\nCurrently the code does:")
print("   features_array → scaler.transform() → model")
print("   (selector is never used!)")
print("=" * 80)
