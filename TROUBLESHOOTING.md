# Troubleshooting High False Positives

## Problem

The NIDS shows reconstruction errors of **9000-15000** for benign traffic (should be < 2), resulting in 100% false positives.

## Root Cause

The model was trained using **CICFlowMeter Java tool** output, which has specific feature extraction methods. Our Python implementation from live packets doesn't match those exact calculations.

### Evidence
```
Expected benign error: 0.3 - 1.4
Actual benign error:   9000 - 15000 (6000x too high!)
```

This indicates our features are **fundamentally incompatible** with the trained model.

## Why Our Implementation Doesn't Match

1. **Feature Calculation Differences**:
   - CICFlowMeter uses Java libraries with specific rounding, overflow handling
   - Our Python numpy calculations might differ slightly
   - Timing precision differences (Java vs Python time handling)

2. **Unknown Feature Order**:
   - We guessed the 78-feature order from documentation
   - Actual CICFlowMeter output might use different order
   - Wrong order = selector picks wrong features

3. **Missing Implementation Details**:
   - Bulk transfer metrics (we set to 0)
   - Active/Idle time calculations (simplified)
   - Window size calculations
   - Subflow definitions

4. **Data Source Mismatch**:
   - Model trained on: Post-processed CSV files from completed PCAP
   - We're using: Live packet capture with real-time processing

## Solutions

### Solution 1: Use Actual CICFlowMeter Tool ⭐ RECOMMENDED

**Step 1**: Capture traffic to PCAP file
```bash
# Capture 5 minutes of traffic
sudo tcpdump -i any -w captured_traffic.pcap -G 300 -W 1
```

**Step 2**: Download CICFlowMeter
```bash
# From: https://github.com/ahlashkari/CICFlowMeter
wget https://github.com/ahlashkari/CICFlowMeter/releases/download/v4.0/CICFlowMeter-4.0.jar
```

**Step 3**: Process PCAP with CICFlowMeter
```bash
java -jar CICFlowMeter-4.0.jar captured_traffic.pcap output_flows.csv
```

**Step 4**: Feed CSV to model (requires modifying network_monitor.py to read CSV)

### Solution 2: Retrain Model with Our Features

If you have access to the training code:

1. Use our `network_monitor.py` feature extraction on CIC-IDS2017 PCAP files
2. Retrain the LSTM autoencoder with OUR features
3. This ensures training and inference use same feature extraction

### Solution 3: Use Threshold Adjustment (Temporary Workaround)

Since errors are ~10000x too high, try threshold of 10000-20000:

```bash
# Test with very high threshold
sudo ./run_monitor.sh --threshold 15000
```

**Caveat**: This is NOT a real solution - it just masks the incompatibility.

### Solution 4: Use Pre-trained Model with Matching Feature Extraction

Look for:
- A model trained specifically for Scapy-based capture
- A model with documented feature extraction code
- A model that includes the feature extraction pipeline

## Verifying the Fix

Once you implement Solution 1 or 2, you should see:

✅ **Benign traffic errors**: 0.3 - 1.4
✅ **Attack traffic errors**: 1.5 - 5.0
✅ **Detection rate**: 90%+ for known attacks
✅ **False positive rate**: < 5%

Currently you're seeing:
❌ **Benign traffic errors**: 9000 - 15000
❌ **Attack traffic errors**: (probably also 9000+)
❌ **Detection rate**: Cannot be measured (everything flagged)
❌ **False positive rate**: ~100%

## Technical Details

### Feature Extraction Mismatch Example

**Our calculation** (Flow Duration in microseconds):
```python
flow_duration_us = (last_time - start_time) * 1_000_000
```

**CICFlowMeter might do**:
```java
long flowDuration = (endTime.getTime() - startTime.getTime()) * 1000;
// Different precision, different handling of time objects
```

Even small differences accumulate across 78 features, leading to completely different inputs to the model.

### What the Model Sees

**During Training** (CICFlowMeter CSV):
```
Feature vector: [80, 451000, 54, 1460, ...]  # Specific CICFlowMeter calculations
```

**During Inference** (Our implementation):
```
Feature vector: [80, 450000, 55, 1500, ...]  # Slightly different values
```

After selector → scaler → LSTM, these small differences become huge reconstruction errors.

## Questions to Ask Your Instructor

1. Can I get the exact CICFlowMeter version and configuration used for training?
2. Are there sample CSV files showing the exact feature format?
3. Can I get the feature extraction code used during training?
4. Is there a pre-processing script that was used?
5. Can I retrain the model with my own feature extraction?

## Related Files

- `network_monitor.py` - Our feature extraction implementation
- `cicflowmeter_features.txt` - Our guessed feature order (78 features)
- `metadata.json` - Model configuration (30 selected features)
- `selector.pkl` - Feature selector (78 → 30)
- `scaler.pkl` - Feature scaler (trained on CICFlowMeter data)
- `lstm_autoencoder.h5` - LSTM model (trained on CICFlowMeter data)

## Last Updated
2025-11-15 - Documented fundamental incompatibility issue
