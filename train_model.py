#!/usr/bin/env python3
"""
Train LSTM Autoencoder for network intrusion detection

This script trains a model using YOUR feature extraction, ensuring 100% compatibility
with network_monitor.py during inference.
"""

import sys
import argparse
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import matplotlib.pyplot as plt

def load_data(csv_file):
    """Load feature CSV file"""
    print(f"Loading data from {csv_file}...")
    df = pd.read_csv(csv_file)

    # Separate features and labels
    X = df.drop('Label', axis=1)
    y = df['Label']

    print(f"Loaded {len(df)} samples")
    print(f"Features: {X.shape[1]}")
    print(f"Label distribution:")
    print(y.value_counts())

    return X, y

def prepare_data(X, y, n_features=30, test_size=0.2):
    """
    Prepare data for training:
    1. Feature selection (78 -> 30)
    2. Normalization
    3. Train/test split
    """
    print(f"\nPreparing data...")
    print(f"Original features: {X.shape[1]}")

    # Convert labels to binary (1=BENIGN, 0=ATTACK)
    y_binary = (y == 'BENIGN').astype(int)

    # Feature selection: Select top k features
    print(f"Selecting top {n_features} features...")
    selector = SelectKBest(f_classif, k=n_features)
    X_selected = selector.fit_transform(X, y_binary)

    print(f"Selected features: {X_selected.shape[1]}")

    # Get selected feature names
    feature_mask = selector.get_support()
    selected_features = X.columns[feature_mask].tolist()
    print(f"Selected feature names (first 10): {selected_features[:10]}")

    # Split data - stratify by label
    X_train, X_test, y_train, y_test = train_test_split(
        X_selected, y_binary, test_size=test_size, random_state=42, stratify=y_binary
    )

    print(f"\nTrain set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")

    # Normalize features
    print("Normalizing features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print(f"Scaler mean (first 5): {scaler.mean_[:5]}")
    print(f"Scaler std (first 5): {scaler.scale_[:5]}")

    return X_train_scaled, X_test_scaled, y_train, y_test, scaler, selector, selected_features

def create_sequences(X, y, window_size=5):
    """
    Create sequences for LSTM

    Args:
        X: Feature array
        y: Labels
        window_size: Number of flows in each sequence

    Returns:
        X_sequences, y_sequences
    """
    print(f"\nCreating sequences with window size {window_size}...")

    X_sequences = []
    y_sequences = []

    for i in range(len(X) - window_size + 1):
        X_sequences.append(X[i:i+window_size])
        # Label sequence as benign only if ALL flows are benign
        y_sequences.append(int(np.all(y.iloc[i:i+window_size] == 1)))

    X_sequences = np.array(X_sequences)
    y_sequences = np.array(y_sequences)

    print(f"Created {len(X_sequences)} sequences")
    print(f"Sequence shape: {X_sequences.shape}")
    print(f"Benign sequences: {np.sum(y_sequences)}")
    print(f"Attack sequences: {len(y_sequences) - np.sum(y_sequences)}")

    return X_sequences, y_sequences

def build_lstm_autoencoder(window_size, n_features, encoding_dim=16):
    """
    Build LSTM Autoencoder model

    Architecture:
    - Encoder: LSTM layers that compress the sequence
    - Decoder: LSTM layers that reconstruct the sequence
    """
    print(f"\nBuilding LSTM Autoencoder...")
    print(f"Input shape: ({window_size}, {n_features})")
    print(f"Encoding dimension: {encoding_dim}")

    # Encoder
    encoder_inputs = layers.Input(shape=(window_size, n_features))
    encoder = layers.LSTM(64, activation='relu', return_sequences=True)(encoder_inputs)
    encoder = layers.LSTM(32, activation='relu', return_sequences=False)(encoder)
    encoder = layers.Dense(encoding_dim, activation='relu')(encoder)

    # Decoder
    decoder = layers.RepeatVector(window_size)(encoder)
    decoder = layers.LSTM(32, activation='relu', return_sequences=True)(decoder)
    decoder = layers.LSTM(64, activation='relu', return_sequences=True)(decoder)
    decoder_outputs = layers.TimeDistributed(layers.Dense(n_features))(decoder)

    # Autoencoder model
    autoencoder = keras.Model(encoder_inputs, decoder_outputs)

    autoencoder.compile(optimizer='adam', loss='mse', metrics=['mae'])

    print(autoencoder.summary())

    return autoencoder

def train_model(model, X_train, X_test, y_train, y_test, epochs=50, batch_size=32):
    """
    Train the autoencoder on BENIGN data only

    The model learns to reconstruct normal traffic patterns.
    Attack traffic will have high reconstruction error.
    """
    print(f"\nTraining model...")

    # Train only on BENIGN sequences
    X_train_benign = X_train[y_train == 1]
    X_test_benign = X_test[y_test == 1]

    print(f"Training on {len(X_train_benign)} benign sequences")
    print(f"Validating on {len(X_test_benign)} benign sequences")

    # Early stopping
    early_stop = keras.callbacks.EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True
    )

    # Train
    history = model.fit(
        X_train_benign, X_train_benign,
        epochs=epochs,
        batch_size=batch_size,
        validation_data=(X_test_benign, X_test_benign),
        callbacks=[early_stop],
        verbose=1
    )

    return history

def calculate_threshold(model, X_train_benign, percentile=95):
    """
    Calculate anomaly threshold as 95th percentile of benign reconstruction errors
    """
    print(f"\nCalculating threshold...")

    # Get reconstruction errors for benign data
    reconstructions = model.predict(X_train_benign, verbose=0)
    mse = np.mean(np.square(X_train_benign - reconstructions), axis=(1, 2))

    # Calculate threshold
    threshold = np.percentile(mse, percentile)

    print(f"Benign reconstruction errors:")
    print(f"  Min: {np.min(mse):.4f}")
    print(f"  Max: {np.max(mse):.4f}")
    print(f"  Mean: {np.mean(mse):.4f}")
    print(f"  Median: {np.median(mse):.4f}")
    print(f"  {percentile}th percentile: {threshold:.4f}")

    return threshold

def evaluate_model(model, X_test, y_test, threshold):
    """
    Evaluate model on test data
    """
    print(f"\nEvaluating model...")

    # Get reconstruction errors
    reconstructions = model.predict(X_test, verbose=0)
    mse = np.mean(np.square(X_test - reconstructions), axis=(1, 2))

    # Predict: 1 if error > threshold (ATTACK), 0 otherwise (BENIGN)
    y_pred = (mse > threshold).astype(int)
    y_true = (y_test == 0).astype(int)  # Convert to 1=ATTACK, 0=BENIGN

    # Calculate metrics
    tp = np.sum((y_pred == 1) & (y_true == 1))  # Attacks correctly detected
    fp = np.sum((y_pred == 1) & (y_true == 0))  # Benign flagged as attack
    tn = np.sum((y_pred == 0) & (y_true == 0))  # Benign correctly classified
    fn = np.sum((y_pred == 0) & (y_true == 1))  # Attacks missed

    accuracy = (tp + tn) / len(y_test)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\nTest Results:")
    print(f"  Accuracy: {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall: {recall:.4f}")
    print(f"  F1-Score: {f1:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"  True Positives (Attacks detected): {tp}")
    print(f"  False Positives (False alarms): {fp}")
    print(f"  True Negatives (Benign correct): {tn}")
    print(f"  False Negatives (Attacks missed): {fn}")

    # Reconstruction error distribution
    benign_errors = mse[y_test == 1]
    attack_errors = mse[y_test == 0]

    print(f"\nReconstruction Error Distribution:")
    print(f"  Benign - Mean: {np.mean(benign_errors):.4f}, Std: {np.std(benign_errors):.4f}")
    print(f"  Attack - Mean: {np.mean(attack_errors):.4f}, Std: {np.std(attack_errors):.4f}")

    return accuracy, precision, recall, f1

def save_model(model, scaler, selector, threshold, selected_features, output_dir='.'):
    """
    Save model, scaler, selector, and metadata
    """
    print(f"\nSaving model to {output_dir}...")

    # Save model
    model.save(f'{output_dir}/lstm_autoencoder.h5')
    print("  ✓ Saved lstm_autoencoder.h5")

    # Save scaler
    joblib.dump(scaler, f'{output_dir}/scaler.pkl')
    print("  ✓ Saved scaler.pkl")

    # Save selector
    joblib.dump(selector, f'{output_dir}/selector.pkl')
    print("  ✓ Saved selector.pkl")

    # Save metadata
    metadata = {
        'model_type': 'LSTM_autoencoder',
        'model_file': 'lstm_autoencoder.h5',
        'framework': 'TensorFlow',
        'tensorflow_version': tf.__version__,
        'scikit_learn_version': '1.5.2',
        'selected_features': selected_features,
        'feature_order': selected_features,
        'window_size': model.input_shape[1],
        'sequence_stride': 1,
        'threshold': float(threshold),
        'threshold_method': '95th_percentile_benign',
        'label_map': {'1': 'BENIGN', '-1': 'ATTACK'},
        'notes': 'Trained using extract_features_from_pcap.py - 100% compatible with network_monitor.py'
    }

    with open(f'{output_dir}/metadata.json', 'w') as f:
        json.dump(metadata, f, indent=4)
    print("  ✓ Saved metadata.json")

    # Save feature order
    with open(f'{output_dir}/feature_order.txt', 'w') as f:
        for feat in selected_features:
            f.write(f"{feat}\n")
    print("  ✓ Saved feature_order.txt")

def main():
    parser = argparse.ArgumentParser(description='Train LSTM Autoencoder for NIDS')
    parser.add_argument('csv_file', help='CSV file with extracted features')
    parser.add_argument('--features', type=int, default=30, help='Number of features to select')
    parser.add_argument('--window-size', type=int, default=5, help='Sequence window size')
    parser.add_argument('--epochs', type=int, default=50, help='Training epochs')
    parser.add_argument('--batch-size', type=int, default=32, help='Batch size')
    parser.add_argument('--encoding-dim', type=int, default=16, help='Encoding dimension')
    parser.add_argument('--threshold-percentile', type=int, default=95, help='Threshold percentile')
    parser.add_argument('--output-dir', default='.', help='Output directory for model files')

    args = parser.parse_args()

    # Load data
    X, y = load_data(args.csv_file)

    # Prepare data
    X_train, X_test, y_train, y_test, scaler, selector, selected_features = prepare_data(
        X, y, n_features=args.features
    )

    # Create sequences
    X_train_seq, y_train_seq = create_sequences(
        pd.DataFrame(X_train), y_train.reset_index(drop=True), args.window_size
    )
    X_test_seq, y_test_seq = create_sequences(
        pd.DataFrame(X_test), y_test.reset_index(drop=True), args.window_size
    )

    # Build model
    model = build_lstm_autoencoder(args.window_size, args.features, args.encoding_dim)

    # Train
    history = train_model(
        model, X_train_seq, X_test_seq, y_train_seq, y_test_seq,
        epochs=args.epochs, batch_size=args.batch_size
    )

    # Calculate threshold
    X_train_benign = X_train_seq[y_train_seq == 1]
    threshold = calculate_threshold(model, X_train_benign, args.threshold_percentile)

    # Evaluate
    evaluate_model(model, X_test_seq, y_test_seq, threshold)

    # Save
    save_model(model, scaler, selector, threshold, selected_features, args.output_dir)

    print("\n" + "="*80)
    print("Training complete!")
    print("="*80)
    print(f"Model saved to: {args.output_dir}")
    print(f"Threshold: {threshold:.6f}")
    print("\nYou can now use this model with network_monitor.py")
    print("The feature extraction is 100% compatible!")

    return 0

if __name__ == '__main__':
    sys.exit(main())
