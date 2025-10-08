#!/usr/bin/env python3
"""
Validate trained model on newly collected data to prove real-world generalization.
"""

import pandas as pd
import joblib
import sys
from pathlib import Path
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Paths
BASE_DIR = Path(__file__).parent.parent
MODEL_PATH = BASE_DIR / "models" / "firewall_classifier.pkl"

# Feature columns
FEATURE_COLUMNS = [
    'avg_latency', 'packet_loss', 'ttl_return', 'icmp_reachable',
    'filtered_ports_count', 'scan_time', 'syn_ack_ratio', 'tcp_reset_ratio',
    'response_time', 'header_modified'
]

# Firewall type mapping
FIREWALL_TYPES = {
    0: "No Firewall",
    1: "Stateless",
    2: "Stateful",
    3: "Proxy"
}


def load_model():
    """Load trained model."""
    if not MODEL_PATH.exists():
        print(f"[!] Error: Model not found at {MODEL_PATH}")
        print("    Please run 'python src/train_model.py' first")
        sys.exit(1)
    
    print(f"[+] Loading model from {MODEL_PATH}")
    return joblib.load(MODEL_PATH)


def validate_on_new_data(model, new_data_path):
    """Validate model on newly collected data."""
    print(f"\n[+] Loading new validation data from {new_data_path}")
    
    try:
        df = pd.read_csv(new_data_path)
    except FileNotFoundError:
        print(f"[!] Error: File not found: {new_data_path}")
        sys.exit(1)
    
    print(f"    Total samples: {len(df)}")
    
    # Check if labels exist (for validation) or not (for prediction only)
    has_labels = 'firewall_label' in df.columns
    
    if has_labels:
        print("\n[+] Labels found - Running validation")
        X_new = df[FEATURE_COLUMNS]
        y_true = df['firewall_label']
        
        # Predict
        y_pred = model.predict(X_new)
        
        # Calculate accuracy
        accuracy = accuracy_score(y_true, y_pred)
        print(f"\n    Validation Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        
        # Show classification report
        print("\n[+] Classification Report:")
        print(classification_report(
            y_true, y_pred,
            target_names=[FIREWALL_TYPES[i] for i in sorted(FIREWALL_TYPES.keys())],
            digits=4
        ))
        
        # Show confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        print("[+] Confusion Matrix:")
        print(f"    Predicted →")
        print(f"    {'True ↓':<15} {' '.join([f'{FIREWALL_TYPES[i][:8]:<10}' for i in range(4)])}")
        for i, row in enumerate(cm):
            print(f"    {FIREWALL_TYPES[i]:<15} {' '.join([f'{val:<10}' for val in row])}")
        
        # Check for misclassifications
        misclassified = (y_true != y_pred).sum()
        if misclassified == 0:
            print("\n    ✓ Perfect classification on new data!")
            print("    ✓ Model generalizes well to unseen samples")
        else:
            print(f"\n    Misclassified: {misclassified}/{len(df)} samples")
            
            # Show misclassified samples
            print("\n[+] Misclassified Samples:")
            misclass_df = df[y_true != y_pred].copy()
            misclass_df['predicted'] = y_pred[y_true != y_pred]
            misclass_df['true_label_name'] = misclass_df['firewall_label'].map(FIREWALL_TYPES)
            misclass_df['pred_label_name'] = misclass_df['predicted'].map(FIREWALL_TYPES)
            
            print(misclass_df[['host', 'true_label_name', 'pred_label_name'] + FEATURE_COLUMNS].to_string())
        
    else:
        print("\n[+] No labels found - Running prediction only")
        X_new = df[FEATURE_COLUMNS]
        
        # Predict
        y_pred = model.predict(X_new)
        
        # Add predictions to dataframe
        df['predicted_label'] = y_pred
        df['predicted_type'] = df['predicted_label'].map(FIREWALL_TYPES)
        
        print("\n[+] Predictions:")
        print(df[['host', 'predicted_label', 'predicted_type'] + FEATURE_COLUMNS].to_string())
        
        # Save predictions
        output_path = Path(new_data_path).parent / f"{Path(new_data_path).stem}_predictions.csv"
        df.to_csv(output_path, index=False)
        print(f"\n[+] Predictions saved to {output_path}")


def main():
    """Main validation pipeline."""
    print("=" * 70)
    print("  AI FIREWALL CLASSIFICATION - MODEL VALIDATION")
    print("=" * 70)
    
    # Check if new data path provided
    if len(sys.argv) < 2:
        print("\nUsage: python src/validate_model.py <path_to_new_data.csv>")
        print("\nExample:")
        print("  python src/validate_model.py data/raw/test.csv")
        print("\nTo collect new validation data:")
        print("  python src/data_collector.py --targets 192.168.56.11 192.168.56.12 192.168.56.13 --repeat 20 --output validation_data.csv")
        sys.exit(1)
    
    new_data_path = sys.argv[1]
    
    # Load model
    model = load_model()
    
    # Validate on new data
    validate_on_new_data(model, new_data_path)
    
    print("\n" + "=" * 70)
    print("  VALIDATION COMPLETE!")
    print("=" * 70)


if __name__ == "__main__":
    main()
