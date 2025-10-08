#!/usr/bin/env python3
"""
Train Random Forest classifier for firewall type detection.
"""

import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.model_selection import train_test_split, cross_val_score, learning_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support
)
import matplotlib.pyplot as plt
import seaborn as sns

# Paths
BASE_DIR = Path(__file__).parent.parent
DATA_PATH = BASE_DIR / "data" / "processed" / "dataset.csv"
MODEL_PATH = BASE_DIR / "models" / "firewall_classifier.pkl"
METRICS_DIR = BASE_DIR / "results" / "metrics"
CM_DIR = BASE_DIR / "results" / "confusion_matrices"

# Feature columns (excluding timestamp, host, and label)
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


def load_data():
    """Load and prepare dataset."""
    print(f"[+] Loading data from {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    
    print(f"    Total samples: {len(df)}")
    print(f"    Features: {len(FEATURE_COLUMNS)}")
    print(f"\n[+] Class distribution:")
    for label, count in df['firewall_label'].value_counts().sort_index().items():
        print(f"    {label} ({FIREWALL_TYPES[label]}): {count} samples")
    
    # Separate features and labels
    X = df[FEATURE_COLUMNS]
    y = df['firewall_label']
    
    return X, y, df


def train_model(X_train, y_train):
    """Train Random Forest classifier."""
    print("\n[+] Training Random Forest classifier...")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    print("    Training complete!")
    
    return model


def evaluate_model(model, X_test, y_test):
    """Evaluate model performance."""
    print("\n[+] Evaluating model...")
    
    # Predictions
    y_pred = model.predict(X_test)
    
    # Accuracy
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n    Overall Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    # Per-class metrics
    precision, recall, f1, support = precision_recall_fscore_support(
        y_test, y_pred, average=None, zero_division=0
    )
    
    print("\n    Per-Class Metrics:")
    print(f"    {'Class':<15} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'Support':<10}")
    print("    " + "-" * 65)
    
    for i, label in enumerate(sorted(y_test.unique())):
        class_name = FIREWALL_TYPES[label]
        print(f"    {class_name:<15} {precision[i]:<12.4f} {recall[i]:<12.4f} {f1[i]:<12.4f} {support[i]:<10.0f}")
    
    # Average metrics
    avg_precision, avg_recall, avg_f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average='weighted', zero_division=0
    )
    
    print(f"\n    Weighted Average:")
    print(f"    Precision: {avg_precision:.4f}")
    print(f"    Recall:    {avg_recall:.4f}")
    print(f"    F1-Score:  {avg_f1:.4f}")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    
    return {
        'accuracy': accuracy,
        'precision': avg_precision,
        'recall': avg_recall,
        'f1_score': avg_f1,
        'confusion_matrix': cm.tolist(),
        'per_class': {
            FIREWALL_TYPES[label]: {
                'precision': float(precision[i]),
                'recall': float(recall[i]),
                'f1_score': float(f1[i]),
                'support': int(support[i])
            }
            for i, label in enumerate(sorted(y_test.unique()))
        }
    }


def plot_confusion_matrix(cm, save_path):
    """Plot and save confusion matrix."""
    plt.figure(figsize=(10, 8))
    
    labels = [FIREWALL_TYPES[i] for i in sorted(FIREWALL_TYPES.keys())]
    
    sns.heatmap(
        cm, annot=True, fmt='d', cmap='Blues',
        xticklabels=labels, yticklabels=labels,
        cbar_kws={'label': 'Count'}
    )
    
    plt.title('Firewall Classification - Confusion Matrix', fontsize=14, fontweight='bold')
    plt.ylabel('True Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.tight_layout()
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"\n[+] Confusion matrix saved to {save_path}")
    plt.close()


def plot_feature_importance(model, save_path):
    """Plot and save feature importance."""
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    plt.figure(figsize=(12, 6))
    plt.title('Feature Importance', fontsize=14, fontweight='bold')
    plt.bar(range(len(FEATURE_COLUMNS)), importances[indices])
    plt.xticks(range(len(FEATURE_COLUMNS)), [FEATURE_COLUMNS[i] for i in indices], rotation=45, ha='right')
    plt.ylabel('Importance', fontsize=12)
    plt.xlabel('Feature', fontsize=12)
    plt.tight_layout()
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"[+] Feature importance saved to {save_path}")
    plt.close()
    
    # Print feature importance
    print("\n[+] Feature Importance Ranking:")
    for i, idx in enumerate(indices, 1):
        print(f"    {i}. {FEATURE_COLUMNS[idx]:<25} {importances[idx]:.4f}")


def cross_validate_model(model, X, y):
    """Perform cross-validation to prove model generalization."""
    print("\n[+] Running 5-Fold Cross-Validation...")
    print("    (Testing model on 5 different train/test splits)")
    
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    
    print(f"\n    Fold Accuracies: {[f'{score:.4f}' for score in cv_scores]}")
    print(f"    Mean Accuracy:   {cv_scores.mean():.4f}")
    print(f"    Std Deviation:   {cv_scores.std():.4f}")
    print(f"    Min Accuracy:    {cv_scores.min():.4f}")
    print(f"    Max Accuracy:    {cv_scores.max():.4f}")
    
    if cv_scores.mean() > 0.95:
        print("\n    ✓ Model shows excellent generalization (not memorizing)")
    
    return {
        'cv_scores': cv_scores.tolist(),
        'cv_mean': float(cv_scores.mean()),
        'cv_std': float(cv_scores.std()),
        'cv_min': float(cv_scores.min()),
        'cv_max': float(cv_scores.max())
    }


def plot_learning_curve(model, X, y, save_path):
    """Plot learning curve to show model learns patterns, not memorizes."""
    print("\n[+] Generating Learning Curve...")
    
    train_sizes, train_scores, test_scores = learning_curve(
        model, X, y, cv=5, n_jobs=-1,
        train_sizes=np.linspace(0.1, 1.0, 10),
        scoring='accuracy'
    )
    
    train_mean = np.mean(train_scores, axis=1)
    train_std = np.std(train_scores, axis=1)
    test_mean = np.mean(test_scores, axis=1)
    test_std = np.std(test_scores, axis=1)
    
    plt.figure(figsize=(10, 6))
    plt.title('Learning Curve - Proof of Generalization', fontsize=14, fontweight='bold')
    
    plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color='blue')
    plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color='red')
    
    plt.plot(train_sizes, train_mean, 'o-', color='blue', label='Training Score')
    plt.plot(train_sizes, test_mean, 'o-', color='red', label='Cross-Validation Score')
    
    plt.xlabel('Training Examples', fontsize=12)
    plt.ylabel('Accuracy', fontsize=12)
    plt.legend(loc='lower right', fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.ylim(0.8, 1.05)
    plt.tight_layout()
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"[+] Learning curve saved to {save_path}")
    plt.close()
    
    # Analysis
    gap = train_mean[-1] - test_mean[-1]
    print(f"\n    Training accuracy:        {train_mean[-1]:.4f}")
    print(f"    Cross-validation accuracy: {test_mean[-1]:.4f}")
    print(f"    Generalization gap:       {gap:.4f}")
    
    if gap < 0.05:
        print("    ✓ Small gap indicates good generalization (model learns, not memorizes)")
    
    return {
        'train_sizes': train_sizes.tolist(),
        'train_mean': train_mean.tolist(),
        'test_mean': test_mean.tolist(),
        'generalization_gap': float(gap)
    }


def save_model(model, path):
    """Save trained model."""
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    print(f"\n[+] Model saved to {path}")


def save_metrics(metrics, path):
    """Save evaluation metrics."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f"[+] Metrics saved to {path}")


def main():
    """Main training pipeline."""
    print("=" * 70)
    print("  AI FIREWALL CLASSIFICATION - MODEL TRAINING")
    print("=" * 70)
    
    # Load data
    X, y, df = load_data()
    
    # Split data
    print("\n[+] Splitting data: 80% train, 20% test")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"    Training samples: {len(X_train)}")
    print(f"    Testing samples:  {len(X_test)}")
    
    # Train model
    model = train_model(X_train, y_train)
    
    # Evaluate model
    metrics = evaluate_model(model, X_test, y_test)
    
    # Create output directories
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    CM_DIR.mkdir(parents=True, exist_ok=True)
    
    # Plot confusion matrix
    cm_path = CM_DIR / "confusion_matrix.png"
    plot_confusion_matrix(metrics['confusion_matrix'], cm_path)
    
    # Plot feature importance
    fi_path = METRICS_DIR / "feature_importance.png"
    plot_feature_importance(model, fi_path)
    
    # Cross-validation (proof of generalization)
    cv_metrics = cross_validate_model(model, X, y)
    metrics['cross_validation'] = cv_metrics
    
    # Learning curve (proof model learns, not memorizes)
    lc_path = METRICS_DIR / "learning_curve.png"
    lc_metrics = plot_learning_curve(model, X, y, lc_path)
    metrics['learning_curve'] = lc_metrics
    
    # Save model
    save_model(model, MODEL_PATH)
    
    # Save metrics
    metrics_path = METRICS_DIR / "metrics.json"
    save_metrics(metrics, metrics_path)
    
    print("\n" + "=" * 70)
    print("  TRAINING COMPLETE!")
    print("=" * 70)
    print(f"\n  Model:              {MODEL_PATH}")
    print(f"  Metrics:            {metrics_path}")
    print(f"  Confusion Matrix:   {cm_path}")
    print(f"  Feature Importance: {fi_path}")
    print(f"  Learning Curve:     {lc_path}")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
