#!/usr/bin/env python3
"""
Real-time firewall classification for unknown hosts.
Collects features and predicts firewall type using trained model.
"""

import sys
import joblib
import pandas as pd
from pathlib import Path
from data_collector import collect_features, FEATURE_COLUMNS

# Paths
BASE_DIR = Path(__file__).parent.parent
MODEL_PATH = BASE_DIR / "models" / "firewall_classifier.pkl"

# Firewall type mapping
FIREWALL_TYPES = {
    0: "No Firewall",
    1: "Stateless",
    2: "Stateful",
    3: "Proxy"
}

# Color codes for output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def load_model():
    """Load trained model."""
    if not MODEL_PATH.exists():
        print(f"{Colors.RED}[!] Error: Model not found at {MODEL_PATH}{Colors.ENDC}")
        print(f"    Please run 'python src/train_model.py' first to train the model")
        sys.exit(1)
    
    return joblib.load(MODEL_PATH)


def classify_host(model, target_ip, debug=False):
    """Classify a single host."""
    print(f"\n{Colors.BLUE}[+] Collecting features from {target_ip}...{Colors.ENDC}")
    
    # Collect features
    features = collect_features(target_ip, debug=debug)
    
    if not features:
        print(f"{Colors.RED}[!] Failed to collect features from {target_ip}{Colors.ENDC}")
        return None
    
    # Feature columns used by model (excluding timestamp, host, and label)
    model_features = [
        'avg_latency', 'packet_loss', 'ttl_return', 'icmp_reachable',
        'filtered_ports_count', 'scan_time', 'syn_ack_ratio', 'tcp_reset_ratio',
        'response_time', 'header_modified'
    ]
    
    # Prepare features for prediction
    feature_values = [features[col] for col in model_features]
    feature_df = pd.DataFrame([feature_values], columns=model_features)
    
    # Predict
    prediction = model.predict(feature_df)[0]
    probabilities = model.predict_proba(feature_df)[0]
    confidence = probabilities[prediction] * 100
    
    return {
        'ip': target_ip,
        'prediction': int(prediction),
        'firewall_type': FIREWALL_TYPES[prediction],
        'confidence': confidence,
        'features': features
    }


def print_result(result):
    """Print classification result in a nice format."""
    if not result:
        return
    
    # Color based on firewall type
    type_colors = {
        0: Colors.GREEN,   # No Firewall
        1: Colors.YELLOW,  # Stateless
        2: Colors.BLUE,    # Stateful
        3: Colors.RED      # Proxy
    }
    
    color = type_colors[result['prediction']]
    
    print(f"\n{'='*70}")
    print(f"{Colors.BOLD}  Classification Result{Colors.ENDC}")
    print(f"{'='*70}")
    print(f"\n  Target IP:       {Colors.BOLD}{result['ip']}{Colors.ENDC}")
    print(f"  Firewall Type:   {color}{Colors.BOLD}{result['firewall_type']}{Colors.ENDC}")
    print(f"  Label:           {color}{Colors.BOLD}{result['prediction']}{Colors.ENDC}")
    print(f"  Confidence:      {Colors.BOLD}{result['confidence']:.2f}%{Colors.ENDC}")
    
    # Show key features
    features = result['features']
    print(f"\n  Key Features:")
    print(f"    avg_latency:         {features['avg_latency']:.3f} ms")
    print(f"    packet_loss:         {features['packet_loss']:.1f}%")
    print(f"    icmp_reachable:      {features['icmp_reachable']}")
    print(f"    filtered_ports:      {features['filtered_ports_count']}")
    print(f"    scan_time:           {features['scan_time']:.2f} s")
    print(f"    syn_ack_ratio:       {features['syn_ack_ratio']:.2f}")
    print(f"    tcp_reset_ratio:     {features['tcp_reset_ratio']:.2f}")
    print(f"    response_time:       {features['response_time']:.2f} ms")
    print(f"    header_modified:     {features['header_modified']}")
    
    print(f"\n{'='*70}\n")


def print_summary_table(results):
    """Print summary table for multiple hosts."""
    print(f"\n{'='*70}")
    print(f"{Colors.BOLD}  Classification Summary{Colors.ENDC}")
    print(f"{'='*70}\n")
    
    # Table header
    print(f"  {'IP Address':<18} {'Firewall Type':<18} {'Label':<8} {'Confidence':<12}")
    print(f"  {'-'*18} {'-'*18} {'-'*8} {'-'*12}")
    
    # Table rows
    type_colors = {
        0: Colors.GREEN,   # No Firewall
        1: Colors.YELLOW,  # Stateless
        2: Colors.BLUE,    # Stateful
        3: Colors.RED      # Proxy
    }
    
    for result in results:
        if result:
            color = type_colors[result['prediction']]
            print(f"  {result['ip']:<18} "
                  f"{color}{result['firewall_type']:<18}{Colors.ENDC} "
                  f"{result['prediction']:<8} "
                  f"{result['confidence']:.2f}%")
    
    print(f"\n{'='*70}\n")


def main():
    """Main classification pipeline."""
    print(f"{Colors.BOLD}{'='*70}")
    print(f"  AI FIREWALL CLASSIFICATION - REAL-TIME CLASSIFIER")
    print(f"{'='*70}{Colors.ENDC}")
    
    # Check arguments
    if len(sys.argv) < 2:
        print(f"\n{Colors.YELLOW}Usage:{Colors.ENDC} python src/classify.py <target_ip> [target_ip2] [target_ip3] ... [--debug]")
        print(f"\n{Colors.YELLOW}Examples:{Colors.ENDC}")
        print(f"  python src/classify.py 192.168.56.11")
        print(f"  python src/classify.py 192.168.56.11 192.168.56.12 192.168.56.13")
        print(f"  python src/classify.py 10.0.1.10 --debug")
        print(f"\n{Colors.YELLOW}Firewall Types:{Colors.ENDC}")
        print(f"  0 - No Firewall")
        print(f"  1 - Stateless Firewall (iptables)")
        print(f"  2 - Stateful Firewall (ufw)")
        print(f"  3 - Proxy Firewall (Squid)")
        print()
        sys.exit(1)
    
    # Parse arguments
    debug = '--debug' in sys.argv
    targets = [arg for arg in sys.argv[1:] if arg != '--debug']
    
    # Load model
    print(f"\n{Colors.BLUE}[+] Loading trained model...{Colors.ENDC}")
    model = load_model()
    print(f"    Model loaded from {MODEL_PATH}")
    
    # Classify each target
    results = []
    for target in targets:
        result = classify_host(model, target, debug=debug)
        results.append(result)
    
    # Display results
    if len(results) == 1:
        # Single target - detailed output
        print_result(results[0])
    else:
        # Multiple targets - summary table
        print_summary_table(results)
        
        # Option to show details
        print(f"{Colors.YELLOW}Tip:{Colors.ENDC} Run with single IP for detailed feature analysis")
        print(f"      Example: python src/classify.py {targets[0]}\n")


if __name__ == "__main__":
    main()
