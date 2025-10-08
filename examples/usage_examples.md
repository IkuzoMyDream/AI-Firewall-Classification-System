# Usage Examples

## Quick Start

### 1. Classify a Single Host

```bash
python src/classify.py 192.168.56.13
```

**Output:**
```
======================================================================
  Classification Result
======================================================================

  Target IP:       192.168.56.13
  Firewall Type:   Proxy
  Label:           3
  Confidence:      100.00%

  Key Features:
    avg_latency:         0.297 ms
    packet_loss:         0.0%
    icmp_reachable:      1
    filtered_ports:      0
    scan_time:           0.34 s
    syn_ack_ratio:       1.00
    tcp_reset_ratio:     1.00
    response_time:       0.36 ms
    header_modified:     1

======================================================================
```

---

### 2. Classify Multiple Hosts

```bash
python src/classify.py 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.13
```

**Output:**
```
======================================================================
  Classification Summary
======================================================================

  IP Address         Firewall Type      Label    Confidence  
  ------------------ ------------------ -------- ------------
  192.168.56.10      No Firewall        0        100.00%
  192.168.56.11      Stateless          1        100.00%
  192.168.56.12      Stateful           2        100.00%
  192.168.56.13      Proxy              3        100.00%

======================================================================
```

---

### 3. Classify with Debug Output

```bash
python src/classify.py 192.168.56.13 --debug
```

Shows detailed command output from ping, nmap, hping3, and curl.

---

### 4. Collect Training Data

```bash
# Collect 250 samples per VM (1000 total)
python src/data_collector.py \
  --targets 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.13 \
  --label-map 192.168.56.10:0 192.168.56.11:1 192.168.56.12:2 192.168.56.13:3 \
  --repeat 250 \
  --output data/processed/dataset.csv
```

---

### 5. Train Model

```bash
python src/train_model.py
```

**Generates:**
- `models/firewall_classifier.pkl` - Trained model
- `results/metrics/metrics.json` - Performance metrics
- `results/confusion_matrices/confusion_matrix.png` - Confusion matrix
- `results/metrics/feature_importance.png` - Feature importance plot
- `results/metrics/learning_curve.png` - Learning curve

---

### 6. Validate Model on New Data

```bash
# Collect fresh data
python src/data_collector.py \
  --targets 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.13 \
  --repeat 20 \
  --output validation_data.csv

# Validate
python src/validate_model.py validation_data.csv
```

**Output:**
```
Validation Accuracy: 1.0000 (100.00%)
✓ Perfect classification on new data!
✓ Model generalizes well to unseen samples
```

---

## Common Issues

### Issue: "Operation not permitted" with hping3

**Solution:**
```bash
sudo setcap cap_net_raw+ep $(which hping3)
```

### Issue: "Module not found: joblib"

**Solution:**
```bash
pip install -r requirements.txt
```

### Issue: Wrong predictions

**Cause:** VMs' firewall configuration changed since training.

**Solution:** Re-collect data and retrain model.
