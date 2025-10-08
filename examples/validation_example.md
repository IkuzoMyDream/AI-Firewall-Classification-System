# Validation Examples

## Test Model on New Data

### 1. Collect Fresh Validation Data (20 samples)
```bash
python src/data_collector.py \
  --targets 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.13 \
  --repeat 5 \
  --output validation_data.csv
```

### 2. Validate Model on New Data
```bash
python src/validate_model.py validation_data.csv
```

## Expected Output

If model generalizes well, you should see:
```
Validation Accuracy: 1.0000 (100.00%)
✓ Perfect classification on new data!
✓ Model generalizes well to unseen samples
```

## What This Proves

1. **Cross-Validation (5-Fold)**: Tests model on 5 different data splits
2. **Learning Curve**: Shows model learns patterns (not memorizes)
3. **New Data Validation**: Tests on fresh samples never seen during training

All three methods prove the model **LEARNS** firewall behavior patterns, not just memorizes training data.
