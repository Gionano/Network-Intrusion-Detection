# Network Intrusion Detection (Realtime IDS/IPS with ML)

Realtime IDS/IPS prototype that captures live traffic, extracts features, and runs a TensorFlow classifier to detect suspicious packets. Optional blocking hooks can be enabled for IPS behavior.

## Features
- Live packet capture with Scapy
- Lightweight feature extraction (protocol, ports, flags, sizes)
- TensorFlow binary classifier
- Optional IPS action hooks (log/block)
- Config-driven runtime

## Tech Stack
- Python 3.10/3.11
- TensorFlow 2.15
- Scapy

## Requirements
- Windows: Npcap installed (for Scapy sniffing)
- Python 3.10 or 3.11 (TensorFlow does not support Python 3.13 yet)

## Quick Start
Install dependencies:
```powershell
pip install -r requirements.txt
```

Train a model using synthetic data:
```powershell
python src\train.py --model-out models\ids_model
```

Run realtime IDS:
```powershell
python src\run_ids.py --config configs\default.yaml
```

## Training Options
Train from CSV:
```powershell
python src\train.py --csv data\your_dataset.csv --model-out models\ids_model
```

Generate a sample CSV dataset:
```powershell
python src\train.py --export-csv data\sample_ids.csv --synthetic-samples 5000
```

CSV must include all feature columns plus `label` (0 or 1). See `src\ids\feature_extraction.py` for the feature list and order.

## Configuration
Default config: `configs\default.yaml`
- `capture.interface`: network interface name (empty uses default)
- `capture.bpf_filter`: capture filter (default `ip`)
- `model.path`: model directory
- `model.threshold`: classification threshold
- `actions.enable_blocking`: enable IPS blocking
- `actions.block_command_template`: blocking command template
- `logging.path`: log file path

## Project Structure
```
src/
  ids/
    actions.py
    capture.py
    config.py
    feature_extraction.py
    inference.py
    model.py
    realtime.py
  run_ids.py
  train.py
configs/
  default.yaml
models/
data/
```

## Notes
- IDS/IPS actions default to logging. Enabling firewall actions may require admin privileges.
- Feature extraction is intentionally simple to keep the pipeline clear. Replace with richer features for production.
- For Windows firewall blocking, `netsh` is used via `actions.block_command_template`.

## Troubleshooting
- If `tensorflow` fails to install, ensure you are on Python 3.10/3.11.
- If capture fails, verify Npcap installation and run the terminal with admin privileges.

## License
Add your license information here.
