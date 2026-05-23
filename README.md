# Network Intrusion Detection System (IDS/IPS)

Multi-class real-time IDS/IPS that captures live network traffic, extracts rich per-packet and flow-level features, and runs a TensorFlow deep learning classifier to detect and categorize network attacks. Includes a real-time web dashboard, PCAP replay for offline analysis, and optional IPS blocking hooks.

## Attack Classes

| Label | Class | Description |
|-------|-------|-------------|
| 0 | Normal | Benign traffic |
| 1 | Port Scan | SYN probes to suspicious ports |
| 2 | DDoS | Volumetric floods and SYN floods |
| 3 | Brute Force | Repeated auth port connections |
| 4 | Exfiltration | Large encrypted outbound transfers |

## Features

- **30-feature vector**: packet-level (size, ports, flags, TTL, entropy) + flow-level (duration, rates, IAT stats)
- **Multi-class classification**: 5 attack categories with per-class confidence scores
- **Deep neural network**: 128→64→32 with BatchNorm, Dropout, early stopping, LR scheduling
- **Flow tracking**: bidirectional 5-tuple flows with automatic expiry
- **Real-time web dashboard**: glassmorphism dark theme, WebSocket live alerts, Chart.js visualisations
- **PCAP replay**: offline analysis of captured traffic files
- **Model evaluation**: precision/recall/F1, confusion matrix, ROC-AUC
- **Optional IPS blocking**: configurable per-class firewall actions via `netsh`

## Tech Stack

- Python 3.10/3.11
- TensorFlow 2.15
- Scapy (packet capture & parsing)
- FastAPI + Uvicorn (dashboard)
- scikit-learn + matplotlib (evaluation)
- pytest (testing)

## Requirements

- Windows: Npcap installed (for Scapy sniffing)
- Python 3.10 or 3.11 (TensorFlow 2.15 does not support Python 3.13)

## Quick Start

Install dependencies:
```powershell
pip install -r requirements.txt
```

Train a model:
```powershell
python src\train.py --model-out models\ids_model
```

Run realtime IDS with dashboard:
```powershell
python src\run_ids.py --config configs\default.yaml
```

Open the dashboard at `http://localhost:8080`.

## Training Options

Train with default synthetic data (10,000 samples, 30 epochs):
```powershell
python src\train.py
```

Train from a CSV dataset:
```powershell
python src\train.py --csv data\your_dataset.csv --model-out models\ids_model
```

Generate and export a synthetic CSV:
```powershell
python src\train.py --export-csv data\sample_ids.csv --synthetic-samples 10000
```

Advanced training options:
```powershell
python src\train.py --epochs 50 --batch-size 128 --lr 0.0005 --patience 10
```

## Model Evaluation

Evaluate an existing model on a test dataset:
```powershell
python src\evaluate.py --model models\ids_model --csv data\sample_ids.csv
```

This produces:
- Per-class precision/recall/F1 report (console)
- Confusion matrix image (`logs/confusion_matrix.png`)
- JSON report (`logs/evaluation_report.json`)

## PCAP Replay (Offline Analysis)

Analyse a captured PCAP file:
```powershell
python src\run_ids.py --pcap data\capture.pcap
```

Save results to CSV:
```powershell
python src\run_ids.py --pcap data\capture.pcap --output-csv logs\results.csv
```

## Configuration

Default config: `configs\default.yaml`

| Section | Key | Description | Default |
|---------|-----|-------------|---------|
| `capture` | `interface` | Network interface | auto |
| `capture` | `bpf_filter` | BPF filter | `ip` |
| `capture` | `packet_limit` | Stop after N packets (0=unlimited) | `0` |
| `model` | `path` | Model directory | `models/ids_model` |
| `model` | `threshold` | Classification threshold | `0.6` |
| `model` | `num_classes` | Number of attack classes | `5` |
| `actions` | `enable_blocking` | Enable IPS firewall blocking | `false` |
| `dashboard` | `enabled` | Start web dashboard | `true` |
| `dashboard` | `port` | Dashboard HTTP port | `8080` |
| `logging` | `path` | Log file path | `logs/ids.log` |

## Project Structure

```
src/
  ids/
    actions.py           # IPS blocking hooks
    capture.py           # Live packet capture (Scapy)
    config.py            # YAML config dataclasses
    dashboard/
      __init__.py
      server.py          # FastAPI dashboard server
      static/
        index.html       # Dashboard UI
        style.css        # Glassmorphism dark theme
        app.js           # WebSocket + Chart.js frontend
    feature_extraction.py # 30-feature vector extraction
    flow_tracker.py      # Bidirectional flow state tracking
    inference.py         # Detection pipeline
    model.py             # TensorFlow multi-class classifier
    realtime.py          # Real-time capture + detection loop
    replay.py            # PCAP file replay
  run_ids.py             # CLI: live capture or PCAP replay
  train.py               # CLI: training + synthetic data gen
  evaluate.py            # CLI: model evaluation & metrics
tests/
  conftest.py
  test_actions.py
  test_config.py
  test_feature_extraction.py
  test_flow_tracker.py
  test_inference.py
  test_model.py
configs/
  default.yaml
models/
data/
```

## Running Tests

```powershell
pytest tests/ -v --cov=src/ids
```

## Notes

- IDS/IPS actions default to logging. Enabling firewall actions requires admin privileges.
- The dashboard starts automatically with live capture. Disable with `dashboard.enabled: false`.
- The existing trained model is incompatible with the upgraded feature set — retrain after upgrading.
- For Windows firewall blocking, `netsh` is used via `actions.block_command_template`.

## Troubleshooting

- If `tensorflow` fails to install, ensure you are on Python 3.10/3.11.
- If capture fails, verify Npcap installation and run the terminal with admin privileges.
- If the dashboard fails to start, install `fastapi` and `uvicorn`: `pip install fastapi uvicorn[standard]`.

## License

Add your license information here.
