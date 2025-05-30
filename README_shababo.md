# UDP Hole Punching & QUIC Demo (Internal)

This repo demonstrates UDP hole punching and QUIC connectivity testing between local and Modal (cloud) environments.

## Quick Start

### 1. Install Requirements
- Python 3.11+
- [Modal](https://modal.com/) CLI installed and logged in
- (Optional) jq for CSV post-processing
- Install jq: `brew install jq` (macOS) or `sudo apt-get install jq` (Linux)

### 2. Run Automated Tests

```bash
bash run_holepunch_tests.sh 5
```
- Runs 5 local and 5 remote hole punching/QUIC tests.
- Results are saved in `holepunch_results/<timestamp>/` as JSON and CSV.

### 3. Run a Single Test Manually

```bash
modal run udp_holepunch.py --local --output <result.json>
```
- `--local` tests local-to-Modal. Omit for Modal-to-Modal.
- Output is a JSON file with full diagnostics.

### 4. Results
- Per-run JSON: endpoint info, NAT type, hairpin, QUIC stats
- Aggregated CSV: summary table for all runs

## Files
- `run_holepunch_tests.sh` — Automates multiple runs, aggregates results
- `udp_holepunch.py` — Single test runner (can be run via Modal CLI)

## Notes
- Modal account required for remote runs
- For local runs, ensure your firewall allows UDP/QUIC traffic

---
For questions, contact @shababo 