#!/usr/bin/env bash
# Run the whole pipeline in order, printing output live and saving each log to outputs/.
#
# Usage (from anywhere):  bash run_all.sh
set -euo pipefail   # stop at the first failing step (pipefail: even when piped into tee)

cd "$(dirname "$0")"

# use the project venv if it exists, otherwise the system python
if [[ -x .venv/bin/python ]]; then PY=.venv/bin/python; else PY=python3; fi

echo "=== Step 1: download + SHA-256 check (skips files already in data/) ==="
bash scripts/00_download.sh 2>&1 | tee outputs/00_download.log

echo "=== Step 2: inspect the CSVs ==="
$PY -u scripts/01_inspect.py 2>&1 | tee outputs/01_inspect.log

echo "=== Step 3: train + evaluate (writes its own log, results.json, tree rules) ==="
$PY -u scripts/02_train.py

echo "=== Step 4: TCP fingerprint check ==="
$PY -u scripts/03_fingerprint_check.py 2>&1 | tee outputs/03_fingerprint.log

echo "=== Step 4b: seed sensitivity ==="
$PY -u scripts/04_seed_sensitivity.py 2>&1 | tee outputs/04_seed_sensitivity.log

echo "=== Done. Logs are in outputs/ ==="
