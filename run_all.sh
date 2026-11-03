#!/usr/bin/env bash
# Runs the whole pipeline in order. Output is shown live and each log is saved in outputs/.
#
# Usage (from anywhere):  bash run_all.sh
set -euo pipefail   # stop at the first step that fails (pipefail: even when piped into tee)

cd "$(dirname "$0")"

# use the project's venv if it's there, otherwise the system python
if [[ -x .venv/bin/python ]]; then PYTHON=.venv/bin/python; else PYTHON=python3; fi

echo "=== Step 1: download + SHA-256 check (skips files already in data/) ==="
bash scripts/00_download.sh 2>&1 | tee outputs/00_download.log

echo "=== Step 2: inspect the CSVs ==="
$PYTHON -u scripts/01_inspect.py 2>&1 | tee outputs/01_inspect.log

echo "=== Step 3: train + evaluate (writes its own log, results.json, tree rules) ==="
$PYTHON -u scripts/02_train.py

echo "=== Step 4: TCP fingerprint check ==="
$PYTHON -u scripts/03_fingerprint_check.py 2>&1 | tee outputs/03_fingerprint.log

echo "=== Step 4b: seed sensitivity ==="
$PYTHON -u scripts/04_seed_sensitivity.py 2>&1 | tee outputs/04_seed_sensitivity.log

echo "=== Done. Logs are in outputs/ ==="
