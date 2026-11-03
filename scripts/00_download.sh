#!/usr/bin/env bash
# Download two CIC-IDS2017 "MachineLearningCVE" CSVs into data/ and check them.
#
# The official CIC server (unb.ca) wasn't reachable, so this uses a public GitHub
# repo that stores the CSVs with Git LFS. Note: the raw.githubusercontent.com link
# only gives you a ~130-byte LFS "pointer" file; media.githubusercontent.com gives
# you the actual CSV.
#
# Usage (from the repo root):  bash scripts/00_download.sh
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p data

BASE_URL="https://media.githubusercontent.com/media/2000pawan/Cyber-Attack-Threat-Classification/main/MachineLearningCVE"
FILES=(
  "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"   # ~74 MB, DDoS (LOIC) + benign
  "Wednesday-workingHours.pcap_ISCX.csv"               # ~215 MB, DoS Hulk/GoldenEye/slowloris/Slowhttptest/Heartbleed + benign
)

# Expected start of each file's SHA-256 (Friday's matches the Git LFS oid in the mirror).
# Using a case statement because macOS ships bash 3.2, which has no associative arrays.
expected_hash() {
  case "$1" in
    Friday-*)    echo "6ff1580f5f81c0ae" ;;
    Wednesday-*) echo "893c27dc968bf7a8" ;;
  esac
}

for file in "${FILES[@]}"; do
  if [[ -s "data/$file" ]]; then
    echo "[skip] data/$file already exists"
  else
    echo "[download] $file"
    curl -fsSL --retry 3 -o "data/$file" "$BASE_URL/$file"
  fi
  # make sure we didn't get an LFS pointer instead of the real CSV
  if head -c 200 "data/$file" | grep -q "git-lfs.github.com/spec"; then
    echo "ERROR: data/$file is a Git LFS pointer, not the CSV" >&2
    exit 1
  fi
done

# Write the checksums (shasum on macOS, sha256sum on Linux)
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
(cd data && $SHA "${FILES[@]}" > SHA256SUMS)
echo "--- data/SHA256SUMS ---"
cat data/SHA256SUMS

# Check each hash against the expected one (SHA256SUMS lines look like "<hash>  <file>")
for file in "${FILES[@]}"; do
  actual=$(grep -F "  $file" data/SHA256SUMS | cut -c1-16)
  expected=$(expected_hash "$file")
  if [[ "$actual" == "$expected" ]]; then
    echo "[ok] $file sha256 prefix $actual"
  else
    echo "ERROR: $file sha256 prefix $actual != expected $expected" >&2
    exit 1
  fi
done
ls -lh data/*.csv
