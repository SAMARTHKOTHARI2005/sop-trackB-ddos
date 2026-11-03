#!/usr/bin/env bash
# Download two CIC-IDS2017 "MachineLearningCVE" CSVs into data/ and verify them.
#
# Why this mirror: the official CIC server (unb.ca) was unreachable, so we use a
# public GitHub repo that stores the CSVs with Git LFS. NOTE: the
# raw.githubusercontent.com URL only returns a ~130-byte LFS *pointer* file;
# media.githubusercontent.com serves the real file content.
#
# Usage (from repo root):  bash scripts/00_download.sh
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p data

BASE="https://media.githubusercontent.com/media/2000pawan/Cyber-Attack-Threat-Classification/main/MachineLearningCVE"
FILES=(
  "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"   # ~77 MB, DDoS (LOIC) + benign
  "Wednesday-workingHours.pcap_ISCX.csv"               # ~225 MB, DoS Hulk/GoldenEye/slowloris/Slowhttptest/Heartbleed + benign
)

# Expected SHA-256 prefixes (Friday's matches the Git LFS oid of the mirror).
# (a case statement instead of an associative array: macOS ships bash 3.2)
expected_prefix() {
  case "$1" in
    Friday-*)    echo "6ff1580f5f81c0ae" ;;
    Wednesday-*) echo "893c27dc968bf7a8" ;;
  esac
}

for f in "${FILES[@]}"; do
  if [[ -s "data/$f" ]]; then
    echo "[skip] data/$f already exists"
  else
    echo "[download] $f"
    curl -fsSL --retry 3 -o "data/$f" "$BASE/$f"
  fi
  # Guard against accidentally getting an LFS pointer instead of the CSV.
  if head -c 200 "data/$f" | grep -q "git-lfs.github.com/spec"; then
    echo "ERROR: data/$f is a Git LFS pointer, not the CSV" >&2
    exit 1
  fi
done

# Write checksums (portable: shasum on macOS, sha256sum on Linux).
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
(cd data && $SHA "${FILES[@]}" > SHA256SUMS)
echo "--- data/SHA256SUMS ---"
cat data/SHA256SUMS

# Verify (1) the checksum file round-trips and (2) each hash has the expected prefix.
(cd data && $SHA -c SHA256SUMS)
for f in "${FILES[@]}"; do
  got=$(grep " \*\?$f\$" data/SHA256SUMS | cut -c1-16)
  want=$(expected_prefix "$f")
  if [[ "$got" == "$want" ]]; then
    echo "[ok] $f sha256 prefix $got"
  else
    echo "ERROR: $f sha256 prefix $got != expected $want" >&2
    exit 1
  fi
done
ls -lh data/*.csv
