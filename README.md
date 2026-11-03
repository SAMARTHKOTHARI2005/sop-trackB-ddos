# SOP Trial Task, Track B: early-packet DDoS detection on CIC-IDS2017

Trial task for Dr. K Hari Babu (BITS Pilani). The goal is a simple classifier that separates
attack from benign traffic using only features a network switch could compute from the first
few packets of a flow. It reports precision and recall and explains one case where the
detector fails.

**Seed:** every random step (train/test split, CV folds, tree tie-breaking, random forest)
uses **seed 46**, the last two digits of my ID 2023A7PS0646P. `scripts/04_seed_sensitivity.py`
deliberately re-runs the EARLY tree with other seeds as a robustness check.

- Report: [report/REPORT.md](report/REPORT.md)
- Where I got stuck: [report/STUCK_NOTES.md](report/STUCK_NOTES.md)
- Week 2 plan: [report/WEEK2.md](report/WEEK2.md)
- AI use disclosure: [report/AI_USE.md](report/AI_USE.md)

## Setup

Tested on macOS with Python 3.9.6, pandas 2.3.3, numpy 2.0.2 and scikit-learn 1.6.1.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Exact commands, in order

Run from the repo root. These are the exact commands that produced the files in `outputs/`.

```bash
# 1. Download the two CSVs (~74 MB + ~215 MB) into data/, write and verify data/SHA256SUMS.
bash scripts/00_download.sh
#    (re-run once more to save the verification log; it skips files that already exist)
bash scripts/00_download.sh 2>&1 | tee outputs/00_download.log

# 2. Inspect shape, labels, columns, NaN/inf and duplicate rows.
.venv/bin/python scripts/01_inspect.py > outputs/01_inspect.log 2>&1

# 3. Train and evaluate (seed 46, depth 5). Takes about 30 s and writes
#    outputs/02_train.log, outputs/results.json and outputs/tree_early_rules.txt itself.
.venv/bin/python scripts/02_train.py

# 4. TCP-fingerprint check: is the detector just recognising the attack tool?
.venv/bin/python scripts/03_fingerprint_check.py > outputs/03_fingerprint.log 2>&1

# 5. Seed-sensitivity check of the EARLY tree (seeds 46, 74, 0-9).
.venv/bin/python scripts/04_seed_sensitivity.py > outputs/04_seed_sensitivity.log 2>&1
```

### Changing depth or seed

`02_train.py` takes `--depth` (default 5), `--seed` (default 46), `--trees` (default 100) and
`--out` (default `outputs/`). Use a separate `--out` folder so the main results are not
overwritten:

```bash
.venv/bin/python scripts/02_train.py --depth 3 --out outputs/depth3
.venv/bin/python scripts/02_train.py --seed 74 --out outputs/seed74
.venv/bin/python scripts/04_seed_sensitivity.py --depth 3 --seeds 46 74 1 2
```

## Repo layout

```
scripts/
  00_download.sh            download + SHA-256 verify the two CSVs (GitHub LFS mirror)
  common.py                 shared paths, CSV loader (strips column-name spaces), clean()
  01_inspect.py             shape, label counts, columns, NaN/inf/duplicate counts
  02_train.py               feature sets, trees + RF, Friday test, 5-fold CV, Wednesday test
  03_fingerprint_check.py   initial-window distributions + single hand-written rules
  04_seed_sensitivity.py    EARLY tree retrained with several seeds
data/
  SHA256SUMS                checksums of the two CSVs (the CSVs themselves are gitignored)
outputs/
  00_download.log  01_inspect.log  02_train.log  03_fingerprint.log  04_seed_sensitivity.log
  results.json              all numbers from 02_train.py
  tree_early_rules.txt      the EARLY decision tree as if/else rules
report/
  REPORT.md  STUCK_NOTES.md  WEEK2.md  AI_USE.md
```

## Data

CIC-IDS2017 "MachineLearningCVE" per-flow CSVs (CICFlowMeter output), from the public
GitHub LFS mirror `2000pawan/Cyber-Attack-Threat-Classification`, because the official CIC
server was unreachable.

| file | SHA-256 |
|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | `6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee` |
| Wednesday-workingHours.pcap_ISCX.csv | `893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a` |
