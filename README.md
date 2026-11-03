# SOP trial task (Track B): early-packet DDoS detection on CIC-IDS2017

Trial task for Dr. K Hari Babu, BITS Pilani. ID: 2023A7PS0646P.

Task: train a simple classifier that separates attack traffic from benign traffic using only
features a switch could compute from the first few packets of a flow, report precision and
recall, and explain one case where it fails.

Seed: 46 (last two digits of my ID) for everything random: the train/test split, CV folds,
the trees and the random forest. `04_seed_sensitivity.py` is the one exception: it uses other
seeds on purpose to see how much the results depend on the seed.

Write-ups are in `report/`:
- [REPORT.md](report/REPORT.md): the main report (about 2 pages)
- [STUCK_NOTES.md](report/STUCK_NOTES.md): problems I ran into and how I got around them
- [WEEK2.md](report/WEEK2.md): plan for week 2
- [AI_USE.md](report/AI_USE.md): how I used AI tools for this

## Short version of the results

The EARLY decision tree uses 4 fields from the TCP handshake and ends up with 16 leaves. On a
held-out 30% of Friday it gets precision 0.9896 and recall 0.9995; 5-fold CV gives
0.9896 ± 0.0004 and 0.9998. But when I ran the same tree on Wednesday, which has different DoS
tools, recall fell to 0.0035. Most of the Friday score turns out to come from recognising the
attack tool's TCP handshake. The slow attacks (slowloris, Slowhttptest) are not caught at all.

## Setup

I used Python 3.9.6 on macOS with pandas 2.3.3, numpy 2.0.2 and scikit-learn 1.6.1. The
system Python didn't have scikit-learn, so I used a venv:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

(If VS Code underlines the sklearn imports, it's using the system Python. Select
`.venv/bin/python` as the interpreter.)

## Commands, in the order I ran them

From the repo root:

```bash
# download both CSVs into data/ and check their SHA-256
bash scripts/00_download.sh
# ran it a second time just to save the check output (it skips existing files)
bash scripts/00_download.sh 2>&1 | tee outputs/00_download.log

# shape, labels, columns, NaN/inf rows, duplicates
.venv/bin/python scripts/01_inspect.py > outputs/01_inspect.log 2>&1

# training + evaluation, ~30 s. writes 02_train.log, results.json, tree_early_rules.txt
.venv/bin/python scripts/02_train.py

# checks whether the model is just matching the attack tool's TCP fingerprint
.venv/bin/python scripts/03_fingerprint_check.py > outputs/03_fingerprint.log 2>&1

# retrains the EARLY tree with seeds 46, 74 and 0-9
.venv/bin/python scripts/04_seed_sensitivity.py > outputs/04_seed_sensitivity.log 2>&1
```

`02_train.py` takes `--depth` (default 5), `--seed` (default 46), `--trees` (default 100) and
`--out` (default `outputs/`). For a quick change, use a different `--out` so the main outputs
aren't overwritten:

```bash
.venv/bin/python scripts/02_train.py --depth 3 --out outputs/depth3
.venv/bin/python scripts/02_train.py --seed 74 --out outputs/seed74
```

With depth 3 the tree goes down to 7 leaves and Friday precision drops to 0.9743.

## Files

```
scripts/
  00_download.sh            downloads the two CSVs and verifies SHA-256
  common.py                 paths, CSV loader (strips spaces in column names), cleaning
  01_inspect.py             basic look at both files
  02_train.py               feature sets, models, Friday test, CV, Wednesday test
  03_fingerprint_check.py   window-size distributions and hand-written rules
  04_seed_sensitivity.py    EARLY tree with different seeds
data/
  SHA256SUMS                checksums (CSVs are gitignored, too big)
outputs/                    logs from every script, results.json, tree_early_rules.txt
report/                     REPORT, STUCK_NOTES, WEEK2, AI_USE
```

## What I did, step by step

### Data

CIC-IDS2017 is a dataset from the Canadian Institute for Cybersecurity. They recorded five
days of traffic on a test network, ran attacks on some of the days, and used CICFlowMeter to
turn the packet captures into CSVs with one row per flow (78 features plus a label).

I used two of the days:
- Friday afternoon: DDoS from LOIC, plus benign traffic. I trained and tested on this day.
- Wednesday: DoS Hulk, GoldenEye, slowloris and Slowhttptest, plus benign traffic. I only used
  this day to test the Friday models on attacks they had never seen.

The official CIC download page wasn't reachable, so I took the CSVs from a public GitHub repo
(`2000pawan/Cyber-Attack-Threat-Classification`) that stores them with Git LFS. The
raw.githubusercontent.com link only gives the small LFS pointer file. The
media.githubusercontent.com link gives the actual CSV. Since the data didn't come from the
official source, the script writes `data/SHA256SUMS` and checks it. Both hashes matched what I
expected, and the Friday one matches the LFS object id:

```
6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee  Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a  Wednesday-workingHours.pcap_ISCX.csv
```

### Looking at the data

`01_inspect.py` output, summarised:

| | Friday | Wednesday |
|---|---|---|
| rows × cols | 225,745 × 79 | 692,703 × 79 |
| labels | 128,027 DDoS, 97,718 benign | 440,031 benign, 231,073 Hulk, 10,293 GoldenEye, 5,796 slowloris, 5,499 Slowhttptest, 11 Heartbleed |
| rows with NaN/inf | 34 | 1,297 |
| duplicate rows | 2,633 | 81,909 |

A few problems showed up:
- Most column names start with a space (`" Label"`), so I strip them when loading.
- `Flow Bytes/s` and `Flow Packets/s` have NaN or inf values, from dividing by a flow
  duration of 0.
- There are many exact duplicate rows. These need to go before the train/test split, or the
  same row can end up in both.

### Cleaning and split

I replace inf with NaN, drop rows with NaN and drop duplicates. That leaves 223,082 Friday
flows (128,014 DDoS / 95,068 benign) and 610,492 Wednesday flows (193,756 attacks). The label
is just `Label != "BENIGN"`. I split Friday 70/30, stratified, with seed 46 (156,157 train /
66,925 test).

### Features

A switch sees packets as they pass. It can match header fields against table entries and keep
a few counters per flow, but it can't wait for the flow to end or run anything heavy. So I
tried four feature sets:

- **EARLY**: Destination Port, Init_Win_bytes_forward, Init_Win_bytes_backward,
  min_seg_size_forward. These are all fixed by the handshake (SYN / SYN-ACK), so a switch
  could read them within the first 1-3 packets. The initial window value is set by the
  sender's OS or TCP stack (e.g. 8192 is common on Windows and 29200 on Linux), and -1 means
  it wasn't seen. min_seg_size_forward behaves more like the minimum header size: 20 with no
  TCP options, 32 with timestamps.
- **EARLY_NO_PORT**: EARLY without the port, to see how much the port contributes.
- **COUNTER**: Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Fwd
  Packet Length Max, Flow Duration. A switch could keep these in registers, but here they're
  totals over the whole flow, so this is an optimistic upper bound rather than a realistic
  first-packets setup.
- **ALL**: all 78 features with a random forest (100 trees). This is only a reference for the
  best you can get on this data. It wouldn't fit on a switch.

For the first three I used a decision tree with max_depth=5. A tree like this can be turned
directly into match-action table entries (each leaf is one rule on ranges of field values),
and depth 5 means at most 32 leaves.

### Friday results (held-out 30%)

Precision and recall are for the attack class.

| model | precision | recall | FP | FN | leaves |
|---|---|---|---|---|---|
| EARLY | 0.9896 | 0.9995 | 405 | 18 | 16 |
| EARLY_NO_PORT | 0.9451 | 0.9995 | 2,228 | 18 | 15 |
| COUNTER | 0.9995 | 0.9986 | 21 | 55 | 15 |
| ALL (RF) | 1.0000 | 0.9999 | 1 | 5 | – |

5-fold stratified CV on the EARLY tree gave precision 0.9896 ± 0.0004 and recall
0.9998 ± 0.0000, so the result wasn't a lucky split. Without the port, false positives go from
405 to 2,228. The EARLY false positives are 390 flows to port 80 and 15 to port 21.

In the EARLY tree, Init_Win_bytes_forward has importance 0.585 and the port 0.331. The full
tree is in [outputs/tree_early_rules.txt](outputs/tree_early_rules.txt).

### Fingerprint check

Since the tree leans so much on the initial window, I checked what values the DDoS flows
actually have. There are only two: 256 (54.5%) and 8192 (45.3%). All DDoS flows also have
min_seg_size_forward = 20, and all but 3 of them go to port 80. Benign traffic is spread over
lots of values (-1, 229, 8192, 29200, 65535, ...).

I then tried some fixed rules, with no training at all:

| rule | Friday P | Friday R | Wednesday R |
|---|---|---|---|
| window == 256 and port 80 | 0.9951 | 0.5451 | 0.0000 |
| window in {256, 8192} and port 80 | 0.9773 | 0.9983 | 0.0000 |
| port 80 | 0.9374 | 1.0000 | 0.9999 (45,979 benign flagged) |

The two-value rule does almost as well as the tree on Friday. So what the tree mostly learned
is what LOIC's SYN packets look like, not anything general about attacks.

### Wednesday (failure case)

I ran the Friday models on Wednesday without retraining:

| model | precision | recall | Hulk | GoldenEye | slowloris | Slowhttptest |
|---|---|---|---|---|---|---|
| EARLY | 0.0855 | 0.0035 | 0.4% | 0% | 0% | 0% |
| EARLY_NO_PORT | 0.0178 | 0.0035 | 0.4% | 0% | 0% | 0% |
| COUNTER | 0.4603 | 0.0029 | 0.3% | 0% | 0% | 0.6% |
| ALL (RF) | 0.5073 | 0.0007 | 0.08% | 0% | 0% | 0.02% |

(the per-attack columns are the % of those flows flagged as attack)

All four models basically fail. Adding features doesn't help: the random forest fits Friday
even more closely. The two-value window rule catches 3 of the 193,756 Wednesday attacks.

The case I focus on is slowloris and Slowhttptest. Their SYNs use window 29200 (72-81% of
flows) or 229 (18-28%), and normal clients use both of these too. On Friday, 229 is 27.5% of
benign flows and 29200 is 6.3%. So from the handshake alone they look like ordinary Linux
clients. They're also low-rate on purpose: they open connections and send partial requests
very slowly to tie up the server's connection slots. That means the volume counters look
normal as well. What would actually give them away is timing: connections that stay open a
long time with very little data, long idle gaps, and lots of half-open connections from the
same source. You only see that after a few seconds, so a per-flow decision at packet 1-3 can't
catch it. A switch would need per-source counters and timers.

### Seed check

An earlier run I did with seed 74 got 0.57 recall on Wednesday (64% of Hulk). With seed 46 I
got 0.0035, so I retrained the EARLY tree with 12 different seeds to see what was going on.
Friday precision stayed between 0.989 and 0.991 every time. Wednesday recall only ever came out
as 0.0035, 0.3075 or 0.5724. Seed 74 gives 0.5724 again, so the code is consistent.

Comparing the two trees explained it. The seed-74 tree has two small leaves that predict
"attack" for window = 251 and window = 0. These come from just 17 and 27 Friday DDoS flows.
Hulk's most common windows happen to be 0 (34%) and 251 (33%), so that tree catches Hulk by
coincidence. The seed-46 tree labels the same values benign. Looking only at Friday, there's
no way to tell these trees apart. I kept seed 46 as the main result since that's what the task
asks for.

### Limitations

- The CSVs are per finished flow, so these aren't real first-k-packet features. I could only
  use fields that are fixed at the handshake. Doing this properly needs the pcaps.
- Random splits within one day make the model look much better than it is. The cross-day
  numbers are more realistic.
- On unseen attacks, the result depends on the seed.
- CIC-IDS2017 has known labelling and CICFlowMeter issues (bad rows, duplicates, a duplicated
  `Fwd Header Length` column).

### Checklist against the task

| asked for | done in |
|---|---|
| public dataset (CIC-IDS2017) | Friday + Wednesday CSVs, SHA-256 checked |
| simple classifier | depth-5 decision tree, 16 leaves |
| only first-few-packet, switch-computable features | EARLY set (handshake fields only). COUNTER and ALL are marked as upper bound / reference |
| precision and recall | Friday 0.9896 / 0.9995, CV, Wednesday 0.0855 / 0.0035 |
| one failure case explained | slowloris / Slowhttptest |
| seed 46 stated | here, in the report and as the default `--seed` |

## AI use

I used Claude (claude.ai and Claude Code) for this. Details are in
[report/AI_USE.md](report/AI_USE.md).
