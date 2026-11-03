# SOP Trial Task, Track B: early-packet DDoS detection on CIC-IDS2017

Trial task for Dr. K Hari Babu (BITS Pilani). Student ID 2023A7PS0646P.

The goal is a simple classifier that separates attack traffic from normal (benign) traffic,
using **only features a network switch could compute from the first few packets of a flow**.
It reports precision and recall and explains one case where the detector fails.

**Seed:** every random step (train/test split, CV folds, tree tie-breaking, random forest)
uses **seed 46**, the last two digits of my ID 2023A7PS0646P. `scripts/04_seed_sensitivity.py`
deliberately re-runs the EARLY tree with other seeds as a robustness check.

| Document | What it is |
|---|---|
| [report/REPORT.md](report/REPORT.md) | The ~2-page report: goal, method, results, failure case, limitations |
| [report/STUCK_NOTES.md](report/STUCK_NOTES.md) | Where I got stuck and how I fixed it |
| [report/WEEK2.md](report/WEEK2.md) | What I would do in week 2 |
| [report/AI_USE.md](report/AI_USE.md) | Disclosure of AI use |

### Results at a glance

| | Precision | Recall |
|---|---|---|
| EARLY tree (4 handshake fields, 16 rules), Friday held-out test | 0.9896 | 0.9995 |
| Same tree, 5-fold CV on Friday | 0.9896 ± 0.0004 | 0.9998 ± 0.0000 |
| Same tree, applied to a different day (Wednesday) | 0.0855 | **0.0035** |

The near-perfect same-day score comes mostly from recognising the attack tool's TCP
handshake "fingerprint". On a new day with different attack tools the detector fails, and it
misses slow attacks like slowloris completely. Details are in the walkthrough below.

---

## Contents

1. [Setup and exact commands](#1-setup-and-exact-commands)
2. [Repo layout](#2-repo-layout)
3. [Full walkthrough, in plain language](#3-full-walkthrough-in-plain-language)
   - [3.0 What the professor asked for](#30-what-the-professor-asked-for)
   - [3.1 Step 0: setting up the repo](#31-step-0-setting-up-the-repo)
   - [3.2 Step 1: getting the data](#32-step-1-getting-the-data-scripts00_downloadsh)
   - [3.3 Step 2: looking at the data first](#33-step-2-looking-at-the-data-first-scripts01_inspectpy)
   - [3.4 Step 3: the main experiment](#34-step-3-the-main-experiment-scripts02_trainpy)
   - [3.5 Step 4: is it really detecting attacks?](#35-step-4-is-it-really-detecting-attacks-scripts03_fingerprint_checkpy)
   - [3.6 The failure case: Wednesday](#36-the-failure-case-wednesday)
   - [3.7 Step 4b: the seed surprise](#37-step-4b-the-seed-surprise-scripts04_seed_sensitivitypy)
   - [3.8 Step 5: the write-ups](#38-step-5-the-write-ups)
   - [3.9 Main limitations](#39-main-limitations)
   - [3.10 How this maps to what was asked](#310-how-this-maps-to-what-was-asked)
4. [How this was built](#4-how-this-was-built)

---

## 1. Setup and exact commands

Tested on macOS with Python 3.9.6, pandas 2.3.3, numpy 2.0.2 and scikit-learn 1.6.1.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Run everything from the repo root. These are the exact commands that produced the files in
`outputs/`, in order:

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

### Changing depth or seed (for a live re-run)

`02_train.py` takes `--depth` (default 5), `--seed` (default 46), `--trees` (default 100) and
`--out` (default `outputs/`). Use a separate `--out` folder so the main results are not
overwritten:

```bash
.venv/bin/python scripts/02_train.py --depth 3 --out outputs/depth3
.venv/bin/python scripts/02_train.py --seed 74 --out outputs/seed74
.venv/bin/python scripts/04_seed_sensitivity.py --depth 3 --seeds 46 74 1 2
```

Example: at `--depth 3` the EARLY tree has 7 rules instead of 16, and Friday precision drops
from 0.9896 to 0.9743. Fewer rules means a smaller switch table but more false alarms.

> **VS Code tip:** if `sklearn` imports show yellow squiggly lines, VS Code is using the system
> Python, which has no scikit-learn. Press `Cmd+Shift+P` → **Python: Select Interpreter** →
> choose `.venv/bin/python`.

---

## 2. Repo layout

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

---

## 3. Full walkthrough, in plain language

### 3.0 What the professor asked for

The task has four parts:

1. **Use a public traffic dataset (CIC-IDS2017).**
2. **Train a simple classifier that separates attack traffic from normal traffic, using only
   features a network switch could compute from the first few packets of a connection.**
3. **Report precision and recall.**
4. **Explain one case where the detector fails.**

Plus: use seed 46 wherever randomness is involved, and say so.

Part 2 is the hard constraint. Ordinary machine-learning detectors look at a connection
*after it has finished*, using 78 statistics. This task wants a detector that could run
**inside a switch** (the box that forwards packets in a network). A switch is very fast but
very limited. It can read packet headers, look values up in small tables ("if port = 80 and
window = 256, do X") and keep a few counters. It can't run a neural network, and it can't
wait until a connection ends. So the question is: **can we spot attacks almost immediately,
from the first 1-3 packets?**

### 3.1 Step 0: setting up the repo

I created four folders: `scripts/` (code), `data/` (the dataset), `outputs/` (logs and
results) and `report/` (the write-ups). I also added a `.gitignore` telling git not to upload
the CSV files. They are 74 MB and 215 MB, too big for a normal GitHub repo, and anyone can
re-download them with the script anyway.

`requirements.txt` lists the three libraries:

- **pandas**: loads the CSV tables.
- **numpy**: does the number crunching.
- **scikit-learn**: provides the machine-learning models.

The Mac's built-in Python had no scikit-learn, so I made a **virtual environment** (`.venv`),
a private Python just for this project, and installed the three libraries there.

The professor wanted a visible history, so I committed and pushed after every step.

### 3.2 Step 1: getting the data (`scripts/00_download.sh`)

**What CIC-IDS2017 is.** In 2017 the Canadian Institute for Cybersecurity (CIC, at the
University of New Brunswick) built a fake company network. For 5 days they recorded all its
traffic: normal users browsing, emailing and so on. On specific days they also launched real
attacks from attacker machines.

They then ran a tool called **CICFlowMeter** over the recordings. It groups packets into
**flows**. A flow is one conversation between two machines, identified by source IP,
destination IP, source port, destination port and protocol. For each flow it computes 78
numbers (duration, packet counts, byte counts, window sizes and so on) and adds a **label**:
`BENIGN` or the attack's name. The "MachineLearningCVE" CSVs are that table, with one row per
flow.

**Which two files and why.**

- **Friday afternoon:** a **DDoS** attack (Distributed Denial of Service: many machines flood
  one web server). The attack tool was **LOIC**. This is the **training day**.
- **Wednesday:** four different **DoS** attacks, all aimed at the same kind of web server:
  **Hulk**, **GoldenEye**, **slowloris** and **Slowhttptest**. This is the **"surprise exam"
  day**, used to find the failure case.

**Where the files came from.** The official CIC server was unreachable. So the script
downloads from a **public GitHub repository** (`2000pawan/Cyber-Attack-Threat-Classification`)
where someone uploaded the same CSVs.

There's a catch. GitHub stores big files with **Git LFS** (Large File Storage). The repo only
holds a tiny text "pointer" note that says, roughly, "the real file has hash X and size Y,
stored elsewhere." The normal `raw.githubusercontent.com` link gives you that 130-byte note,
not the data. The `media.githubusercontent.com` link gives you the real file. The script uses
the media link, and it also checks that the download isn't a pointer note.

**Proving it's the right file: SHA-256.** Since the data came from a stranger's GitHub instead
of the official source, how do we know it's genuine and complete? With **SHA-256**, a
fingerprint computed from a file's bytes. Change one byte and the fingerprint changes
completely.

The script computes both fingerprints, saves them to `data/SHA256SUMS`, and checks that they
start with the expected values. Both matched. The Friday one also equals the ID the LFS system
uses for that file, so it's the exact file the mirror says it is.

| file | SHA-256 |
|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | `6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee` |
| Wednesday-workingHours.pcap_ISCX.csv | `893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a` |

One small fix here: the first version of the script used a bash feature (associative arrays)
that the old bash on macOS (version 3.2) doesn't support, so I rewrote it with a `case`
statement.

### 3.3 Step 2: looking at the data first (`scripts/01_inspect.py`)

Rule one of data work: look before you train. This script prints, for each file, its size, how
many rows have each label, every column name, and how many rows are broken. What it found:

| | Friday | Wednesday |
|---|---|---|
| Rows × columns | 225,745 × 79 | 692,703 × 79 |
| Labels | 128,027 DDoS, 97,718 benign | 440,031 benign, 231,073 Hulk, 10,293 GoldenEye, 5,796 slowloris, 5,499 Slowhttptest, 11 Heartbleed |
| Rows with NaN or infinity | 34 | 1,297 |
| Exact duplicate rows | 2,633 | 81,909 |

79 columns means 78 features plus the label. The problems it found:

- **Column names start with a space.** The header literally says `" Label"`, not `"Label"`. So
  `df["Label"]` would fail. The fix is in `scripts/common.py`, which strips spaces from every
  column name when loading. All the scripts share this loader.
- **NaN and infinity.** "Flow Bytes/s" and "Flow Packets/s" are rates: bytes divided by
  duration. When a flow's duration is 0, you divide by zero and get infinity or "not a
  number". The models can't handle those values.
- **Duplicates.** Identical rows. If the same row lands in both the training set and the test
  set, the model is tested on something it has already seen. That's like seeing the exam paper
  in advance, and it inflates the score.

### 3.4 Step 3: the main experiment (`scripts/02_train.py`)

#### Cleaning

1. Turn infinities into "missing" (NaN).
2. Drop every row that has any missing value.
3. Drop exact duplicate rows. This happens **before** splitting into train and test, so no row
   can appear in both.

Afterwards Friday has 223,082 flows (128,014 DDoS, 95,068 benign) and Wednesday has 610,492
(193,756 of them attacks).

The label becomes a simple yes or no: **y = 1 if Label ≠ "BENIGN", else 0.** So the task is
"attack or not", not "which attack".

#### The train/test split

Friday's flows are split **70% for training, 30% for testing** (156,157 and 66,925 flows). The
model learns from the 70% and is graded on the 30% it never saw.

The split is **stratified**: both parts keep the same attack/benign ratio as the whole day.

The split is random, so it uses **seed 46**. A seed is the starting point of the random number
generator. The same seed gives the same "random" split every time, so anyone can reproduce
these exact numbers.

#### The four feature sets

These are the core of the project. Each answers a different question.

**EARLY: the actual answer to the professor's question.** These four values are fixed by the
first 1-3 packets. Every TCP connection starts with a "handshake": the client sends **SYN**,
the server replies **SYN-ACK**, and the client sends **ACK**. The four features come from those
packets:

| Feature | Plain meaning |
|---|---|
| Destination Port | Which service is being contacted. 80 = web, 443 = secure web, 53 = DNS. |
| Init_Win_bytes_forward | The TCP window value in the client's first packet: roughly "how much data I can receive at once". The **operating system** sets it, so it acts like a signature of the client's OS or software. For example, 8192 is a classic Windows value and 29200 is the usual Linux value. -1 means "never seen". |
| Init_Win_bytes_backward | The same, from the server's reply. |
| min_seg_size_forward | In practice, the smallest header size the client used. 20 means plain headers; 32 means headers with extra options (e.g. timestamps). Again an OS or software signature. |

A switch can read all four from packet headers immediately. That's why this is the "honest"
feature set.

**EARLY_NO_PORT: an experiment by removal (an "ablation").** This is EARLY without the port.
It asks: how much is the model relying on "is it port 80?" If the score drops a lot, the port
was doing much of the work.

**COUNTER: what if the switch kept counters?** Switches can keep small counters per flow
("registers"): packets so far, bytes so far, biggest packet so far. COUNTER uses Total Fwd
Packets, Total Backward Packets, Total Length of Fwd Packets, Fwd Packet Length Max and Flow
Duration. The catch is that in the CSV these are **final totals over the entire flow**, not
"after 3 packets". A real switch would only have partial counts, so this set is an
**optimistic upper bound**: better than a switch could really do.

**ALL: the ceiling.** All 78 features, fed to a **Random Forest** (100 decision trees voting
together), a strong off-the-shelf model. A switch could never run this. It's only there to show
the best possible score on this data, so we can see how much is lost by restricting to EARLY.

#### Why a decision tree with depth 5

A decision tree is a flowchart of yes/no questions:

```
Is Init_Win_bytes_forward > 255.5?
 ├─ yes → Is Destination Port ≤ 84?
 │         ├─ yes → ... → ATTACK
 │         └─ no  → BENIGN
 └─ no  → ... → BENIGN
```

Each path from top to bottom (a **leaf**) is one rule, like "if window is in this range and
port is in that range, it's an attack". That is exactly what a switch's **match-action table**
does: match header fields against ranges, then take an action (forward, drop or flag). So a
tree can be copied almost directly into switch hardware.

**Depth 5** means at most 5 questions per path, so at most 2⁵ = 32 rules. Small enough to fit
in a switch. The EARLY tree has **16 leaves**. Depth is a command-line option (`--depth`). The
full tree is in [outputs/tree_early_rules.txt](outputs/tree_early_rules.txt).

#### Precision and recall, explained simply

Think of the detector as a security guard flagging people at a door.

- **TP (true positive):** an attacker, correctly flagged.
- **FP (false positive):** a normal user, wrongly flagged (a false alarm).
- **FN (false negative):** an attacker who got through, missed.
- **TN (true negative):** a normal user, correctly let through.

Then:

- **Precision = TP / (TP + FP)**: "When the guard raises an alarm, how often is it really an
  attacker?" Low precision means lots of false alarms, which in a network means blocking real
  users.
- **Recall = TP / (TP + FN)**: "Of all the attackers, how many did the guard catch?" Low recall
  means attacks slip through.

#### Results on Friday (same-day test)

| Model | Precision | Recall | False alarms (FP) | Missed attacks (FN) | Leaves |
|---|---|---|---|---|---|
| EARLY | 0.9896 | 0.9995 | 405 | 18 | 16 |
| EARLY_NO_PORT | 0.9451 | 0.9995 | 2,228 | 18 | 15 |
| COUNTER | 0.9995 | 0.9986 | 21 | 55 | 15 |
| ALL (RF) | 1.0000 | 0.9999 | 1 | 5 | – |

At face value: **using just 4 handshake fields, a 16-rule tree catches 99.95% of DDoS flows,
and 99% of its alarms are real.** Removing the port raises false alarms more than fivefold, so
the port matters.

**5-fold cross-validation** repeats the experiment five times with five different splits.
Precision was 0.9896 ± 0.0004 each time, so the result isn't luck of one split.

The script also saves:

- **The tree's rules** (`outputs/tree_early_rules.txt`): the "switch table".
- **Feature importances:** how much each feature contributed. The window field
  (Init_Win_bytes_forward) contributed 58.5% and the port 33.1%.
- **The ports of the false alarms:** 390 on port 80 (web) and 15 on port 21 (FTP). The tree
  flags some normal web traffic that happens to look like the attacker's.

Those numbers look too good, and the next step shows why.

### 3.5 Step 4: is it really detecting attacks? (`scripts/03_fingerprint_check.py`)

The tree relies mostly on one field, the TCP window, which the **operating system or attack
tool** sets. That raises a suspicion: maybe the model learned to recognise the LOIC attack
computers, not attack behaviour.

The script lists the most common window values for DDoS and for benign flows on Friday:

- **DDoS:** 256 (54.5%) and 8192 (45.3%). Just two values cover 99.8% of all DDoS flows. Also,
  100% of DDoS flows go to port 80 and 100% have a min header size of 20.
- **Benign:** spread across many values: -1, 229, 8192, 29200, 65535 and more.

Then the script tests single hand-written rules with **no machine learning at all**:

| Rule | Friday precision | Friday recall | Wednesday recall |
|---|---|---|---|
| window = 256 AND port 80 | 0.9951 | 0.5451 | 0.0000 |
| **window = 256 or 8192, AND port 80** | **0.9773** | **0.9983** | **0.0000** |
| port 80 only | 0.9374 | 1.0000 | 0.9999 (but flags 45,979 benign flows) |

The two-value rule is almost as good as the trained tree on Friday. So the tree's
near-perfect score is basically **"recognise the attack tool's handshake signature"**. It's
like a guard who catches every robber because all the robbers that day wore the same red
jacket. That works perfectly until robbers show up in different clothes.

### 3.6 The failure case: Wednesday

The professor asked for one case where the detector fails. To find it honestly, I gave the
Friday-trained models **a different day with different attack tools**, unchanged and without
retraining. This is the "robbers in different clothes" test.

| Model | Precision | Recall | Hulk caught | GoldenEye | slowloris | Slowhttptest |
|---|---|---|---|---|---|---|
| EARLY | 0.0855 | **0.0035** | 0.4% | 0% | 0% | 0% |
| EARLY_NO_PORT | 0.0178 | 0.0035 | 0.4% | 0% | 0% | 0% |
| COUNTER | 0.4603 | 0.0029 | 0.3% | 0% | 0% | 0.6% |
| ALL (RF) | 0.5073 | 0.0007 | 0.08% | 0% | 0% | 0.02% |

**Every model collapses.** EARLY catches 0.35% of attacks. Even the 78-feature forest catches
almost nothing: more features just let it memorise Friday more precisely. The Friday
fingerprint rule catches 3 out of 193,756 Wednesday attacks.

#### The specific failure: slowloris and Slowhttptest

Here's how these attacks work, using a restaurant as an analogy. A web server has a limited
number of "tables" (connections). A flood like LOIC sends a crowd through the door. Slowloris
is sneakier: it sits at a table and orders one word every 10 seconds ("I'd… like… the…"),
never finishing. The waiter has to keep the table reserved. Do that at every table and the
restaurant is full, yet each customer looks polite.

Why the detector can't see it in the first few packets:

1. **Their handshake looks completely normal.** Their window values are 29200 (72-81% of
   flows) and 229 (18-28%). Normal benign clients use these same values (on Friday, 229 is
   27.5% of benign flows and 29200 is 6.3%). They use the standard Linux network stack, so
   their "jacket" is a normal jacket.
2. **They're low-volume by design.** Few packets, few bytes, small packets. So even the volume
   counters (COUNTER, ALL) see nothing unusual.
3. **What gives them away only shows up over time:** connections that stay open for a long time
   with almost no data, long silent gaps, and one source holding many half-finished connections
   at once. A switch would need timers and per-source counters, and it would need to wait
   seconds, not 1-3 packets.

**That's the main limitation:** first-packet detection can catch tools with a distinctive
signature, but it's blind to attacks whose whole point is to look normal and act slowly.

### 3.7 Step 4b: the seed surprise (`scripts/04_seed_sensitivity.py`)

An earlier run with **seed 74** caught 57% of Wednesday attacks (64% of Hulk). This run, with
**seed 46**, caught 0.35%. That's a huge gap for "just a different seed", so I investigated
rather than ignoring it.

I retrained the EARLY tree with 12 seeds:

- **Friday precision barely moves:** 0.989-0.991 every time.
- **Wednesday recall jumps between exactly three values:** 0.0035, 0.3075 or 0.5724. Seed 74
  reproduces 0.5724 exactly, so the code is consistent with the earlier run.

**Why:** I compared the two trees' rules. The seed-74 tree has two tiny extra "attack" rules:

- "window = 251": built from just 17 of Friday's 128,014 DDoS flows.
- "window = 0": built from just 27 of them.

By pure coincidence, Hulk's two most common window values are 0 (34%) and 251 (33%). So seed
74 "catches Hulk" through two tiny rules that happen to fit, not through any real
understanding. Seed 46's tree labels those same rare cases "benign".

**The lesson:** same-day accuracy can't tell a lucky tree from an unlucky one. Any success on
new attack types here is coincidence. That's why the report says to always test across days.
I kept seed 46 as the main result, as required, rather than picking the seed that looks best.

### 3.8 Step 5: the write-ups

| File | What it is |
|---|---|
| `README.md` | This file: setup, exact commands, layout, walkthrough |
| `report/REPORT.md` | The ~2-page report: goal, method, results, failure case, limitations |
| `report/STUCK_NOTES.md` | Every real problem and its fix: server down, LFS pointers, spaces in column names, NaN/infinity, duplicates, bash 3.2, missing sklearn, the seed mismatch |
| `report/WEEK2.md` | The next-week plan: get the raw packet captures (pcaps), compute real "first k packets" features for k = 2 to 10, always test across days, add per-source timers for slow attacks, put the tree into a P4 switch program on BMv2/Mininet, and link it to my ResilientDAG work |
| `report/AI_USE.md` | Disclosure of AI use |

Every number in the reports was copied from the files in `outputs/`.

### 3.9 Main limitations

1. **These aren't true "first-k-packet" features.** The CSV has one row per finished flow, so I
   could only use fields that are fixed at the handshake. Doing it properly needs the raw
   packet captures (week 2).
2. **A random split within one day flatters the model.** The same attacker, tool and hour
   appear in both train and test.
3. **On unseen attacks, results depend on luck (the seed).**
4. **The dataset has known quality issues:** broken rows, duplicates, and a duplicated column
   (`Fwd Header Length`).

### 3.10 How this maps to what was asked

| Professor asked | Where it's done |
|---|---|
| Public dataset, CIC-IDS2017 | Step 1: Friday + Wednesday CSVs, SHA-256 verified |
| Simple classifier | Depth-5 decision tree, 16 rules |
| Only switch-computable, first-few-packet features | EARLY set: 4 handshake fields. COUNTER is clearly marked as an optimistic bound, ALL as a ceiling only. |
| Precision and recall | Friday 0.9896 / 0.9995, plus CV, plus Wednesday 0.0855 / 0.0035 |
| One case where it fails, explained | Slowloris and Slowhttptest: normal handshake, low-rate, only detectable over time |
| Seed 46, stated | Used for the split, the CV and the models; stated here, in the report and in the code. `--seed` option for live changes. |

---

## 4. How this was built

The task, the plan (dataset mirror, the two files, the four feature sets, the decision tree,
the steps) and the seed came from my brief. I used Claude Code to write and run the scripts,
make the commits and draft the documents. Things added along the way:

- the bash 3.2 and Python environment fixes;
- the second fingerprint rule (window 256 **or** 8192);
- the seed-sensitivity investigation, after the seed-46 result didn't match the earlier seed-74
  numbers.

See [report/AI_USE.md](report/AI_USE.md) for the full disclosure.
