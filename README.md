# SOP Trial Task, Track B: early-packet DDoS detection on CIC-IDS2017

Trial task for Dr. K Hari Babu (BITS Pilani). Samarth Kothari, student ID 2023A7PS0646P.

The aim is to build a simple classifier that tells attack traffic apart from normal (benign)
traffic, using only the features a network switch could work out from the first few packets
of a flow. I report precision and recall and go through one case where the detector fails.

Seed: anything random in this project (train/test split, CV folds, tree tie-breaking, the
random forest) uses seed 46, which is the last two digits of my ID 2023A7PS0646P. The only
exception is `scripts/04_seed_sensitivity.py`, which re-runs the EARLY tree with other seeds
on purpose to check how stable the results are.

| Document | What's in it |
|---|---|
| [report/REPORT.pdf](report/REPORT.pdf) ([.md](report/REPORT.md)) | The main report, 2 pages: goal, method, results, failure case, limitations |
| [report/STUCK_NOTES.md](report/STUCK_NOTES.md) | Things I got stuck on and how I fixed them |
| [report/WEEK2.md](report/WEEK2.md) | What I'd do in week 2 |
| [report/AI_USE.md](report/AI_USE.md) | How I used AI tools |

### Quick summary of results

| | Precision | Recall |
|---|---|---|
| EARLY tree (4 handshake fields, 16 rules), Friday held-out test | 0.9896 | 0.9995 |
| Same tree, 5-fold CV on Friday | 0.9896 ± 0.0004 | 0.9998 ± 0.0000 |
| Same tree, run on a different day (Wednesday) | 0.0855 | 0.0035 |

The very high same-day score mostly comes from the model recognising the TCP handshake of the
attack tool. Once I tested it on a different day with different attack tools it stopped
working, and it missed slow attacks like slowloris entirely. The walkthrough below has the
details.

---

## Contents

1. [Setup and exact commands](#1-setup-and-exact-commands)
2. [Repo layout](#2-repo-layout)
3. [Walkthrough of everything I did](#3-walkthrough-of-everything-i-did)
   - [3.0 What the task asks for](#30-what-the-task-asks-for)
   - [3.1 Step 0: setting up the repo](#31-step-0-setting-up-the-repo)
   - [3.2 Step 1: getting the data](#32-step-1-getting-the-data)
   - [3.3 Step 2: looking at the data first](#33-step-2-looking-at-the-data-first)
   - [3.4 Step 3: the main experiment](#34-step-3-the-main-experiment)
   - [3.5 Step 4: is it actually detecting attacks?](#35-step-4-is-it-actually-detecting-attacks)
   - [3.6 The failure case: Wednesday](#36-the-failure-case-wednesday)
   - [3.7 Step 4b: the seed problem](#37-step-4b-the-seed-problem)
   - [3.8 Step 5: the write-ups](#38-step-5-the-write-ups)
   - [3.9 Main limitations](#39-main-limitations)
   - [3.10 Checklist against the task](#310-checklist-against-the-task)
4. [How this was built](#4-how-this-was-built)

---

## 1. Setup and exact commands

I ran this on macOS with Python 3.9.6, pandas 2.3.3, numpy 2.0.2 and scikit-learn 1.6.1.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

To run the whole pipeline in one go (about a minute once the CSVs are downloaded):

```bash
bash run_all.sh
```

It runs the five steps below in order, shows the output live and saves each log in `outputs/`.
Since everything uses seed 46, a rerun should reproduce the committed outputs exactly, and
`git status outputs/` should show no changes afterwards.

To run the steps one at a time instead: all commands are run from the repo root, and this is
exactly what I ran to get the files in `outputs/`, in this order:

```bash
# 1. Download the two CSVs (~74 MB + ~215 MB) into data/, write and verify data/SHA256SUMS.
bash scripts/00_download.sh
#    (ran it once more to save the check output; it skips files that are already there)
bash scripts/00_download.sh 2>&1 | tee outputs/00_download.log

# 2. Shape, labels, columns, NaN/inf and duplicate rows.
.venv/bin/python scripts/01_inspect.py > outputs/01_inspect.log 2>&1

# 3. Train and evaluate (seed 46, depth 5). Takes ~30 s and writes
#    outputs/02_train.log, outputs/results.json and outputs/tree_early_rules.txt on its own.
.venv/bin/python scripts/02_train.py

# 4. TCP fingerprint check: is the detector just recognising the attack tool?
.venv/bin/python scripts/03_fingerprint_check.py > outputs/03_fingerprint.log 2>&1

# 5. Robustness check: EARLY tree with seed 46 and seeds 0-9.
.venv/bin/python scripts/04_seed_sensitivity.py > outputs/04_seed_sensitivity.log 2>&1
```

### Changing the depth or seed

`02_train.py` accepts `--depth` (default 5), `--seed` (default 46), `--trees` (default 100)
and `--out` (default `outputs/`). It's best to give a different `--out` folder so the main
results don't get overwritten:

```bash
.venv/bin/python scripts/02_train.py --depth 3 --out outputs/depth3
.venv/bin/python scripts/04_seed_sensitivity.py --depth 3 --seeds 46 1 2
```

For example, with `--depth 3` the EARLY tree has 7 rules instead of 16 and Friday precision
goes down from 0.9896 to 0.9743. So a smaller switch table costs you more false alarms.

> Note for VS Code: if the `sklearn` imports have yellow squiggly lines under them, VS Code is
> pointing at the system Python, which doesn't have scikit-learn. Fix it with `Cmd+Shift+P` →
> Python: Select Interpreter → `.venv/bin/python`.

---

## 2. Repo layout

```
run_all.sh                  runs all the steps below in order and saves the logs
scripts/
  00_download.sh            downloads the two CSVs and checks SHA-256 (GitHub LFS mirror)
  common.py                 shared paths, CSV loader (strips spaces in column names), clean()
  01_inspect.py             shape, label counts, columns, NaN/inf/duplicate counts
  02_train.py               feature sets, trees + RF, Friday test, 5-fold CV, Wednesday test
  03_fingerprint_check.py   initial window distributions + single hand-written rules
  04_seed_sensitivity.py    EARLY tree retrained with several seeds
data/
  SHA256SUMS                checksums of the two CSVs (the CSVs are gitignored)
outputs/
  00_download.log  01_inspect.log  02_train.log  03_fingerprint.log  04_seed_sensitivity.log
  results.json              every number from 02_train.py
  tree_early_rules.txt      the EARLY tree as a rule table (one row per leaf) and as if/else rules
report/
  REPORT.pdf  REPORT.md  STUCK_NOTES.md  WEEK2.md  AI_USE.md
```

---

## 3. Walkthrough of everything I did

### 3.0 What the task asks for

The task has four parts:

1. Use a public traffic dataset (CIC-IDS2017).
2. Train a simple classifier to separate attack traffic from normal traffic, using only
   features a network switch could compute from the first few packets of a connection.
3. Report precision and recall.
4. Explain one case where the detector fails.

On top of that, seed 46 has to be used for anything random, and I have to mention it.

The second point is what makes this tricky. Most ML-based intrusion detectors look at a
connection after it's over and use all 78 statistics. Here the detector is supposed to be
something that could run inside a switch, i.e. the device that forwards packets in the
network. Switches are extremely fast but can't do much. They can read header fields, look
them up in small tables ("if port is 80 and window is 256, then do X"), and keep a handful of
counters. They can't run a neural network and they can't wait for a connection to finish. So
the real question is whether you can spot an attack almost straight away, from the first one
to three packets.

### 3.1 Step 0: setting up the repo

I made four folders: `scripts/` for code, `data/` for the dataset, `outputs/` for logs and
results, and `report/` for the write-ups. The `.gitignore` keeps the CSV files out of git.
They're 74 MB and 215 MB, which is too big for a normal GitHub repo, and the download script
can fetch them again anyway.

`requirements.txt` has the three libraries I needed:

- pandas, to load the CSV tables
- numpy, for the number crunching
- scikit-learn, for the models

The Python that comes with the Mac didn't have scikit-learn, so I set up a virtual
environment (`.venv`). It's basically a separate Python install just for this project, and I
installed the three libraries into it.

Since the professor wanted to see the commit history, I committed and pushed after each step
instead of uploading everything at the end.

### 3.2 Step 1: getting the data

Script: `scripts/00_download.sh`

**About CIC-IDS2017.** In 2017 the Canadian Institute for Cybersecurity (CIC, University of New
Brunswick) set up a mock company network and recorded all of its traffic for 5 days. Most of
it is normal activity like browsing and email, but on certain days they also ran real attacks
from attacker machines.

They then processed the recordings with a tool called CICFlowMeter. It groups packets into
flows, where a flow is one conversation between two machines (identified by source IP,
destination IP, source port, destination port and protocol). For each flow it calculates 78
numbers, things like duration, packet counts, byte counts and window sizes, and attaches a
label, either `BENIGN` or the name of the attack. The "MachineLearningCVE" CSVs are this
table, one row per flow.

**The two files I picked.**

- Friday afternoon has a DDoS attack (Distributed Denial of Service, where lots of machines
  flood one web server). The tool used was LOIC. This is the day I trained on.
- Wednesday has four other DoS attacks, all against the same kind of web server: Hulk,
  GoldenEye, slowloris and Slowhttptest (plus 11 Heartbleed flows, which also count as
  attacks). I only used this day as an unseen test, to find where the detector breaks.

**Where I downloaded them from.** The official CIC server wasn't reachable, so the script pulls
the files from a public GitHub repo (`2000pawan/Cyber-Attack-Threat-Classification`) where
someone had uploaded the same CSVs.

This caused a small problem. GitHub stores large files with Git LFS (Large File Storage), so
the repo itself only has a short text "pointer" saying roughly "the real file has hash X and
size Y and is stored somewhere else". The usual `raw.githubusercontent.com` link just returns
that 130-byte pointer. The `media.githubusercontent.com` link returns the actual file. The
script uses the media link and also checks that what it downloaded isn't a pointer file.

**Checking the files with SHA-256.** Because the data came from someone's GitHub and not from
CIC directly, I wanted to make sure the files were complete and unchanged. SHA-256 gives a
fingerprint of a file's contents, and changing even one byte gives a totally different hash.

The script computes the hash of both files, saves them in `data/SHA256SUMS`, and checks that
they start with the values I expected. Both matched. The Friday hash is also the same as the
LFS object ID for that file, so it really is the file the mirror says it is.

| file | SHA-256 |
|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | `6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee` |
| Wednesday-workingHours.pcap_ISCX.csv | `893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a` |

One small issue: my first version of the script used associative arrays in bash, which the old
bash on macOS (3.2) doesn't support. I replaced that part with a `case` statement.

### 3.3 Step 2: looking at the data first

Script: `scripts/01_inspect.py`

Before training anything I wanted to see what the data actually looks like. This script
prints the size of each file, how many rows each label has, all the column names, and how many
rows have bad values. Here's what came out:

| | Friday | Wednesday |
|---|---|---|
| Rows × columns | 225,745 × 79 | 692,703 × 79 |
| Labels | 128,027 DDoS, 97,718 benign | 440,031 benign, 231,073 Hulk, 10,293 GoldenEye, 5,796 slowloris, 5,499 Slowhttptest, 11 Heartbleed |
| Rows with NaN or infinity | 34 | 1,297 |
| Exact duplicate rows | 2,633 | 81,909 |

The 79 columns are 78 features plus the label. A few problems turned up:

- Column names start with a space. The header actually says `" Label"` and not `"Label"`, so
  `df["Label"]` doesn't work. `scripts/common.py` strips the spaces from every column name when
  it loads a file, and all the scripts use that loader.
- NaN and infinity values. "Flow Bytes/s" and "Flow Packets/s" are rates (bytes or packets
  divided by duration). If a flow lasted 0 seconds, that's a division by zero, which gives
  infinity or NaN. The models can't take those values.
- Duplicate rows. If the same row ends up in both the training and test set, the model gets
  tested on something it has already seen, which is a bit like having the exam questions
  beforehand. It makes the score look better than it is.

### 3.4 Step 3: the main experiment

Script: `scripts/02_train.py`

#### Cleaning

1. Replace infinities with NaN.
2. Drop any row that has a NaN.
3. Drop exact duplicate rows. I do this before the train/test split so the same row can't be
   in both.

After cleaning, Friday has 223,082 flows (128,014 DDoS, 95,068 benign) and Wednesday has
610,492, of which 193,756 are attacks (including the 11 Heartbleed flows).

The label is just yes/no: y = 1 if Label isn't "BENIGN", otherwise 0. So the model only has to
say "attack or not", not which attack it is.

#### Train/test split

Friday is split into 70% training and 30% testing (156,157 and 66,925 flows). The model learns
from the 70% and is scored on the 30% it hasn't seen.

The split is stratified, meaning both parts have the same ratio of attack to benign as the
full day.

Since the split is random, it uses seed 46. The seed sets where the random number generator
starts, so the same seed always gives the same split. That way anyone can rerun it and get the
same numbers I did.

#### The four feature sets

This is the main part of the project. Each feature set is there to answer a different
question.

**EARLY**, which is the actual answer to the task. All four of these values are decided within
the first 1-3 packets. A TCP connection starts with a handshake: the client sends a SYN, the
server answers with a SYN-ACK, and the client sends an ACK. These features come from those
packets:

| Feature | What it means |
|---|---|
| Destination Port | The service being contacted. 80 is web, 443 is HTTPS, 53 is DNS. |
| Init_Win_bytes_forward | The TCP window value in the client's first packet, roughly "how much data I can take in at once". It's set by the operating system, so it works a bit like a signature of the client's OS or software. 8192 is a typical Windows value and 29200 is the usual Linux one. -1 means it was never seen. |
| Init_Win_bytes_backward | Same thing, but from the server's reply. |
| min_seg_size_forward | In practice this is the smallest header size the client sent. 20 means plain headers and 32 means there were extra options like timestamps. Also a kind of OS/software signature. |

A switch can read all four straight from the packet headers, which is why this is the set
that actually fits the task.

**EARLY_NO_PORT**. This is EARLY with the port taken out. It's there to see how much the model
depends on "is this port 80?". If the score drops a lot without it, the port was carrying a
lot of the weight.

**COUNTER**. Switches can keep a few counters per flow in registers, like packets so far,
bytes so far, or the biggest packet so far. COUNTER uses Total Fwd Packets, Total Backward
Packets, Total Length of Fwd Packets, Fwd Packet Length Max and Flow Duration. The problem is
that in the CSV these are final totals for the whole flow, not values after 3 packets. A real
switch would only have partial counts, so this set is an optimistic upper bound and does
better than a switch actually could.

**ALL**. All 78 features, given to a random forest (100 decision trees that vote). There's no
way a switch could run this. It's only there as a ceiling, to show the best score you can get
on this data and how much you give up by sticking to EARLY.

#### Why a decision tree, and why depth 5

A decision tree is basically a flowchart of yes/no questions:

```
Is Init_Win_bytes_forward > 255.5?
 ├─ yes → Is Destination Port ≤ 84?
 │         ├─ yes → ... → ATTACK
 │         └─ no  → BENIGN
 └─ no  → ... → BENIGN
```

Every path from the top down to a leaf is one rule, something like "if the window is in this
range and the port is in that range, it's an attack". That's pretty much how a switch's
match-action table works: it matches header fields against ranges and then takes an action
(forward, drop or flag). So a tree like this can be moved onto switch hardware almost
directly.

With depth 5 there are at most 5 questions on any path, so at most 2⁵ = 32 rules, which is
small enough for a switch. The EARLY tree ended up with 16 leaves. Depth can be changed with
`--depth`. Its rules, one table row per leaf, are in [outputs/tree_early_rules.txt](outputs/tree_early_rules.txt).

#### Precision and recall

One way to think about it is a security guard at a door who flags people.

- TP (true positive): an attacker who gets flagged.
- FP (false positive): a normal user who gets flagged by mistake, i.e. a false alarm.
- FN (false negative): an attacker who isn't flagged and gets through.
- TN (true negative): a normal user who is correctly let in.

Then:

- Precision = TP / (TP + FP). Out of all the alarms, how many were real attackers? Low
  precision means lots of false alarms, which on a network means blocking real users.
- Recall = TP / (TP + FN). Out of all the attackers, how many got caught? Low recall means
  attacks get through.

#### Friday results (same-day test)

| Model | Precision | Recall | False alarms (FP) | Missed attacks (FN) | Leaves |
|---|---|---|---|---|---|
| EARLY | 0.9896 | 0.9995 | 405 | 18 | 16 |
| EARLY_NO_PORT | 0.9451 | 0.9995 | 2,228 | 18 | 15 |
| COUNTER | 0.9995 | 0.9986 | 21 | 55 | 15 |
| ALL (RF) | 1.0000 | 0.9999 | 1 | 5 | – |

Taken at face value, a 16-rule tree on 4 handshake fields catches 99.95% of DDoS flows, and
about 99% of the flows it flags really are attacks. Dropping the port increases false alarms
by more than 5 times, so the port clearly matters.

I also ran 5-fold cross-validation, which repeats the train/test process on five different
splits. Precision came out at 0.9896 ± 0.0004, so the result isn't just a lucky split.

The script also saves:

- the tree's rules (`outputs/tree_early_rules.txt`), which is basically the switch table
- the feature importances, i.e. how much each feature contributed. Init_Win_bytes_forward was
  58.5% and the port 33.1%.
- the ports of the false alarms: 390 to port 80 (web) and 15 to port 21 (FTP). So some normal
  web traffic looks enough like the attack traffic that the tree flags it.

These numbers seemed too good to me, which is what led to the next step.

### 3.5 Step 4: is it actually detecting attacks?

Script: `scripts/03_fingerprint_check.py`

The tree depends mainly on one field, the TCP window, and that value is set by the operating
system or by the attack tool. That made me suspect that the model had learned to recognise
the LOIC attacking machines rather than attack behaviour in general.

So the script lists the most common window values for DDoS flows and for benign flows on
Friday:

- DDoS: 256 (54.5%) and 8192 (45.3%). Those two values alone cover 99.8% of the DDoS flows.
  Also, every DDoS flow has a min header size of 20, and all but 3 of them go to port 80.
- Benign: lots of different values, like -1, 229, 8192, 29200, 65535 and others.

Next, it tests some simple hand-written rules, with no machine learning involved:

| Rule | Friday precision | Friday recall | Wednesday recall |
|---|---|---|---|
| window = 256 AND port 80 | 0.9951 | 0.5451 | 0.0000 |
| window = 256 or 8192, AND port 80 | 0.9773 | 0.9983 | 0.0000 |
| port 80 only | 0.9374 | 1.0000 | 0.9999 (but 45,979 benign flows get flagged too) |

The two-value rule does nearly as well as the trained tree on Friday. So the tree's high score
mostly comes down to recognising the handshake signature of the attack tool. To use the guard
example again, it's like a guard who catches every robber only because all the robbers that
day happened to wear the same red jacket. It works until the robbers turn up in different
clothes.

### 3.6 The failure case: Wednesday

The task asks for one case where the detector fails. To find one, I took the models trained on
Friday and ran them on Wednesday, which has different attack tools, without retraining them.
That's the "robbers in different clothes" situation.

| Model | Precision | Recall | Hulk caught | GoldenEye | slowloris | Slowhttptest |
|---|---|---|---|---|---|---|
| EARLY | 0.0855 | 0.0035 | 0.4% | 0% | 0% | 0% |
| EARLY_NO_PORT | 0.0178 | 0.0035 | 0.4% | 0% | 0% | 0% |
| COUNTER | 0.4603 | 0.0029 | 0.3% | 0% | 0% | 0.6% |
| ALL (RF) | 0.5073 | 0.0007 | 0.08% | 0% | 0% | 0.02% |

None of the models hold up. EARLY catches 0.35% of the attacks, and even the random forest
with all 78 features catches almost nothing. Giving it more features just lets it fit Friday
more closely. The Friday fingerprint rule catches 3 out of 193,756 attacks on Wednesday.

#### The specific failure: slowloris and Slowhttptest

These attacks work differently from a flood. A web server can only hold a certain number of
connections at once. Think of it as a restaurant with a fixed number of tables. A flood like
LOIC is a crowd pushing through the door. Slowloris is more like a customer who sits down and
orders one word every 10 seconds ("I'd… like… the…") and never finishes, so the waiter has to
keep the table. If every table is taken like that, the restaurant is full even though each
customer looks perfectly polite.

The detector can't see this in the first few packets because:

1. The handshake looks completely normal. Their window values are 29200 (72-81% of flows) and
   229 (18-28%), and normal clients use the same values. On Friday, 229 makes up 27.5% of
   benign flows and 29200 makes up 6.3%. They're using the regular Linux network stack, so
   there's nothing unusual about the "jacket".
2. They're low-volume on purpose: few packets, few bytes, small packets. So the volume
   counters (COUNTER, ALL) don't see anything strange either.
3. What actually gives them away only shows up over time: connections that stay open for a
   long time with very little data, long gaps with nothing sent, and one source holding lots of
   half-finished connections. A switch would need timers and per-source counters for that, and
   it would need to watch for several seconds, not 1-3 packets.

So this is the main limitation. Detecting from the first packets works on tools with an
obvious signature, but not on attacks that are designed to look normal and go slowly.

### 3.7 Step 4b: the seed problem

Script: `scripts/04_seed_sensitivity.py`

With seed 46 the EARLY tree caught only 0.35% of the Wednesday attacks. I wanted to know
whether that number is stable or just how this particular tree turned out, so as a robustness
check I retrained the EARLY tree with seed 46 and seeds 0-9 (11 trees). Seed 46 is still the
main result everywhere else.

- Friday precision hardly changes, staying between 0.9893 and 0.9905.
- Wednesday recall only ever takes one of three values: 0.0035 (seed 46), 0.3075 or 0.5724.
  The best case, e.g. seed 1, catches 64% of Hulk.

To find out why, I compared the rules of the seed-46 tree with the seed-1 tree. The seed-1 tree
has two extra small "attack" rules:

- "window = 0" (and port up to 261), a leaf that holds only 22 of the 156,157 training flows
- "window = 251" (and port up to 84), a leaf that holds only 2 training flows

These window values are rare on Friday anyway: only 27 and 17 of the 128,014 DDoS flows have
them. Both leaves are in the rules table at the end of `outputs/04_seed_sensitivity.log`.

As it happens, the two most common window values for Hulk are 0 (34%) and 251 (33%). So the
seed-1 tree catches Hulk because of two tiny rules that just happen to line up, not because
it learned anything useful. The seed-46 tree labels those same values as benign.

What I take from this is that same-day accuracy can't tell a lucky tree from an unlucky one,
so any success on new attack types here is basically coincidence. That's why the report says
testing should be done across different days. I kept seed 46 as the main result, as the task
requires, and report this as a limitation instead of choosing whichever seed looks best.

### 3.8 Step 5: the write-ups

| File | What's in it |
|---|---|
| `README.md` | This file: setup, exact commands, layout, walkthrough |
| `report/REPORT.pdf` / `REPORT.md` | The 2-page report: goal, method, results, failure case, limitations |
| `report/STUCK_NOTES.md` | The problems I hit and how I fixed them: server down, LFS pointers, spaces in column names, NaN/infinity, duplicates, bash 3.2, missing sklearn, the seed check |
| `report/WEEK2.md` | Plan for week 2: get the raw packet captures (pcaps), compute real first-k-packet features for k = 2 to 10, always test across days, add per-source timers for slow attacks, put the tree into a P4 switch program on BMv2/Mininet, and connect it to my ResilientDAG work |
| `report/AI_USE.md` | How I used AI tools |

All the numbers in the reports are taken from the files in `outputs/`.

### 3.9 Main limitations

1. These aren't true first-k-packet features. The CSV has one row per finished flow, so I
   could only use fields that are fixed during the handshake. Doing this properly needs the raw
   packet captures, which is the plan for week 2.
2. Splitting randomly within a single day makes the model look better than it is, since the
   same attacker, tool and time window show up in both train and test.
3. On attacks the model hasn't seen, the result depends on the seed, i.e. on luck.
4. The dataset has some known quality problems: broken rows, duplicates, and a column that
   appears twice (`Fwd Header Length`).

### 3.10 Checklist against the task

| Asked for | Where it's done |
|---|---|
| Public dataset, CIC-IDS2017 | Step 1: Friday + Wednesday CSVs, SHA-256 checked |
| Simple classifier | Depth-5 decision tree, 16 rules |
| Only switch-computable, first-few-packet features | EARLY set: 4 handshake fields. COUNTER is marked as an optimistic bound and ALL as a reference ceiling only. |
| Precision and recall | Friday 0.9896 / 0.9995, CV, and Wednesday 0.0855 / 0.0035 |
| One failure case, explained | Slowloris and Slowhttptest: normal handshake, low-rate, only detectable over time |
| Seed 46, stated | Used for the split, CV and models; mentioned here, in the report and in the code. `--seed` can be changed live. |

---

## 4. How this was built

The task, the overall plan (dataset mirror, the two files, the four feature sets, the decision
tree, the steps), the seed and the week-2 direction were from my own brief, after reading up on
CIC-IDS2017, LOIC and P4 and an earlier attempt of my own. I also set up the
repo, made the decisions along the way (seed 46 only, other seeds just as a robustness check),
checked everything against the professor's requirements, asked for the clean-up and table
formatting, and re-ran the pipeline myself.

I used Claude Code for all the coding, most of the analysis, the commits and drafting the
documents. A few things it added while doing it:

- fixes for bash 3.2 and the Python environment
- the second fingerprint rule (window 256 or 8192)
- the seed robustness check, to see whether the seed-46 cross-day result was stable

The full disclosure is in [report/AI_USE.md](report/AI_USE.md).
