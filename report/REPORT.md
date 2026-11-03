# Early-packet DDoS detection on CIC-IDS2017: trial report (draft)

*Student ID 2023A7PS0646P. All randomness uses seed 46 (last two digits of my ID).
Every number below comes from `outputs/`.*

## 1. Goal

Separate attack flows from benign flows using **only features a switch could compute from
the first few packets of a flow**, report precision and recall for the attack class, and
explain a case where the detector fails.

## 2. Method

**Data.** CIC-IDS2017 per-flow CSVs: Friday afternoon (DDoS, LOIC) for training and
same-day testing, and Wednesday (DoS Hulk, GoldenEye, slowloris, Slowhttptest) for a
cross-day test. I replaced inf with NaN, dropped NaN rows and dropped exact duplicate rows.
This left Friday with 223,082 flows (128,014 DDoS, 95,068 benign) and Wednesday with 610,492
flows (193,756 attack). Label: `y = (Label != "BENIGN")`. Friday was split 70/30 with
stratification (156,157 train, 66,925 test).

**Feature sets.**

| set | features | switch view |
|---|---|---|
| EARLY | Destination Port, Init_Win_bytes_forward, Init_Win_bytes_backward, min_seg_size_forward | fixed by the SYN / SYN-ACK headers (first 1-3 packets) |
| EARLY_NO_PORT | EARLY without Destination Port | ablation |
| COUNTER | Total Fwd/Bwd Packets, Total Length of Fwd Packets, Fwd Packet Length Max, Flow Duration | per-flow registers, but computed over the *whole* flow here, so an optimistic upper bound |
| ALL | all 78 CICFlowMeter features | reference ceiling only |

**Models.** DecisionTree with `max_depth=5` for EARLY, EARLY_NO_PORT and COUNTER, because a
shallow tree maps directly onto a few switch match-action table entries. ALL uses a
RandomForest with 100 trees. I also ran 5-fold stratified CV on the EARLY tree, a hand-rule
fingerprint check (`03_fingerprint_check.py`) and a seed-sensitivity check
(`04_seed_sensitivity.py`).

## 3. Results

**Friday, held-out 30% (same day), attack class:**

| model | precision | recall | TP | FP | FN | leaves |
|---|---|---|---|---|---|---|
| EARLY | 0.9896 | 0.9995 | 38,386 | 405 | 18 | 16 |
| EARLY_NO_PORT | 0.9451 | 0.9995 | 38,386 | 2,228 | 18 | 15 |
| COUNTER | 0.9995 | 0.9986 | 38,349 | 21 | 55 | 15 |
| ALL (RF) | 1.0000 | 0.9999 | 38,399 | 1 | 5 | – |

5-fold CV on the EARLY tree: precision 0.9896 ± 0.0004, recall 0.9998 ± 0.0000. Removing the
port raises false positives from 405 to 2,228. Of the 405 EARLY false positives, 390 are to
port 80 and 15 to port 21.

**The detector learned a tool fingerprint.** The EARLY tree's importances are
Init_Win_bytes_forward 0.585, Destination Port 0.331, Init_Win_bytes_backward 0.081 and
min_seg_size_forward 0.003. In the cleaned Friday data, DDoS flows use only two initial
windows: 256 (54.5%) and 8192 (45.3%). They go to port 80 (128,011 of 128,014) and all have
min_seg_size_forward = 20. The median initial window is 256 for DDoS and 229 for benign. A
hand rule with no training, `Init_Win_fwd ∈ {256, 8192} AND port == 80`, already gets
precision 0.9773 and recall 0.9983 on Friday. So the near-perfect same-day score mostly
reflects how the LOIC hosts' TCP stack fills in SYN headers, not "attack behaviour".

**Cross-day test: Friday-trained models on Wednesday (the failure case):**

| model | precision | recall | Hulk | GoldenEye | slowloris | Slowhttptest | benign flagged |
|---|---|---|---|---|---|---|---|
| EARLY | 0.0855 | 0.0035 | 0.0040 | 0.0000 | 0.0000 | 0.0000 | 0.0176 |
| EARLY_NO_PORT | 0.0178 | 0.0035 | 0.0040 | 0.0000 | 0.0000 | 0.0000 | 0.0909 |
| COUNTER | 0.4603 | 0.0029 | 0.0031 | 0.0000 | 0.0000 | 0.0063 | 0.0016 |
| ALL (RF) | 0.5073 | 0.0007 | 0.0008 | 0.0000 | 0.0000 | 0.0002 | 0.0003 |

(per-label columns = fraction of that label's flows flagged as attack)

All four detectors collapse on a new day and new tools. The richer models (COUNTER, ALL)
do no better than EARLY: more features only let them overfit Friday more precisely. The Friday
fingerprint rule catches 3 of 193,756 Wednesday attacks.

**Seed sensitivity.** I retrained the EARLY tree with 12 seeds. Friday precision stays
between 0.9893 and 0.9905 for all of them. Wednesday recall, however, takes only three values:
0.0035 (seed 46), 0.3075 or 0.5724 (e.g. seed 74). The seed-74 tree catches 64% of Hulk only
because of two tiny "attack" leaves, at Init_Win_fwd = 251 and Init_Win_fwd = 0. These come
from 17 and 27 rare Friday DDoS flows (out of 128,014) and happen to match Hulk's two most
common windows (0: 34.1%, 251: 32.6%). Same-day metrics cannot tell these trees apart, so any
cross-day "success" here is luck, not generalisation.

## 4. Failure case: slowloris and Slowhttptest

No model flags any slowloris flow, and the best gets 0.63% of Slowhttptest (COUNTER). The
reason is in their first packets. Their SYNs carry Init_Win_bytes_forward = 29200 (71.8% of
slowloris, 80.6% of Slowhttptest flows) or 229 (28.0% and 18.5%). 29200 is the usual Linux
default, and both values are common among ordinary Friday benign clients (229: 27.5%,
29200: 6.3%). The median min_seg_size_forward is 32 for slowloris and 40 for Slowhttptest;
32 and 40 also occur in benign traffic (23.9% and 2.2%). So the handshake looks like a normal
client's. These attacks are also **low-rate by design**: they open a connection and then send
partial headers slowly to hold server sockets. Volume counters (packet and byte totals,
max packet length) therefore look benign too, which is why even COUNTER and ALL miss them.
What gives them away is time-based state that only builds up after seconds: long flow
duration with little data, long idle gaps, and many concurrent half-open connections from
one source to one server. A switch detector would need per-source registers and timers for
this, not a per-flow decision at packet 1-3.

## 5. Main limitations

1. **Not true first-k-packet features.** The CSV has one row per finished flow, so I could
   only use fields that are fixed at the handshake. COUNTER is computed over the whole flow.
   Measuring accuracy as a function of k needs the pcaps.
2. **Random within-day splits overstate performance.** Friday train and test come from the
   same attackers, tool and hour, so 0.99 precision mainly measures fingerprint recall. The
   cross-day result (recall ≤ 0.0035 with seed 46) is the honest number.
3. **Results depend on the seed for unseen traffic.** See the seed-sensitivity paragraph.
4. **Dataset issues.** CIC-IDS2017 has known labelling and CICFlowMeter problems: I removed
   34 + 1,297 NaN/inf rows and 2,629 + 80,914 duplicate rows. `Fwd Header Length` appears twice,
   and `-1` in the window fields means "not observed".
