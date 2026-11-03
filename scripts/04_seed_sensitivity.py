"""Step 4b: how much do the results depend on the random seed?

With seed 46 the EARLY tree catches almost nothing on Wednesday, while an
earlier run with seed 74 caught ~57%. This script retrains the EARLY tree
(same depth, same pipeline as 02_train.py) for several seeds and shows that
the same-day Friday score barely moves while the cross-day Wednesday score
jumps between a few discrete values. It also prints the two trees' rules
so the difference can be read directly.

The seed changes (a) which rows land in the 70% train split and (b) the
tree's tie-breaking between equally good splits.

Usage:  python scripts/04_seed_sensitivity.py | tee outputs/04_seed_sensitivity.log
"""
import argparse

import numpy as np
from sklearn.metrics import precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

from common import DEFAULT_SEED, FRIDAY, WEDNESDAY, clean, load_csv

ap = argparse.ArgumentParser()
ap.add_argument("--depth", type=int, default=5)
ap.add_argument("--seeds", type=int, nargs="+", default=[DEFAULT_SEED, 74] + list(range(10)))
args = ap.parse_args()

EARLY = ["Destination Port", "Init_Win_bytes_forward",
         "Init_Win_bytes_backward", "min_seg_size_forward"]
WED_ATTACKS = ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]

fri = clean(load_csv(FRIDAY), "Friday")
wed = clean(load_csv(WEDNESDAY), "Wednesday")
y_fri = (fri["Label"] != "BENIGN").astype(int).values
y_wed = (wed["Label"] != "BENIGN").astype(int).values

print(f"\nEARLY tree, depth {args.depth}")
print(f"{'seed':>4} | {'Fri P':>6} {'Fri R':>6} | {'Wed P':>6} {'Wed R':>6} | "
      + " ".join(f"{a.replace('DoS ', ''):>11}" for a in WED_ATTACKS) + " | leaves")
trees = {}
for seed in args.seeds:
    tr, te = train_test_split(np.arange(len(fri)), test_size=0.30,
                              stratify=y_fri, random_state=seed)
    m = DecisionTreeClassifier(max_depth=args.depth, random_state=seed)
    m.fit(fri.loc[tr, EARLY], y_fri[tr])
    trees[seed] = m
    p_te = m.predict(fri.loc[te, EARLY])
    p_wed = m.predict(wed[EARLY])
    flagged = [p_wed[(wed["Label"] == a).values].mean() for a in WED_ATTACKS]
    print(f"{seed:>4} | {precision_score(y_fri[te], p_te):6.4f} {recall_score(y_fri[te], p_te):6.4f} | "
          f"{precision_score(y_wed, p_wed, zero_division=0):6.4f} {recall_score(y_wed, p_wed):6.4f} | "
          + " ".join(f"{f:11.4f}" for f in flagged) + f" | {m.get_n_leaves()}")

# Show the rules for the main seed and the earlier seed side by side
for seed in [s for s in [DEFAULT_SEED, 74] if s in trees]:
    print(f"\n=== EARLY tree rules, seed {seed} ===")
    print(export_text(trees[seed], feature_names=EARLY))
