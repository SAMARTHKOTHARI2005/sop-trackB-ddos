"""Step 4b: is the seed-46 result stable, or does it depend on the seed?

The main results use seed 46. As a robustness check, this script retrains
the EARLY tree (same depth, same pipeline as 02_train.py) with seed 46 and
seeds 0-9, and shows that the same-day Friday score barely moves while the
cross-day Wednesday score jumps between a few discrete values. It also
prints the rules of the seed-46 tree next to the tree with the highest
Wednesday recall, so the difference can be read directly.

The seed changes (a) which rows land in the 70% train split and (b) the
tree's tie-breaking between equally good splits.

Usage:  python scripts/04_seed_sensitivity.py | tee outputs/04_seed_sensitivity.log
"""
import argparse

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

from common import DEFAULT_SEED, EARLY, FRIDAY, WEDNESDAY, clean, is_attack, load_csv, scores

ap = argparse.ArgumentParser()
ap.add_argument("--depth", type=int, default=5)
ap.add_argument("--seeds", type=int, nargs="+", default=[DEFAULT_SEED] + list(range(10)))
args = ap.parse_args()

WED_ATTACKS = ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]

fri = clean(load_csv(FRIDAY), "Friday")
wed = clean(load_csv(WEDNESDAY), "Wednesday")
y_fri, y_wed = is_attack(fri), is_attack(wed)

print(f"\nEARLY tree, depth {args.depth}")
print(f"{'seed':>4} | {'Fri P':>6} {'Fri R':>6} | {'Wed P':>6} {'Wed R':>6} | "
      + " ".join(f"{a.replace('DoS ', ''):>11}" for a in WED_ATTACKS) + " | leaves")
trees, wed_recall = {}, {}
for seed in args.seeds:
    # same split + tree as 02_train.py, just with a different seed
    tr, te = train_test_split(np.arange(len(fri)), test_size=0.30,
                              stratify=y_fri, random_state=seed)
    m = DecisionTreeClassifier(max_depth=args.depth, random_state=seed)
    m.fit(fri.loc[tr, EARLY], y_fri[tr])
    trees[seed] = m
    p_wed = m.predict(wed[EARLY])
    f, w = scores(y_fri[te], m.predict(fri.loc[te, EARLY])), scores(y_wed, p_wed)
    wed_recall[seed] = w["recall"]
    flagged = [p_wed[(wed["Label"] == a).values].mean() for a in WED_ATTACKS]
    print(f"{seed:>4} | {f['precision']:6.4f} {f['recall']:6.4f} | {w['precision']:6.4f} {w['recall']:6.4f} | "
          + " ".join(f"{x:11.4f}" for x in flagged) + f" | {m.get_n_leaves()}")

# Rules of the seed-46 tree and of the tree with the highest Wednesday recall
main, why = (DEFAULT_SEED, "main seed") if DEFAULT_SEED in trees else (args.seeds[0], "first seed given")
best = max(wed_recall, key=wed_recall.get)
show = [(main, why)] + ([(best, "highest Wednesday recall")] if best != main else [])
for seed, why in show:
    print(f"\n=== EARLY tree rules, seed {seed} ({why}) ===")
    print(export_text(trees[seed], feature_names=EARLY, max_depth=args.depth))
