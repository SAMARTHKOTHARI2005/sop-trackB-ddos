"""Step 4b: is the seed-46 result stable, or would another seed change it?

All the main results use seed 46. As a robustness check, this retrains the
EARLY tree (same depth and same steps as 02_train.py) with seed 46 and with
seeds 0-9. The Friday score barely moves, but the Wednesday score jumps
between a few fixed values. It also prints the rules of the seed-46 tree next
to the tree that did best on Wednesday, so you can see what's different.

The seed changes (a) which rows end up in the 70% training split and
(b) how the tree breaks ties between equally good splits.

Usage:  python scripts/04_seed_sensitivity.py | tee outputs/04_seed_sensitivity.log
"""
import argparse

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

from common import DEFAULT_SEED, EARLY, FRIDAY, WEDNESDAY, clean, is_attack, load_csv, scores

parser = argparse.ArgumentParser()
parser.add_argument("--depth", type=int, default=5)
parser.add_argument("--seeds", type=int, nargs="+", default=[DEFAULT_SEED] + list(range(10)))
args = parser.parse_args()

WED_ATTACKS = ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]

friday = clean(load_csv(FRIDAY), "Friday")
wednesday = clean(load_csv(WEDNESDAY), "Wednesday")
y_friday = is_attack(friday)
y_wednesday = is_attack(wednesday)

print(f"\nEARLY tree, depth {args.depth}")
print(f"{'seed':>4} | {'Fri P':>6} {'Fri R':>6} | {'Wed P':>6} {'Wed R':>6} | "
      + " ".join(f"{attack.replace('DoS ', ''):>11}" for attack in WED_ATTACKS) + " | leaves")

trees = {}
wed_recall = {}
for seed in args.seeds:
    # same split and tree as 02_train.py, just with a different seed
    train_idx, test_idx = train_test_split(np.arange(len(friday)), test_size=0.30,
                                           stratify=y_friday, random_state=seed)
    model = DecisionTreeClassifier(max_depth=args.depth, random_state=seed)
    model.fit(friday.loc[train_idx, EARLY], y_friday[train_idx])
    trees[seed] = model

    fri_result = scores(y_friday[test_idx], model.predict(friday.loc[test_idx, EARLY]))
    wed_pred = model.predict(wednesday[EARLY])
    wed_result = scores(y_wednesday, wed_pred)
    wed_recall[seed] = wed_result["recall"]
    caught = [wed_pred[(wednesday["Label"] == attack).values].mean() for attack in WED_ATTACKS]

    print(f"{seed:>4} | {fri_result['precision']:6.4f} {fri_result['recall']:6.4f} | "
          f"{wed_result['precision']:6.4f} {wed_result['recall']:6.4f} | "
          + " ".join(f"{share:11.4f}" for share in caught) + f" | {model.get_n_leaves()}")

# Print the rules of the seed-46 tree and of the tree with the best Wednesday recall
if DEFAULT_SEED in trees:
    main_seed, main_label = DEFAULT_SEED, "main seed"
else:
    main_seed, main_label = args.seeds[0], "first seed given"
best_seed = max(wed_recall, key=wed_recall.get)

to_show = [(main_seed, main_label)]
if best_seed != main_seed:
    to_show.append((best_seed, "highest Wednesday recall"))

for seed, label in to_show:
    print(f"\n=== EARLY tree rules, seed {seed} ({label}) ===")
    print(export_text(trees[seed], feature_names=EARLY, max_depth=args.depth))
