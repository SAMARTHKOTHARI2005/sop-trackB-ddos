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
from sklearn.tree import DecisionTreeClassifier

from common import DEFAULT_SEED, EARLY, is_attack, load_both_days, scores, table, tree_rules_table

parser = argparse.ArgumentParser()
parser.add_argument("--depth", type=int, default=5)
parser.add_argument("--seeds", type=int, nargs="+", default=[DEFAULT_SEED] + list(range(10)))
args = parser.parse_args()

WED_ATTACKS = ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]

friday, wednesday, cleaning_summary = load_both_days()
y_friday = is_attack(friday)
y_wednesday = is_attack(wednesday)
print("=== Cleaning ===")
print(cleaning_summary)

trees = {}
wed_recall = {}
rows = []
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
    caught = [float(wed_pred[(wednesday["Label"] == attack).values].mean()) for attack in WED_ATTACKS]
    rows.append([seed, fri_result["precision"], fri_result["recall"],
                 wed_result["precision"], wed_result["recall"]] + caught + [model.get_n_leaves()])

print(f"\n=== EARLY tree (depth {args.depth}) with each seed; the last attack columns = share of that attack caught ===")
print(table(["seed", "Fri precision", "Fri recall", "Wed precision", "Wed recall"]
            + [attack.replace("DoS ", "") for attack in WED_ATTACKS] + ["leaves"], rows))

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
    print(tree_rules_table(trees[seed], EARLY))
