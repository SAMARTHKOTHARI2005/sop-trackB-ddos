"""Step 3: train attack-vs-benign classifiers on Friday (DDoS), test them on a
held-out part of Friday, and then on a completely different day (Wednesday,
different DoS tools) to find where they fail.

Feature sets (the report explains why):
  EARLY          header fields fixed by the first 1-3 packets (SYN / SYN-ACK)
  EARLY_NO_PORT  EARLY without Destination Port, to see how much the port matters
  COUNTER        per-flow counters a switch could keep in registers; in this CSV
                 they cover the WHOLE flow, so this is an optimistic upper bound
  ALL            all 78 CICFlowMeter features in a random forest, only as a ceiling

Everything random (train/test split, CV folds, trees) uses --seed, which
defaults to 46 (last two digits of my ID, 2023A7PS0646P).

Usage:
  python scripts/02_train.py                       # depth 5, seed 46, writes to outputs/
  python scripts/02_train.py --depth 3 --out outputs/depth3
"""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

from common import (DEFAULT_SEED, EARLY, FRIDAY, OUTPUTS, WEDNESDAY,
                    clean, is_attack, load_csv, scores)

parser = argparse.ArgumentParser()
parser.add_argument("--depth", type=int, default=5, help="max depth of the decision trees")
parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="random seed (default 46)")
parser.add_argument("--trees", type=int, default=100, help="number of trees in the ALL random forest")
parser.add_argument("--out", default=str(OUTPUTS), help="folder to write the logs and results to")
args = parser.parse_args()

out_dir = Path(args.out)
out_dir.mkdir(parents=True, exist_ok=True)
log_lines = []


def log(*parts):
    """Like print(), but also keeps the line so it can be saved to 02_train.log."""
    line = " ".join(str(p) for p in parts)
    print(line)
    log_lines.append(line)


def tree():
    """The shallow decision tree used for EARLY, EARLY_NO_PORT and COUNTER."""
    return DecisionTreeClassifier(max_depth=args.depth, random_state=args.seed)


EARLY_NO_PORT = [col for col in EARLY if col != "Destination Port"]
COUNTER = ["Total Fwd Packets", "Total Backward Packets",
           "Total Length of Fwd Packets", "Fwd Packet Length Max", "Flow Duration"]

log(f"seed = {args.seed}   tree depth = {args.depth}   RF trees = {args.trees}")

# Load and clean both days
friday = clean(load_csv(FRIDAY), "Friday", log)
wednesday = clean(load_csv(WEDNESDAY), "Wednesday", log)
ALL = [col for col in friday.columns if col != "Label"]
log(f"ALL feature count: {len(ALL)}")

y_friday = is_attack(friday)
y_wednesday = is_attack(wednesday)
log("Friday labels after cleaning:", friday["Label"].value_counts().to_dict())
log("Wednesday labels after cleaning:", wednesday["Label"].value_counts().to_dict())

# Stratified 70/30 split of Friday. Split the row numbers, so every model
# is trained and tested on exactly the same rows.
train_idx, test_idx = train_test_split(np.arange(len(friday)), test_size=0.30,
                                       stratify=y_friday, random_state=args.seed)
log(f"Friday split: train {len(train_idx)}  test {len(test_idx)}")

models = {
    "EARLY": (EARLY, tree),
    "EARLY_NO_PORT": (EARLY_NO_PORT, tree),
    "COUNTER": (COUNTER, tree),
    "ALL": (ALL, lambda: RandomForestClassifier(n_estimators=args.trees,
                                                random_state=args.seed, n_jobs=-1)),
}

results = {"seed": args.seed, "depth": args.depth, "rf_trees": args.trees,
           "features": {"EARLY": EARLY, "EARLY_NO_PORT": EARLY_NO_PORT, "COUNTER": COUNTER,
                        "ALL": f"{len(ALL)} features"},
           "rows": {"friday_clean": len(friday), "wednesday_clean": len(wednesday),
                    "friday_train": len(train_idx), "friday_test": len(test_idx)},
           "friday_test": {}, "wednesday": {}}
trained = {}

# Train on Friday's 70% and score on the other 30%
log("\n=== Friday held-out test (30%), attack class ===")
for name, (features, make_model) in models.items():
    model = make_model().fit(friday.loc[train_idx, features], y_friday[train_idx])
    trained[name] = model
    result = scores(y_friday[test_idx], model.predict(friday.loc[test_idx, features]))
    if isinstance(model, DecisionTreeClassifier):
        result["leaves"] = int(model.get_n_leaves())
    results["friday_test"][name] = result
    log(f"{name:14s} " + "  ".join(f"{k}={v}" for k, v in result.items()))

# Which features each model relies on (top 10)
log("\n=== feature importances ===")
results["importances"] = {}
for name, (features, _) in models.items():
    importances = pd.Series(trained[name].feature_importances_, index=features)
    importances = importances.sort_values(ascending=False).head(10)
    results["importances"][name] = {k: round(float(v), 4) for k, v in importances.items()}
    log(f"[{name}] " + ", ".join(f"{k}={v:.4f}" for k, v in importances.items()))

# 5-fold stratified cross-validation of the EARLY tree on all of Friday
folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
cv_results = cross_validate(tree(), friday[EARLY], y_friday, cv=folds,
                            scoring=["precision", "recall"])
cv_precision = cv_results["test_precision"]
cv_recall = cv_results["test_recall"]
results["cv_early"] = {
    "precision_mean": round(float(cv_precision.mean()), 4),
    "precision_std": round(float(cv_precision.std()), 4),
    "recall_mean": round(float(cv_recall.mean()), 4),
    "recall_std": round(float(cv_recall.std()), 4),
    "precision_folds": [round(float(v), 4) for v in cv_precision],
    "recall_folds": [round(float(v), 4) for v in cv_recall],
}
log("\n=== 5-fold stratified CV, EARLY tree, Friday ===")
log(json.dumps(results["cv_early"]))

# Save the EARLY tree as if/else rules (these would become switch table entries)
early_tree = trained["EARLY"]
(out_dir / "tree_early_rules.txt").write_text(
    f"# EARLY DecisionTree, max_depth={args.depth}, seed={args.seed}, "
    f"leaves={early_tree.get_n_leaves()}\n# class 1 = attack, class 0 = benign\n"
    + export_text(early_tree, feature_names=EARLY, max_depth=args.depth))

# Which ports do the EARLY tree's false alarms on the Friday test set go to?
test_rows = friday.loc[test_idx]
false_alarm = (early_tree.predict(test_rows[EARLY]) == 1) & (y_friday[test_idx] == 0)
false_alarm_ports = test_rows.loc[false_alarm, "Destination Port"].value_counts().head(15)
results["early_false_positive_ports"] = {str(port): int(n) for port, n in false_alarm_ports.items()}
log(f"\n=== EARLY false positives on Friday test: {int(false_alarm.sum())} flows, top destination ports ===")
log(false_alarm_ports.to_string())

# Failure case: run the Friday-trained models, unchanged, on Wednesday
log("\n=== Cross-day: Friday-trained models on Wednesday (all rows) ===")
for name, (features, _) in models.items():
    predictions = trained[name].predict(wednesday[features])
    result = scores(y_wednesday, predictions)
    share_flagged = pd.Series(predictions).groupby(wednesday["Label"].values).mean()
    result["fraction_flagged_per_label"] = {label: round(float(v), 4) for label, v in share_flagged.items()}
    results["wednesday"][name] = result
    log(f"{name:14s} precision={result['precision']} recall={result['recall']} "
        f"TP={result['TP']} FP={result['FP']} FN={result['FN']} TN={result['TN']}")
    log("    fraction flagged as attack per label: " +
        ", ".join(f"{label}={v:.4f}" for label, v in result["fraction_flagged_per_label"].items()))

# Median EARLY values per day and label, to see why it fails
both_days = pd.concat([friday.assign(Day="Friday"), wednesday.assign(Day="Wednesday")])
by_day_label = both_days.groupby(["Day", "Label"])
medians = by_day_label[EARLY].median()
medians["n_flows"] = by_day_label.size()
results["median_early_features"] = {f"{day}|{label}": {k: float(v) for k, v in row.items()}
                                    for (day, label), row in medians.iterrows()}
log("\n=== median EARLY feature values per (day, label) ===")
log(medians.to_string())

# Save everything
(out_dir / "results.json").write_text(json.dumps(results, indent=2))
(out_dir / "02_train.log").write_text("\n".join(log_lines) + "\n")
log(f"\nwrote {out_dir/'results.json'}, {out_dir/'02_train.log'}, {out_dir/'tree_early_rules.txt'}")
