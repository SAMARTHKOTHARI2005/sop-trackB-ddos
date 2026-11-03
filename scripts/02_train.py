"""Step 3: train attack-vs-benign classifiers on Friday (DDoS) and test them
on a held-out Friday split AND on a different day (Wednesday, DoS attacks).

Feature sets (see README / report for the reasoning):
  EARLY          header fields fixed by the first 1-3 packets (SYN / SYN-ACK)
  EARLY_NO_PORT  EARLY without Destination Port (ablation)
  COUNTER        per-flow counters a switch could keep in registers; in this
                 CSV they are computed over the WHOLE flow -> optimistic bound
  ALL            all 78 CICFlowMeter features, RandomForest, reference ceiling

Every source of randomness (train/test split, CV folds, trees) uses --seed.
Default seed = 46 (last two digits of student ID 2023A7PS0646P).

Usage:
  python scripts/02_train.py                       # depth 5, seed 46 -> outputs/
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

# ---------------------------------------------------------------- arguments
ap = argparse.ArgumentParser()
ap.add_argument("--depth", type=int, default=5, help="max depth of the decision trees")
ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help="random seed (default 46)")
ap.add_argument("--trees", type=int, default=100, help="trees in the ALL random forest")
ap.add_argument("--out", default=str(OUTPUTS), help="output folder for logs/results")
args = ap.parse_args()

out = Path(args.out)
out.mkdir(parents=True, exist_ok=True)
log_lines = []


def log(*parts):
    """print() that also keeps a copy for outputs/02_train.log"""
    line = " ".join(str(p) for p in parts)
    print(line)
    log_lines.append(line)


def tree():
    """The shallow decision tree used for EARLY, EARLY_NO_PORT and COUNTER."""
    return DecisionTreeClassifier(max_depth=args.depth, random_state=args.seed)


# ---------------------------------------------------------------- features
EARLY_NO_PORT = [f for f in EARLY if f != "Destination Port"]
COUNTER = ["Total Fwd Packets", "Total Backward Packets",
           "Total Length of Fwd Packets", "Fwd Packet Length Max", "Flow Duration"]

log(f"seed = {args.seed}   tree depth = {args.depth}   RF trees = {args.trees}")

# ---------------------------------------------------------------- load + clean
fri = clean(load_csv(FRIDAY), "Friday", log)
wed = clean(load_csv(WEDNESDAY), "Wednesday", log)
ALL = [c for c in fri.columns if c != "Label"]
log(f"ALL feature count: {len(ALL)}")

y_fri, y_wed = is_attack(fri), is_attack(wed)
log("Friday labels after cleaning:", fri["Label"].value_counts().to_dict())
log("Wednesday labels after cleaning:", wed["Label"].value_counts().to_dict())

# stratified 70/30 split on Friday (indices, so every model sees the same rows)
idx_tr, idx_te = train_test_split(np.arange(len(fri)), test_size=0.30,
                                  stratify=y_fri, random_state=args.seed)
log(f"Friday split: train {len(idx_tr)}  test {len(idx_te)}")

# ---------------------------------------------------------------- models
MODELS = {
    "EARLY": (EARLY, tree),
    "EARLY_NO_PORT": (EARLY_NO_PORT, tree),
    "COUNTER": (COUNTER, tree),
    "ALL": (ALL, lambda: RandomForestClassifier(n_estimators=args.trees,
                                                random_state=args.seed, n_jobs=-1)),
}

results = {"seed": args.seed, "depth": args.depth, "rf_trees": args.trees,
           "features": {"EARLY": EARLY, "EARLY_NO_PORT": EARLY_NO_PORT, "COUNTER": COUNTER,
                        "ALL": f"{len(ALL)} features"},
           "rows": {"friday_clean": len(fri), "wednesday_clean": len(wed),
                    "friday_train": len(idx_tr), "friday_test": len(idx_te)},
           "friday_test": {}, "wednesday": {}}
fitted = {}

log("\n=== Friday held-out test (30%), attack class ===")
for name, (feats, make) in MODELS.items():
    model = make().fit(fri.loc[idx_tr, feats], y_fri[idx_tr])
    fitted[name] = model
    r = scores(y_fri[idx_te], model.predict(fri.loc[idx_te, feats]))
    if isinstance(model, DecisionTreeClassifier):
        r["leaves"] = int(model.get_n_leaves())
    results["friday_test"][name] = r
    log(f"{name:14s} " + "  ".join(f"{k}={v}" for k, v in r.items()))

# feature importances for every model (top 10)
log("\n=== feature importances ===")
results["importances"] = {}
for name, (feats, _) in MODELS.items():
    imp = pd.Series(fitted[name].feature_importances_, index=feats)
    imp = imp.sort_values(ascending=False).head(10)
    results["importances"][name] = {k: round(float(v), 4) for k, v in imp.items()}
    log(f"[{name}] " + ", ".join(f"{k}={v:.4f}" for k, v in imp.items()))

# 5-fold stratified CV on the EARLY tree (whole cleaned Friday)
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
cvr = cross_validate(tree(), fri[EARLY], y_fri, cv=cv, scoring=["precision", "recall"])
cv_p, cv_r = cvr["test_precision"], cvr["test_recall"]
results["cv_early"] = {
    "precision_mean": round(float(cv_p.mean()), 4), "precision_std": round(float(cv_p.std()), 4),
    "recall_mean": round(float(cv_r.mean()), 4), "recall_std": round(float(cv_r.std()), 4),
    "precision_folds": [round(float(v), 4) for v in cv_p],
    "recall_folds": [round(float(v), 4) for v in cv_r],
}
log("\n=== 5-fold stratified CV, EARLY tree, Friday ===")
log(json.dumps(results["cv_early"]))

# EARLY tree rules (this is what would become switch match-action entries)
early = fitted["EARLY"]
(out / "tree_early_rules.txt").write_text(
    f"# EARLY DecisionTree, max_depth={args.depth}, seed={args.seed}, "
    f"leaves={early.get_n_leaves()}\n# class 1 = attack, class 0 = benign\n"
    + export_text(early, feature_names=EARLY, max_depth=args.depth))

# false positives of the EARLY tree on the Friday test set: which ports?
te = fri.loc[idx_te]
fp_mask = (early.predict(te[EARLY]) == 1) & (y_fri[idx_te] == 0)
fp_ports = te.loc[fp_mask, "Destination Port"].value_counts().head(15)
results["early_false_positive_ports"] = {str(k): int(v) for k, v in fp_ports.items()}
log(f"\n=== EARLY false positives on Friday test: {int(fp_mask.sum())} flows, top destination ports ===")
log(fp_ports.to_string())

# ---------------------------------------------------------------- failure case
# Apply the Friday-trained models unchanged to Wednesday (different DoS tools).
log("\n=== Cross-day: Friday-trained models on Wednesday (all rows) ===")
for name, (feats, _) in MODELS.items():
    pred = fitted[name].predict(wed[feats])
    r = scores(y_wed, pred)
    flagged = pd.Series(pred).groupby(wed["Label"].values).mean()
    r["fraction_flagged_per_label"] = {k: round(float(v), 4) for k, v in flagged.items()}
    results["wednesday"][name] = r
    log(f"{name:14s} precision={r['precision']} recall={r['recall']} "
        f"TP={r['TP']} FP={r['FP']} FN={r['FN']} TN={r['TN']}")
    log("    fraction flagged as attack per label: " +
        ", ".join(f"{k}={v:.4f}" for k, v in r["fraction_flagged_per_label"].items()))

# median EARLY feature values per (day, label): why does it fail?
groups = pd.concat([fri.assign(Day="Friday"), wed.assign(Day="Wednesday")]).groupby(["Day", "Label"])
med = groups[EARLY].median()
med["n_flows"] = groups.size()
results["median_early_features"] = {f"{d}|{l}": {k: float(v) for k, v in row.items()}
                                    for (d, l), row in med.iterrows()}
log("\n=== median EARLY feature values per (day, label) ===")
log(med.to_string())

# ---------------------------------------------------------------- save
(out / "results.json").write_text(json.dumps(results, indent=2))
(out / "02_train.log").write_text("\n".join(log_lines) + "\n")
log(f"\nwrote {out/'results.json'}, {out/'02_train.log'}, {out/'tree_early_rules.txt'}")
