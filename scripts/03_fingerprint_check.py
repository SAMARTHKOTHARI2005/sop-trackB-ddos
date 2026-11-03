"""Step 4: is the Friday detector just fingerprinting the attack tool's TCP stack?

If one hand-written rule on the initial TCP window + port does about as well
as the trained tree, the tree has learned "what LOIC's SYN looks like",
not "what an attack looks like".

No randomness here (no training, no sampling); rules are evaluated on all
cleaned rows.

Usage:  python scripts/03_fingerprint_check.py | tee outputs/03_fingerprint.log
"""
import pandas as pd
from sklearn.metrics import precision_score, recall_score

from common import FRIDAY, WEDNESDAY, clean, load_csv

TOP = 10
fri = clean(load_csv(FRIDAY), "Friday")
wed = clean(load_csv(WEDNESDAY), "Wednesday")


def top_values(df, col, label):
    """top-N values of `col` for one label, with counts and share of that label"""
    s = df.loc[df["Label"] == label, col]
    vc = s.value_counts().head(TOP)
    return pd.DataFrame({"count": vc, "share": (vc / len(s)).round(4)})


print("\n=== Friday: Init_Win_bytes_forward, top values per label ===")
for label in ["DDoS", "BENIGN"]:
    print(f"\n-- {label} (n={int((fri['Label'] == label).sum())}) --")
    print(top_values(fri, "Init_Win_bytes_forward", label).to_string())

# the other early fields, for context
for col in ["Destination Port", "Init_Win_bytes_backward", "min_seg_size_forward"]:
    print(f"\n=== Friday: {col}, top values per label ===")
    for label in ["DDoS", "BENIGN"]:
        print(f"-- {label} --")
        print(top_values(fri, col, label).head(5).to_string())

print("\n=== Wednesday: Init_Win_bytes_forward, top values per attack label ===")
for label in ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]:
    print(f"\n-- {label} (n={int((wed['Label'] == label).sum())}) --")
    print(top_values(wed, "Init_Win_bytes_forward", label).head(5).to_string())

# ------------------------------------------------ single hand-written rules
RULES = {
    "Init_Win_fwd == 256 AND port == 80":
        lambda d: (d["Init_Win_bytes_forward"] == 256) & (d["Destination Port"] == 80),
    # DDoS flows use two initial windows (see the top-values table above)
    "Init_Win_fwd in {256, 8192} AND port == 80":
        lambda d: d["Init_Win_bytes_forward"].isin([256, 8192]) & (d["Destination Port"] == 80),
    "Init_Win_fwd == 256":
        lambda d: d["Init_Win_bytes_forward"] == 256,
    "port == 80":
        lambda d: d["Destination Port"] == 80,
}

print("\n=== single-rule detectors (attack = positive class) ===")
for day, df in [("Friday", fri), ("Wednesday", wed)]:
    y = (df["Label"] != "BENIGN").astype(int)
    for name, rule in RULES.items():
        pred = rule(df).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        print(f"{day:9s} | {name:44s} | precision={precision_score(y, pred, zero_division=0):.4f} "
              f"recall={recall_score(y, pred, zero_division=0):.4f}  TP={tp} FP={fp} FN={fn}")
