"""Step 4: is the Friday detector just fingerprinting the attack tool's TCP stack?

If one hand-written rule on the initial TCP window + port does about as well
as the trained tree, the tree has learned "what LOIC's SYN looks like",
not "what an attack looks like".

No randomness here (no training, no sampling); rules are evaluated on all
cleaned rows.

Usage:  python scripts/03_fingerprint_check.py | tee outputs/03_fingerprint.log
"""
import pandas as pd

from common import FRIDAY, WEDNESDAY, clean, is_attack, load_csv, scores

fri = clean(load_csv(FRIDAY), "Friday")
wed = clean(load_csv(WEDNESDAY), "Wednesday")


def top_values(df, col, label, n=10):
    """Top-n values of `col` for one label, with counts and share of that label."""
    s = df.loc[df["Label"] == label, col]
    vc = s.value_counts().head(n)
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
        print(top_values(fri, col, label, n=5).to_string())

print("\n=== Wednesday: Init_Win_bytes_forward, top values per attack label ===")
for label in ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]:
    print(f"\n-- {label} (n={int((wed['Label'] == label).sum())}) --")
    print(top_values(wed, "Init_Win_bytes_forward", label, n=5).to_string())

# ------------------------------------------------ single hand-written rules
RULES = {
    "Init_Win_fwd == 256 AND port == 80":
        lambda d: (d["Init_Win_bytes_forward"] == 256) & (d["Destination Port"] == 80),
    # DDoS flows use two initial windows (see the top-values table above)
    "Init_Win_fwd in {256, 8192} AND port == 80":
        lambda d: d["Init_Win_bytes_forward"].isin([256, 8192]) & (d["Destination Port"] == 80),
    "port == 80":
        lambda d: d["Destination Port"] == 80,
}

print("\n=== single-rule detectors (attack = positive class) ===")
for day, df in [("Friday", fri), ("Wednesday", wed)]:
    y = is_attack(df)
    for name, rule in RULES.items():
        r = scores(y, rule(df).astype(int).values)
        print(f"{day:9s} | {name:44s} | precision={r['precision']:.4f} recall={r['recall']:.4f}  "
              f"TP={r['TP']} FP={r['FP']} FN={r['FN']}")
