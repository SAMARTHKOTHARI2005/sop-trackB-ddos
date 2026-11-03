"""Step 4: is the Friday detector just recognising the attack tool's TCP stack?

If a single hand-written rule on the initial TCP window and the port does
about as well as the trained tree, then the tree has learned "what LOIC's
SYN packets look like", not "what an attack looks like".

There's nothing random here (no training, no sampling); the rules are just
checked against every cleaned row.

Usage:  python scripts/03_fingerprint_check.py | tee outputs/03_fingerprint.log
"""
import pandas as pd

from common import FRIDAY, WEDNESDAY, clean, is_attack, load_csv, scores

friday = clean(load_csv(FRIDAY), "Friday")
wednesday = clean(load_csv(WEDNESDAY), "Wednesday")


def top_values(df, column, label, n=10):
    """The n most common values of `column` for one label, with counts and share."""
    values = df.loc[df["Label"] == label, column]
    counts = values.value_counts().head(n)
    return pd.DataFrame({"count": counts, "share": (counts / len(values)).round(4)})


print("\n=== Friday: Init_Win_bytes_forward, top values per label ===")
for label in ["DDoS", "BENIGN"]:
    print(f"\n-- {label} (n={int((friday['Label'] == label).sum())}) --")
    print(top_values(friday, "Init_Win_bytes_forward", label).to_string())

# The other early fields, for context
for column in ["Destination Port", "Init_Win_bytes_backward", "min_seg_size_forward"]:
    print(f"\n=== Friday: {column}, top values per label ===")
    for label in ["DDoS", "BENIGN"]:
        print(f"-- {label} --")
        print(top_values(friday, column, label, n=5).to_string())

print("\n=== Wednesday: Init_Win_bytes_forward, top values per attack label ===")
for label in ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]:
    print(f"\n-- {label} (n={int((wednesday['Label'] == label).sum())}) --")
    print(top_values(wednesday, "Init_Win_bytes_forward", label, n=5).to_string())

# Simple hand-written rules, no machine learning
rules = {
    "Init_Win_fwd == 256 AND port == 80":
        lambda df: (df["Init_Win_bytes_forward"] == 256) & (df["Destination Port"] == 80),
    # the DDoS flows use two initial windows (see the table above)
    "Init_Win_fwd in {256, 8192} AND port == 80":
        lambda df: df["Init_Win_bytes_forward"].isin([256, 8192]) & (df["Destination Port"] == 80),
    "port == 80":
        lambda df: df["Destination Port"] == 80,
}

print("\n=== single-rule detectors (attack = positive class) ===")
for day, df in [("Friday", friday), ("Wednesday", wednesday)]:
    y_true = is_attack(df)
    for rule_name, rule in rules.items():
        result = scores(y_true, rule(df).astype(int).values)
        print(f"{day:9s} | {rule_name:44s} | precision={result['precision']:.4f} recall={result['recall']:.4f}  "
              f"TP={result['TP']} FP={result['FP']} FN={result['FN']}")
