"""Things every script needs: file paths, the seed, the EARLY feature list,
and small helpers to load, clean and score the data and print tables."""
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUTPUTS = ROOT / "outputs"

FRIDAY = DATA / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
WEDNESDAY = DATA / "Wednesday-workingHours.pcap_ISCX.csv"

DEFAULT_SEED = 46  # last two digits of my ID, 2023A7PS0646P

# Header fields a switch already has after the first 1-3 packets (SYN / SYN-ACK / ACK).
# min_seg_size_forward is technically a minimum over the whole flow, but TCP header
# options don't change after the handshake, so in practice it's fixed by packet 3.
EARLY = ["Destination Port", "Init_Win_bytes_forward",
         "Init_Win_bytes_backward", "min_seg_size_forward"]


def load_csv(path):
    """Read one CIC-IDS2017 CSV. CICFlowMeter puts a space in front of most
    column names (e.g. ' Label'), so strip those."""
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    return df


def clean(df):
    """Turn inf into NaN, drop rows with NaN, then drop exact duplicate rows.
    Returns the cleaned data and [rows in, dropped NaN/inf, dropped duplicates, rows out]."""
    rows_before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    rows_after_nan = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    return df, [rows_before, rows_before - rows_after_nan, rows_after_nan - len(df), len(df)]


def load_both_days():
    """Load and clean Friday and Wednesday. Also returns a table of what cleaning removed."""
    friday, friday_stats = clean(load_csv(FRIDAY))
    wednesday, wednesday_stats = clean(load_csv(WEDNESDAY))
    summary = table(["day", "rows in", "dropped NaN/inf", "dropped duplicates", "rows out"],
                    [["Friday"] + friday_stats, ["Wednesday"] + wednesday_stats])
    return friday, wednesday, summary


def is_attack(df):
    """1 if the flow is any kind of attack, 0 if it's BENIGN."""
    return (df["Label"] != "BENIGN").astype(int).values


def scores(y_true, y_pred):
    """Precision and recall for the attack class, plus the confusion-matrix counts."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "TP": int(tp), "FP": int(fp), "FN": int(fn), "TN": int(tn)}


def looks_like_number(text):
    try:
        float(text.rstrip("%"))
        return True
    except ValueError:
        return False


def table(headers, rows):
    """Format rows as a text table with borders. Floats get 4 decimals, and
    columns that only hold numbers are right-aligned."""
    cells = [[f"{v:.4f}" if isinstance(v, float) else str(v) for v in row] for row in rows]
    widths = [max([len(h)] + [len(row[i]) for row in cells]) for i, h in enumerate(headers)]
    numeric = [all(looks_like_number(row[i]) or row[i] in ("", "-") for row in cells)
               for i in range(len(headers))]

    def line(values):
        padded = [v.rjust(w) if num else v.ljust(w) for v, w, num in zip(values, widths, numeric)]
        return "| " + " | ".join(padded) + " |"

    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    return "\n".join([border, line(headers), border] + [line(row) for row in cells] + [border])


def tree_rules_table(model, features):
    """One row per leaf of a fitted decision tree: the range each feature has to
    fall in, the predicted class and how many training flows ended up there.
    This is basically what the switch's match-action table would hold."""
    tree = model.tree_
    rows = []

    def describe(low, high):
        if low == -np.inf and high == np.inf:
            return "any"
        if low == -np.inf:
            return f"<= {high:.10g}"
        if high == np.inf:
            return f"> {low:.10g}"
        return f"> {low:.10g} and <= {high:.10g}"

    def walk(node, bounds):
        if tree.children_left[node] == -1:  # leaf
            predicted = model.classes_[tree.value[node][0].argmax()]
            rows.append([len(rows) + 1] + [describe(*bounds[f]) for f in features]
                        + ["attack" if predicted == 1 else "benign", int(tree.n_node_samples[node])])
            return
        feature, threshold = features[tree.feature[node]], tree.threshold[node]
        low, high = bounds[feature]
        walk(tree.children_left[node], {**bounds, feature: (low, min(high, threshold))})
        walk(tree.children_right[node], {**bounds, feature: (max(low, threshold), high)})

    walk(0, {f: (-np.inf, np.inf) for f in features})
    return table(["rule"] + features + ["class", "training flows"], rows)
