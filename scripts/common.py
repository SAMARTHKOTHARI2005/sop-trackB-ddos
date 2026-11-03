"""Things every script needs: file paths, the seed, the EARLY feature list,
and small helpers to load, clean and score the data."""
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


def clean(df, name="", log=print):
    """Turn inf into NaN, drop rows with NaN, then drop exact duplicate rows.
    Prints how many rows each step removed."""
    rows_before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    rows_after_nan = len(df)
    df = df.drop_duplicates()
    rows_after = len(df)
    log(f"[clean {name}] rows in: {rows_before}  dropped NaN/inf: {rows_before - rows_after_nan}  "
        f"dropped duplicates: {rows_after_nan - rows_after}  rows out: {rows_after}")
    return df.reset_index(drop=True)


def is_attack(df):
    """1 if the flow is any kind of attack, 0 if it's BENIGN."""
    return (df["Label"] != "BENIGN").astype(int).values


def scores(y_true, y_pred):
    """Precision and recall for the attack class, plus the confusion-matrix counts."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "TP": int(tp), "FP": int(fp), "FN": int(fn), "TN": int(tn)}
