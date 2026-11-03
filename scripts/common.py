"""Shared helpers used by every script: paths, the seed, the EARLY feature set,
CSV loading, cleaning and scoring."""
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUTPUTS = ROOT / "outputs"

FRIDAY = DATA / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
WEDNESDAY = DATA / "Wednesday-workingHours.pcap_ISCX.csv"

DEFAULT_SEED = 46  # last two digits of student ID 2023A7PS0646P

# Header fields a switch has within the first 1-3 packets (SYN / SYN-ACK / ACK).
# min_seg_size_forward is a minimum over the flow, but TCP header options do not
# change after the handshake, so in practice it is fixed by the 3rd packet.
EARLY = ["Destination Port", "Init_Win_bytes_forward",
         "Init_Win_bytes_backward", "min_seg_size_forward"]


def load_csv(path):
    """Read a CIC-IDS2017 CSV and strip the leading/trailing spaces that the
    original CICFlowMeter export puts in most column names (e.g. ' Label')."""
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    return df


def clean(df, name="", log=print):
    """Replace +/-inf with NaN, drop rows with any NaN, then drop exact
    duplicate rows. Logs how many rows each step removed."""
    n0 = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    n1 = len(df)
    df = df.drop_duplicates()
    n2 = len(df)
    log(f"[clean {name}] rows in: {n0}  dropped NaN/inf: {n0 - n1}  "
        f"dropped duplicates: {n1 - n2}  rows out: {n2}")
    return df.reset_index(drop=True)


def is_attack(df):
    """Binary label: 1 for any attack, 0 for BENIGN."""
    return (df["Label"] != "BENIGN").astype(int).values


def scores(y_true, y_pred):
    """Precision / recall for the attack class (label 1) plus confusion counts."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "TP": int(tp), "FP": int(fp), "FN": int(fn), "TN": int(tn)}
