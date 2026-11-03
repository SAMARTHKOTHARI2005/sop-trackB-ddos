"""Shared helpers used by every script: file paths, CSV loading and cleaning."""
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUTPUTS = ROOT / "outputs"

FRIDAY = DATA / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
WEDNESDAY = DATA / "Wednesday-workingHours.pcap_ISCX.csv"

DEFAULT_SEED = 46  # last two digits of student ID 2023A7PS0646P


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
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    n1 = len(df)
    df = df.drop_duplicates()
    n2 = len(df)
    log(f"[clean {name}] rows in: {n0}  dropped NaN/inf: {n0 - n1}  "
        f"dropped duplicates: {n1 - n2}  rows out: {n2}")
    return df.reset_index(drop=True)
