"""Step 2: look at the raw data before training anything.

Prints, for both CSVs: shape, label counts, the (stripped) column list,
and how many rows contain NaN or +/-inf values.

Usage:  python scripts/01_inspect.py | tee outputs/01_inspect.log
"""
import numpy as np

from common import FRIDAY, WEDNESDAY, load_csv

for path in [FRIDAY, WEDNESDAY]:
    print("=" * 70)
    print(path.name)
    print("=" * 70)
    df = load_csv(path)
    print(f"shape: {df.shape}")

    print("\nlabel counts:")
    print(df["Label"].value_counts().to_string())

    print(f"\ncolumns ({len(df.columns)}):")
    for i, c in enumerate(df.columns):
        print(f"  {i:2d}  {c}")

    num = df.select_dtypes(include=[np.number])
    nan_rows = df.isna().any(axis=1)
    inf_rows = np.isinf(num).any(axis=1)
    print(f"\nrows with any NaN:  {int(nan_rows.sum())}")
    print(f"rows with any inf:  {int(inf_rows.sum())}")
    print(f"rows with NaN or inf: {int((nan_rows | inf_rows).sum())}")
    print("columns containing NaN:", list(df.columns[df.isna().any()]))
    print("columns containing inf:", list(num.columns[np.isinf(num).any()]))
    print(f"exact duplicate rows: {int(df.duplicated().sum())}")
    print()
