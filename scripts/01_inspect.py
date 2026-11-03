"""Step 2: have a look at the raw data before training anything.

For both CSVs this prints the shape, label counts, the column names (with the
spaces stripped), how many rows have NaN or inf values, and how many rows
are exact duplicates.

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
    for i, col in enumerate(df.columns):
        print(f"  {i:2d}  {col}")

    numeric = df.select_dtypes(include=[np.number])
    has_nan = df.isna().any(axis=1)
    has_inf = np.isinf(numeric).any(axis=1)
    print(f"\nrows with any NaN:  {int(has_nan.sum())}")
    print(f"rows with any inf:  {int(has_inf.sum())}")
    print(f"rows with NaN or inf: {int((has_nan | has_inf).sum())}")
    print("columns containing NaN:", list(df.columns[df.isna().any()]))
    print("columns containing inf:", list(numeric.columns[np.isinf(numeric).any()]))
    print(f"exact duplicate rows: {int(df.duplicated().sum())}")
    print()
