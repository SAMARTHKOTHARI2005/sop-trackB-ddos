"""Step 2: have a look at the raw data before training anything.

For both CSVs this prints the shape, label counts, the column names (with the
spaces stripped), how many rows have NaN or inf values, and how many rows
are exact duplicates.

Usage:  python scripts/01_inspect.py | tee outputs/01_inspect.log
"""
import numpy as np

from common import FRIDAY, WEDNESDAY, load_csv, table

for path in [FRIDAY, WEDNESDAY]:
    print("=" * 70)
    print(path.name)
    print("=" * 70)
    df = load_csv(path)

    print("\nlabel counts:")
    print(table(["label", "flows"], df["Label"].value_counts().reset_index().values.tolist()))

    print(f"\ncolumns ({len(df.columns)}):")
    print(table(["#", "column"], list(enumerate(df.columns))))

    numeric = df.select_dtypes(include=[np.number])
    has_nan = df.isna().any(axis=1)
    has_inf = np.isinf(numeric).any(axis=1)
    print("\nsummary:")
    print(table(["check", "result"], [
        ["rows", len(df)],
        ["columns", len(df.columns)],
        ["rows with any NaN", int(has_nan.sum())],
        ["rows with any inf", int(has_inf.sum())],
        ["rows with NaN or inf", int((has_nan | has_inf).sum())],
        ["columns containing NaN", ", ".join(df.columns[df.isna().any()])],
        ["columns containing inf", ", ".join(numeric.columns[np.isinf(numeric).any()])],
        ["exact duplicate rows", int(df.duplicated().sum())],
    ]))
    print()
