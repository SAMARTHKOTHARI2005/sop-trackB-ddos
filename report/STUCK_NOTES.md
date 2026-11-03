# Where I got stuck, and how I fixed it

1. **The official CIC download server was unreachable.** The CIC-IDS2017 page on unb.ca did
   not load, so I could not get the CSVs from the source. *Fix:* I used a public GitHub mirror
   (`2000pawan/Cyber-Attack-Threat-Classification`) that stores the `MachineLearningCVE`
   CSVs. To make sure the files were not tampered with or truncated, I checked their SHA-256
   (`data/SHA256SUMS`). The Friday hash `6ff1580f5f81c0ae…` matches the Git LFS object id
   in the mirror.

2. **I got Git LFS pointer files instead of CSVs.** The `raw.githubusercontent.com` URL
   returns a ~130-byte text file (`version https://git-lfs.github.com/spec/v1`, `oid sha256:…`,
   `size …`), not the data. *Fix:* use `media.githubusercontent.com/media/<user>/<repo>/<branch>/<path>`,
   which serves the actual LFS content. `00_download.sh` also checks for the LFS header and
   stops if it gets a pointer.

3. **Column names have leading spaces.** The CSV header is
   `" Destination Port, Flow Duration, Total Fwd Packets, …"`, so `df["Label"]` fails with a
   KeyError (the column is really `" Label"`). *Fix:* `df.columns = df.columns.str.strip()` in
   `scripts/common.py:load_csv`, used by every script.

4. **NaN and inf rows.** `Flow Bytes/s` has NaN, and both `Flow Bytes/s` and `Flow Packets/s`
   have inf. These are rate features, which CICFlowMeter divides by a zero flow duration.
   scikit-learn refuses inf/NaN input. Counts from `outputs/01_inspect.log`: Friday 34 rows,
   Wednesday 1,297 rows. *Fix:* replace ±inf with NaN, then drop rows with any NaN. This
   removes a negligible share of the data, so I did not try to impute.

5. **Duplicate rows.** Friday has 2,633 exact duplicate rows and Wednesday 81,909 (2,629 and
   80,914 after the NaN/inf rows are removed). If duplicates stay in, the same row can land in
   both train and test and inflate the score. *Fix:* `drop_duplicates()` on the full row
   **before** the train/test split. The counts are logged in `outputs/02_train.log`.

6. **Smaller issues on the way.**
   - My first download script used `declare -A` (an associative array), which macOS's
     bash 3.2 does not support. *Fix:* replaced it with a `case` statement.
   - The system Python 3.9 had no scikit-learn. *Fix:* a local `.venv` (gitignored)
     with the packages from `requirements.txt`.
   - `Fwd Header Length` appears twice in the CSV. pandas renames the second copy
     `Fwd Header Length.1`, and I left it in the ALL set (78 features).

7. **Was the seed-46 cross-day result stable?** With seed 46 the EARLY tree caught only
   0.35% of Wednesday attacks while scoring 0.99 on Friday, and I wasn't sure whether that
   was a property of the method or of this one tree. *Fix / finding:* I wrote
   `04_seed_sensitivity.py`, which retrains the EARLY tree with seed 46 and seeds 0-9. The
   Friday scores stay almost identical, but the Wednesday recall only takes the values
   0.0035, 0.3075 and 0.5724. The difference comes from two tiny leaves (Init_Win_fwd = 251
   and = 0) that only some seeds label "attack". They are built from 17 and 27 Friday DDoS
   flows and happen to match Hulk's windows. I kept seed 46 as the main result, as required,
   and report this as a limitation instead of picking the seed that looks best.
