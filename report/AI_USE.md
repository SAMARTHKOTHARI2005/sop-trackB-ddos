# Use of AI tools

I used Anthropic's Claude for this task, as allowed. This is what it was used for and what I did
myself.

## What Claude did

**Claude (claude.ai chat), for planning.** It helped me compare the tracks and pick Track B, and
helped me plan the approach: which two CIC-IDS2017 days to use, which fields count as
"first few packets", and using a cross-day test to find a failure case.

**Claude Code (AI coding agent in VS Code), for the coding and most of the analysis.**

- Wrote all the code: the download and SHA-256 check (`00_download.sh`), the shared loading and
  cleaning code (`common.py`), the inspection script, the training and evaluation script
  (`02_train.py`), the fingerprint check, the seed robustness check and `run_all.sh`.
- Ran the scripts, fixed the problems that came up (bash 3.2 on macOS, scikit-learn missing,
  LFS pointer files) and made the git commits.
- Did the analysis beyond my brief. It found that the DDoS flows use two window values (256
  and 8192) and tested the two-value rule, and it suggested and wrote the seed robustness check
  (seed 46 against seeds 0-9) along with the explanation of the two small leaves.
- Drafted the README and all the files in `report/` (including the PDF) from the logs in
  `outputs/`, and later reworded them in plainer language at my request.

## What I did

**Planning and design**

- Chose Track B and wrote the task brief that the code follows (planned with claude.ai, as above).
  It fixed the dataset mirror (including that the `media.githubusercontent.com` link has to be
  used instead of `raw.githubusercontent.com`), the two days, the four feature sets and what each
  one is for, the depth-5 decision tree (because a shallow tree maps onto switch match-action
  tables), precision/recall as the metrics, the Friday-to-Wednesday test for the failure case,
  seed 46, and the list of deliverables.
- Listed the data problems the notes had to cover (CIC server unreachable, LFS pointer files,
  spaces in column names, NaN/inf rows, duplicate rows).
- Chose the week-2 direction, including the link to my earlier ResilientDAG work on slow,
  low-rate attacks that look valid locally but break liveness globally.

**Running the project**

- Set up the GitHub repository and asked for a commit after every step so the history shows
  how the work progressed.
- Checked the work against the professor's requirements one at a time (commit history, raw
  logs, exact commands, the stuck notes, the week-2 paragraph, AI disclosure, the seed) and asked
  for whatever was missing to be added.
- Made the decisions along the way: seed 46 is the only seed for every reported result, other
  seeds are only a robustness check, and the report must be exactly two pages.
- Asked for the clean-up passes: removing unneeded code, clearer variable names, a single
  `run_all.sh` to run everything, and printing every result as a table so the logs are easier
  to read and check.
- Made some small formatting edits to `02_train.py` myself.

**Understanding and checking it**

- Asked for a walkthrough of every step and went through it so that I understand each choice
  and can explain it.
- Read the README and report drafts and asked for them to be rewritten in my own style.
- Re-ran the pipeline myself (`bash run_all.sh`) and tried a live change (`02_train.py --depth 3`).

## Seed

Everything random (train/test split, CV folds, decision trees, random forest) uses seed 46, the
last two digits of my ID 2023A7PS0646P. Every number in the report comes from the logs in
`outputs/`, which the scripts regenerate exactly.
