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

- Wrote the task brief that the code follows (planned with claude.ai as above). It fixed the
  dataset mirror and the two days, the four feature sets, the depth-5 decision tree, the
  metrics, the order of the steps, seed 46 and the list of deliverables.
- Made the decisions along the way, e.g. that seed 46 is the only seed for every reported result
  and that other seeds are used only as a robustness check.
- Asked for a walkthrough of every step and went through it so that I understand each choice
  and can explain it, and re-ran the pipeline myself (`bash run_all.sh`, or `02_train.py` with a
  different `--depth` or `--seed`).

## Seed

Everything random (train/test split, CV folds, decision trees, random forest) uses seed 46, the
last two digits of my ID 2023A7PS0646P. Every number in the report comes from the logs in
`outputs/`, which the scripts regenerate exactly.
