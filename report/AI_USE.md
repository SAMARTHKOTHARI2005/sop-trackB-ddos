# Disclosure of AI use

I used Anthropic's Claude for this trial task, in two ways:

- **claude.ai (chat):** to compare the available tracks and choose Track B, and to plan the
  approach: which CIC-IDS2017 files to use, which features count as "first few packets", and
  the cross-day test as the failure case.
- **Claude Code (coding agent in my editor):** wrote the scripts in `scripts/`, ran them,
  made the step-by-step git commits, and drafted `README.md` and the files in `report/` from
  the logs in `outputs/`. While running the pipeline, it noticed that my seed-46 cross-day
  result was very different from an earlier seed-74 run and added
  `04_seed_sensitivity.py` to explain why.

I specified the task, the feature sets, the seed and the structure of the deliverables. I
read and checked the code and logs, checked that the numbers in the report match `outputs/`,
and reviewed and rewrote the report in my own words. I can explain every choice and re-run
any step, e.g. with a different `--depth` or `--seed`. Any remaining mistakes are mine.
