# Labelled benchmark

`cases.json` is the ground truth, written before the baseline scan. Never execute its code. Inputs are snippets for static review, not runnable applications. Credential placeholders are materialized into synthetic, unusable values only in temporary directories. No API calls are made.

Labels describe detectable review patterns, not proven exploitable vulnerabilities. Each positive has one expected rule and starting line. There are 40 ordinary positives, 40 ordinary negatives and 10 tricky cases. Tricky cases have their own positive/negative label. Informational findings are not scored.

Run `python benchmark/run.py --output benchmark/results/baseline.json` before rule changes. The runner refuses to overwrite result files. Run again to a different filename after changes. Results include a SHA-256 of the exact case file and the scanner files, plus the Git revision.

TP = expected rule/line found, FN = expected rule/line missing, FP = additional actionable rule/line findings, TN = negative cases with no actionable findings. Precision = TP/(TP+FP); recall = TP/(TP+FN). Exact rule/line matching means a wrong rule or location can produce both an FP and an FN. Per-rule TN counts negative cases explicitly targeted at that rule. These are synthetic-set results, not estimates of general accuracy.
