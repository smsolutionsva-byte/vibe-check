# Benchmark — 2 November 2026

The first sections preserve the original 90-case development benchmark at commit 81eee8b. The later Final precision pass section reports a separate 20-case held-out evaluation. Results describe these labelled synthetic sets only, not security or general accuracy.

## Dataset frozen before scanning

- Ground truth: `benchmark/cases.json`, frozen in commit `d9d4f8b` before the first scanner run.
- 40 ordinary positive cases, 40 ordinary negative cases and 10 tricky cases (7 positive, 3 negative): 47 expected findings and 43 negatives overall.
- Languages: Python, JS/TS, Go, PHP, Ruby, Rust and .env. Generic secret assignments cover all these languages; execution rules apply only to Python and JS/TS.
- All credential-shaped values are synthetic and materialized only in temporary directories. Snippets are never executed. No AI/API is used by the benchmark.
- Dataset SHA-256 (identical before/after): `20e703a46b6da606a5798d2b785feabf922b1d4dd111f5be7e4a0df0db72d5f0`.
- No cases were removed, relabelled or edited after the baseline. `make_dataset.py` records the pre-run construction; the runner reads the frozen JSON, not this generator.

## Scoring

TP is an expected rule/starting-line pair matched by an actionable finding. FN is an unmatched expected pair. FP is an unexpected actionable pair. TN is a negative case with no actionable findings. Information findings are excluded. A wrong rule or line can create both an FP and an FN. Duplicated identical rule/line pairs are collapsed. This set has one expected finding per positive.

Precision = TP / (TP + FP); recall = TP / (TP + FN). Per-rule TN means a negative case explicitly assigned to that rule, not every case without that rule. N20 is a negative documentation example mentioning new Function but its pre-frozen routing metadata targets js-eval; it remains untouched. This affects per-rule TN allocation, not overall TP/FP/TN/FN.

| Run | TP | FP | TN | FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Before fixes | 38 | 9 | 34 | 9 | 80.85% | 80.85% |
| After fixes | 45 | 0 | 43 | 2 | 100.00% | 95.74% |

## Per-rule results

| Rule | Before TP/FP/TN/FN | After TP/FP/TN/FN | Before precision/recall | After precision/recall |
| --- | --- | --- | --- | --- |
| aws-access-key | 3/0/0/0 | 3/0/0/0 | 100.00%/100.00% | 100.00%/100.00% |
| dynamic-code-execution | 4/0/3/0 | 4/0/3/0 | 100.00%/100.00% | 100.00%/100.00% |
| github-token | 3/0/0/0 | 3/0/0/0 | 100.00%/100.00% | 100.00%/100.00% |
| hardcoded-credential | 14/2/23/3 | 17/0/25/0 | 87.50%/82.35% | 100.00%/100.00% |
| js-child-process-concatenation | 4/1/2/2 | 6/0/3/0 | 80.00%/66.67% | 100.00%/100.00% |
| js-eval | 3/4/4/1 | 4/0/8/0 | 42.86%/75.00% | 100.00%/100.00% |
| js-new-function | 3/2/1/1 | 4/0/3/0 | 60.00%/75.00% | 100.00%/100.00% |
| private-key-block | 2/0/0/0 | 2/0/0/0 | 100.00%/100.00% | 100.00%/100.00% |
| subprocess-shell-true | 2/0/1/2 | 2/0/1/2 | 100.00%/50.00% | 100.00%/50.00% |

## Three problem areas fixed

1. JS context filtering: remove quoted strings, template text and line/block comments from the risk-matching view while preserving offsets. Match eval and new Function across whitespace/newlines. This removes code-like-text false positives and recovers multiline calls.
2. Literal credentials: Python AST handling distinguishes real literal assignments/keyword arguments from comments and env reads and supports bytes, multiline literals, attributes and subscript settings. Generic patterns now accept Rust &str annotations; JS/Go/Rust/PHP comment filtering reduces assignment-in-comment false positives. A public-repo regression check preserves Python attribute/subscript settings.
3. Child-process attribution: recognize basic CommonJS/ES module bindings and aliases, constrain exec calls to those bindings, and inspect the first argument across line breaks. An unrelated regex.exec is no longer attributed to an imported child_process module.

## Remaining misses at the original snapshot

- T01: `import subprocess as sp` followed by `sp.run(..., shell=True)`.
- T02: `from subprocess import run as launch` followed by `launch(..., shell=True)`.
These stayed labelled positive and counted as two false negatives at the original snapshot. The later precision pass below resolves these import aliases without relabelling them.

## Reproduce

```powershell
python benchmark/run.py --output benchmark/results/my-run.json
python -m unittest discover -s tests -v
```

The runner prints overall and per-rule measurements and refuses to overwrite results. Original baseline: `benchmark/results/baseline.json`. Final result: `benchmark/results/final.json`. `after.json` and `after-final.json` preserve intermediate runs; final.json includes the attribute/subscript regression fix. Source hashes identify the scanner state; the recorded Git revision is the checked-out parent while rule edits were uncommitted. Do not use revision alone to identify those scanner versions. Raw dataset hashes can vary with checkout newline conversion; parsed labels and source text must also be compared when reproducing on other platforms.

## Read-only vulnerable-repo comparison

Both clones were scanned without executing their code, installing their dependencies or changing their worktrees. `git status --porcelain` was empty for both afterward. Reports are masked and stored here, not in the clones. No exploit attempts, dependency audits or complete ground-truth vulnerability counts were performed. Public repo findings are not included in the 90-case metrics.

### OWASP NodeGoat

- Repository revision: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`.
- Command: `python -m vibe_check.cli ..\eval-nodegoat --report benchmark/results/nodegoat.md`.
- Observed at original snapshot: 7 findings (4 high, 3 medium), FIX FIRST, exit 1.
- Confirmed documented overlap: the [server-side JS injection lesson](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a1.html#L149) describes untrusted contribution inputs passed to eval. The scanner flags [contributions.js lines 32–34](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/contributions.js#L32).
- Confirmed false positives: `app/routes/session.js:61` and `:172` are password error-message strings, not passwords. Broad name matching still causes these.
- Context-only findings: `test/security/profile-test.js:37` is a test credential; `artifacts/cert/server.key:1` is a bundled private-key block. They are real literals/artifacts, but neither is evidence of a live production secret. Values were not reproduced.
- Missed/out of scope: the [stored XSS lesson](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a3.html#L153) is not detected. `config/env/all.js:8` contains a cookieSecret setting which the credential-name patterns miss. No complete vulnerability recall can be calculated.

### PyGoat

- Repository revision: `2aa4cc14f251e4a780e94e200aed6b36a5b15c21`.
- Final command: `python -m vibe_check.cli ..\eval-pygoat --report benchmark/results/pygoat-final.md`.
- Observed at original snapshot: 22 findings (19 high, 2 medium, 1 info), FIX FIRST, exit 1. Earlier `pygoat.md` preserves the 16-finding scan before the Python attribute/subscript regression fix.
- Confirmed documented overlap: [command-injection lab README](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/dockerized_labs/command_injection_lab/README.md) describes both shell command execution and eval; flags occur at [app.py:29 and :49](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/dockerized_labs/command_injection_lab/app.py#L29).
- Confirmed false positives: SQL-injection tutorial query text is reported as a password in `dockerized_labs/sql_injection_lab/templates/index.html:57`, `introduction/templates/Lab/SQL/sql.html:63` and `introduction/templates/Lab_2021/A3_Injection/injection.html:72`.
- Additional findings include deliberately exposed lab settings/default credentials, an AWS-shaped lab value, and credentials mentioned in instructional HTML/README text. These were not validated as live keys; do not interpret their count as confirmed security bugs. The insufficient-logging README and HTML findings are educational credential examples, not independently established secret leaks.
- Documented misses: the [SQL-injection lab](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/dockerized_labs/sql_injection_lab/README.md) constructs an unsafe query at `app.py:50–57`; no SQL-injection rule flags it. The [SSRF lab](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/dockerized_labs/ssrf_lab/README.md) has request-derived paths at `app.py:18–22` and URL fetching at `:35–37`; neither is detected.
- The info finding points to a source file because no Python test filenames matched; it is not proof of missing tests.

## Known limits at the original snapshot

Small hand-authored set; fixes were selected using the same cases, so overfitting is possible. Some rule/language combinations have few or no negatives. Inputs are snippets, not compiler-validated applications. JS/TS filtering is not full parsing: template interpolation and regex literals, lexical scope, shadowing and reassigned imports can cause misses or false positives. The shell rule lacks Python alias resolution. Generic credential names, lengths and explicit placeholder suppression can still miss real secrets or flag harmless text. Python syntax errors are skipped for AST checks. No SQL/XSS/SSRF/dataflow, dependency, runtime or test-quality analysis is performed. A SHIP verdict means only that these checks found no high/medium evidence, not that shipping is safe.

Original snapshot tests: 22 test methods passed. The later precision pass adds tests; see its separate result below. No push or submission was performed.

## Final precision pass: separate held-out evaluation

- `benchmark/heldout.json`: 20 additional cases (10 positive, 10 negative), frozen in commit `3c7157a` before scanner rules changed.
- Frozen held-out SHA-256: `4380c3dbf9ff1678e4e08e2758c86aa01c78c32e473984b3a5bd1372aa12e43f`.
- Rules/tests frozen in commit `ef298c37d1cb0548158fcbea0eab448a257367b7` before the held-out run. Scanner module hashes are saved in the result.
- Implementation used documented public-repo errors and separate development regressions. The held-out cases were not run until the rules were frozen. They were evaluated once; no scanner rules were changed after observing that result.
- This small set was authored by the same agent before implementation, not independently blinded or randomly sampled. Case-selection bias is possible. It is not used to claim general accuracy.

| Set / phase | Cases | TP | FP | TN | FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Original development set after this pass | 90 | 47 | 0 | 43 | 0 | 100.00% | 100.00% |
| New held-out set, one-time run | 20 | 10 | 0 | 10 | 0 | 100.00% | 100.00% |

Held-out per-rule results (not combined with development):

| Rule | TP | FP | TN | FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| aws-access-key | 1 | 0 | 0 | 0 | 100.00% | 100.00% |
| hardcoded-credential | 1 | 0 | 5 | 0 | 100.00% | 100.00% |
| possible-sql-string-building | 4 | 0 | 3 | 0 | 100.00% | 100.00% |
| subprocess-shell-true | 4 | 0 | 2 | 0 | 100.00% | 100.00% |

### What changed

1. Credential-name matching excludes UI suffixes such as passwordError/password_error. Generic credential checks skip documentation/HTML/plain text; provider-specific token and private-key checks still run there. This removes the documented NodeGoat messages and PyGoat tutorial SQL/example text.
2. Python subprocess module/from-import aliases are tracked with basic function-local binding, parameter shadowing and direct reassignment handling. Arbitrary alias assignment, dynamic imports and full control-flow/scope analysis remain unsupported.
3. New medium rule `possible-sql-string-building`, labelled **possible SQL string building**, flags an interpolated f-string or a string-containing addition in the first positional argument of a cursor-like execute call. It recognizes cursor/cur/db_cursor names or simple variables assigned from .cursor(). It is a review hint, not a confirmed vulnerability.

### Public-repo recheck

Same revisions and clean read-only worktrees as above:
- NodeGoat: 7 → 5 findings. The two password-error-message false positives disappeared. Three documented eval calls, a bundled private-key block and a test credential remain. Report: `benchmark/results/nodegoat-precision.md`.
- PyGoat: 22 → 15 findings. Three tutorial SQL password false positives and four generic documentation/HTML credential examples disappeared. Source/default credential patterns, the shell/eval labs and one info finding remain. Report: `benchmark/results/pygoat-precision.md`. These are not counts of confirmed exploitable vulnerabilities or live secrets.
- PyGoat builds its SQL query into a variable before calling execute, so the new same-call rule intentionally does not catch that documented lab. XSS, SSRF and **full SQL injection detection remain not covered**.

### Current limitations and precision tradeoffs

Skipping generic credentials in documentation/HTML can hide actual generic secret literals and keys in inline scripts there. UI-style names can also hide a poorly named real credential. Provider-token/private-key patterns remain active in those files. Test/default credentials are not automatically excluded. Python syntax errors, dynamic imports, complex rebindings and global/nonlocal/class/lambda binding nuances can cause misses or false positives. SQL receiver recognition is heuristic: unrelated objects named cursor can be flagged and real cursors under other names can be missed. Query variables, .format, percent formatting, SQL taint/sanitization analysis, XSS and SSRF are not covered. JS/TS remains pattern-based. SHIP is not a security guarantee.

### Repository self-scan

The final `python -m vibe_check.cli . --report "$env:TEMP\vibe-final-precision-self-scan.md"` returned exit 1: one high hardcoded-credential finding at `benchmark/heldout.json:213`, masked as `arbi****`. This is the fake tutorial text serialized in H14, not a real credential. H14 is correctly ignored when materialized as lesson.html by the benchmark; scanning the JSON container itself loses that file context. This remains a known false positive. The frozen corpus and scanner were left unchanged after held-out evaluation.

### Commands and tests

```powershell
python -m unittest discover -s tests -v
python benchmark/run.py --output benchmark/results/precision-development.json
python benchmark/run.py --cases benchmark/heldout.json --output benchmark/results/heldout-once.json
```

31 test methods passed before held-out evaluation; no failures. Captured log: `benchmark/results/precision-unit-tests.txt`. The runner refuses to overwrite the saved results. Do not rerun the held-out set to tune rules; future changes should get a new evaluation set. No push or submission.
