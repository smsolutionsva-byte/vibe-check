"""Render saved measurements; never rerun the scanner or edit case labels."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
before = json.loads((ROOT / 'benchmark/results/baseline.json').read_text())
after = json.loads((ROOT / 'benchmark/results/final.json').read_text())
assert before['dataset_sha256'] == after['dataset_sha256']


def percent(value):
    return 'N/A' if value is None else f'{value:.2%}'


lines = [
    '# Benchmark — 2 November 2026', '',
    'These results describe this labelled synthetic set only. They do not establish security or general accuracy. The same set guided fixes and measured them; there is no held-out set.', '',
    '## Dataset frozen before scanning', '',
    '- Ground truth: `benchmark/cases.json`, frozen in commit `d9d4f8b` before the first scanner run.',
    '- 40 ordinary positive cases, 40 ordinary negative cases and 10 tricky cases (7 positive, 3 negative): 47 expected findings and 43 negatives overall.',
    '- Languages: Python, JS/TS, Go, PHP, Ruby, Rust and .env. Generic secret assignments cover all these languages; execution rules apply only to Python and JS/TS.',
    '- All credential-shaped values are synthetic and materialized only in temporary directories. Snippets are never executed. No AI/API is used by the benchmark.',
    '- Dataset SHA-256 (identical before/after): `' + before['dataset_sha256'] + '`.',
    '- No cases were removed, relabelled or edited after the baseline. `make_dataset.py` records the pre-run construction; the runner reads the frozen JSON, not this generator.', '',
    '## Scoring', '',
    'TP is an expected rule/starting-line pair matched by an actionable finding. FN is an unmatched expected pair. FP is an unexpected actionable pair. TN is a negative case with no actionable findings. Information findings are excluded. A wrong rule or line can create both an FP and an FN. Duplicated identical rule/line pairs are collapsed. This set has one expected finding per positive.', '',
    'Precision = TP / (TP + FP); recall = TP / (TP + FN). Per-rule TN means a negative case explicitly assigned to that rule, not every case without that rule. N20 is a negative documentation example mentioning new Function but its pre-frozen routing metadata targets js-eval; it remains untouched. This affects per-rule TN allocation, not overall TP/FP/TN/FN.', '',
    '| Run | TP | FP | TN | FN | Precision | Recall |',
    '| --- | ---: | ---: | ---: | ---: | ---: | ---: |',
]
for title, result in [('Before fixes', before), ('After fixes', after)]:
    m = result['metrics']
    lines.append(f"| {title} | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} | {percent(m['precision'])} | {percent(m['recall'])} |")
lines += ['', '## Per-rule results', '', '| Rule | Before TP/FP/TN/FN | After TP/FP/TN/FN | Before precision/recall | After precision/recall |', '| --- | --- | --- | --- | --- |']
for rule, b in before['per_rule'].items():
    a = after['per_rule'][rule]
    fmt = lambda row: '/'.join(str(row[k]) for k in ('TP', 'FP', 'TN', 'FN'))
    lines.append(f"| {rule} | {fmt(b)} | {fmt(a)} | {percent(b['precision'])}/{percent(b['recall'])} | {percent(a['precision'])}/{percent(a['recall'])} |")
lines += [
    '', '## Three problem areas fixed', '',
    '1. JS context filtering: remove quoted strings, template text and line/block comments from the risk-matching view while preserving offsets. Match eval and new Function across whitespace/newlines. This removes code-like-text false positives and recovers multiline calls.',
    '2. Literal credentials: Python AST handling distinguishes real literal assignments/keyword arguments from comments and env reads and supports bytes, multiline literals, attributes and subscript settings. Generic patterns now accept Rust &str annotations; JS/Go/Rust/PHP comment filtering reduces assignment-in-comment false positives. A public-repo regression check preserves Python attribute/subscript settings.',
    '3. Child-process attribution: recognize basic CommonJS/ES module bindings and aliases, constrain exec calls to those bindings, and inspect the first argument across line breaks. An unrelated regex.exec is no longer attributed to an imported child_process module.', '',
    '## Remaining benchmark misses', '',
    '- T01: `import subprocess as sp` followed by `sp.run(..., shell=True)`.',
    '- T02: `from subprocess import run as launch` followed by `launch(..., shell=True)`.',
    'These stay labelled positive and count as two false negatives. Python subprocess alias resolution was not one of the three selected fixes.', '',
    '## Reproduce', '',
    '```powershell',
    'python benchmark/run.py --output benchmark/results/my-run.json',
    'python -m unittest discover -s tests -v',
    '```', '',
    'The runner prints overall and per-rule measurements and refuses to overwrite results. Original baseline: `benchmark/results/baseline.json`. Final result: `benchmark/results/final.json`. `after.json` and `after-final.json` preserve intermediate runs; final.json includes the attribute/subscript regression fix. Source hashes identify the scanner state; the recorded Git revision is the checked-out parent while rule edits were uncommitted. Do not use revision alone to identify those scanner versions. Raw dataset hashes can vary with checkout newline conversion; parsed labels and source text must also be compared when reproducing on other platforms.', '',
    '## Read-only vulnerable-repo comparison', '',
    'Both clones were scanned without executing their code, installing their dependencies or changing their worktrees. `git status --porcelain` was empty for both afterward. Reports are masked and stored here, not in the clones. No exploit attempts, dependency audits or complete ground-truth vulnerability counts were performed. Public repo findings are not included in the 90-case metrics.', '',
    '### OWASP NodeGoat', '',
    '- Repository revision: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`.',
    '- Command: `python -m vibe_check.cli ..\\eval-nodegoat --report benchmark/results/nodegoat.md`.',
    '- Observed: 7 findings (4 high, 3 medium), FIX FIRST, exit 1.',
    '- Confirmed documented overlap: the [server-side JS injection lesson](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a1.html#L149) describes untrusted contribution inputs passed to eval. The scanner flags [contributions.js lines 32–34](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/contributions.js#L32).',
    '- Confirmed false positives: `app/routes/session.js:61` and `:172` are password error-message strings, not passwords. Broad name matching still causes these.',
    '- Context-only findings: `test/security/profile-test.js:37` is a test credential; `artifacts/cert/server.key:1` is a bundled private-key block. They are real literals/artifacts, but neither is evidence of a live production secret. Values were not reproduced.',
    '- Missed/out of scope: the [stored XSS lesson](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a3.html#L153) is not detected. `config/env/all.js:8` contains a cookieSecret setting which the credential-name patterns miss. No complete vulnerability recall can be calculated.', '',
    '### PyGoat', '',
    '- Repository revision: `2aa4cc14f251e4a780e94e200aed6b36a5b15c21`.',
    '- Final command: `python -m vibe_check.cli ..\\eval-pygoat --report benchmark/results/pygoat-final.md`.',
    '- Observed final: 22 findings (19 high, 2 medium, 1 info), FIX FIRST, exit 1. Earlier `pygoat.md` preserves the 16-finding scan before the Python attribute/subscript regression fix.',
    '- Confirmed documented overlap: [command-injection lab README](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/dockerized_labs/command_injection_lab/README.md) describes both shell command execution and eval; flags occur at [app.py:29 and :49](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/dockerized_labs/command_injection_lab/app.py#L29).',
    '- Confirmed false positives: SQL-injection tutorial query text is reported as a password in `dockerized_labs/sql_injection_lab/templates/index.html:57`, `introduction/templates/Lab/SQL/sql.html:63` and `introduction/templates/Lab_2021/A3_Injection/injection.html:72`.',
    '- Additional findings include deliberately exposed lab settings/default credentials, an AWS-shaped lab value, and credentials mentioned in instructional HTML/README text. These were not validated as live keys; do not interpret their count as confirmed security bugs. The insufficient-logging README and HTML findings are educational credential examples, not independently established secret leaks.',
    '- Documented misses: the [SQL-injection lab](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/dockerized_labs/sql_injection_lab/README.md) constructs an unsafe query at `app.py:50–57`; no SQL-injection rule flags it. The [SSRF lab](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/dockerized_labs/ssrf_lab/README.md) has request-derived paths at `app.py:18–22` and URL fetching at `:35–37`; neither is detected.',
    '- The info finding points to a source file because no Python test filenames matched; it is not proof of missing tests.', '',
    '## Known limits', '',
    'Small hand-authored set; fixes were selected using the same cases, so overfitting is possible. Some rule/language combinations have few or no negatives. Inputs are snippets, not compiler-validated applications. JS/TS filtering is not full parsing: template interpolation and regex literals, lexical scope, shadowing and reassigned imports can cause misses or false positives. The shell rule lacks Python alias resolution. Generic credential names, lengths and explicit placeholder suppression can still miss real secrets or flag harmless text. Python syntax errors are skipped for AST checks. No SQL/XSS/SSRF/dataflow, dependency, runtime or test-quality analysis is performed. A SHIP verdict means only that these checks found no high/medium evidence, not that shipping is safe.', '',
    'Unit tests: 22 test methods passed in the final run (see PROGRESS.md for commands). No failed tests remained. No push or submission was performed.', '',
]
(ROOT / 'BENCHMARK.md').write_text('\n'.join(lines), encoding='utf-8')
print('Wrote BENCHMARK.md from preserved baseline and final measurements.')
