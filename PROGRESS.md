# Progress — 2 November 2026

## Working

- Deterministic scanner and Markdown report with high/medium/info severity and FIX FIRST/REVIEW/SHIP verdicts.
- Masked secret findings and limited Python AST and JS/TS pattern checks.
- Optional BharatCode adapter sends fixed rule descriptions only. A labeled mock exists only in tests. Failed calls retain deterministic output.
- Local Git repository; no push or submission.

## Verification

- `python -m unittest discover -s tests -v`: 14 tests passed, including mocked API fallback and report masking.
- Fresh temporary Python virtual environment: `python -m pip install -e .` and installed `vibe-check --help` both succeeded on 2 November 2026.
- Sample one: fake Python credential plus eval, no named tests: 3 findings, FIX FIRST, exit 1. Credential shown as `abcd****`.
- Sample two: JavaScript child-process concatenation plus `new Function`: 2 findings, REVIEW, exit 1.
- All deliberately planted examples were found. These samples do not establish real-world accuracy. No false positives were observed in the two samples; no unplanted issues were independently audited.
- Model listing succeeded. On 2 November 2026, a real `vibe_check.cli` run using model `qwen-3.8-27b` returned: "This check flags a JavaScript or TypeScript line that appears to call `eval`, which may execute unsafe code. Review the flagged line and remove or justify the `eval` use." The production adapter was used, not the mock. Python's default TLS validation failed on this machine; an installed certifi bundle validated the connection. Verification was not disabled.

## Public repository evaluation

Read-only shallow clones, 2 November 2026:

- pallets/itsdangerous at 672971d66a2ef9f85151e53283113f33d642dabd: initially 8 high findings, all inspected and identified as test placeholders or documentation examples. Narrow exact-placeholder filters reduced findings to 0; regression test added. Suppressing these exact strings could miss a real but weak credential with the same value.
- chalk/ansi-styles at 8cf247afbecf29a8227f7d0beb69c2997fc6bc61: 0 findings before and after. Its regular-expression `.exec()` call was not misidentified as child-process execution.
- pallets/markupsafe at 4e111271b1494995708a9e878a10829b5e10c7ba: 0 findings before and after.

These clean outcomes are not proof of safety. A targeted search for selected risky APIs found no additional supported pattern in their source; no exhaustive security audit was performed, so actual misses in these repos are undetermined. Known scanner misses include JS/TS test discovery, multiline expressions, aliases and unsupported credential formats.

The working-tree self-scan after building fake test credentials at runtime reports zero findings. An audit of all three existing commits found only fake test and README fixtures; they remain in the old Git history and could still trigger external scanners. No tracked `.env` file was found; `.env.example` is the only environment template in history. This pattern-based audit cannot guarantee the absence of every possible secret.

## Known limitations

Patterns miss some secrets. JS/TS checks now filter ordinary strings/comments, support basic multiline calls and attribute child-process calls to simple imports; they still do not parse the language or resolve scope/reassigned bindings. Template interpolation, regex literals and Python subprocess aliases remain gaps. Missing-test observation covers only Python naming patterns and cannot establish whether tests exist elsewhere. Python syntax errors are skipped. The access-required message can also indicate a network or certificate failure.

## Frozen benchmark and vulnerable repositories — 2 November 2026

- Dataset frozen in `d9d4f8b` before scanning: 40 ordinary positives, 40 negatives, 10 tricky cases (7 positive / 3 negative). No cases were edited or relabelled after baseline.
- `python benchmark/run.py --output benchmark/results/baseline.json`: TP 38, FP 9, TN 34, FN 9; precision/recall both 80.85% on this set.
- Fixed three areas: JS comment/string context, literal-credential extraction, and child-process call attribution/multiline aliases. Added regression tests, including a public-repo attribute/subscript regression discovered during inspection.
- `python benchmark/run.py --output benchmark/results/final.json`: TP 45, FP 0, TN 43, FN 2; precision 100%, recall 95.74% on this same synthetic set only. Two Python subprocess-alias misses remain. No held-out set was used.
- `python -m unittest discover -s tests -v`: 22 tests passed; no final failures. Earlier intermediate run passed 20 before two more test methods were added.
- `python -m vibe_check.cli ..\eval-nodegoat --report benchmark/results/nodegoat.md`: 7 findings, FIX FIRST, exit 1. Three eval calls correspond to its documented injection lesson; error-message and test/example false positives remain.
- `python -m vibe_check.cli ..\eval-pygoat --report benchmark/results/pygoat-final.md`: 22 findings, FIX FIRST, exit 1. Its documented shell/eval labs were found. Documented SQL injection/SSRF and other classes remain outside coverage; tutorial text also creates false positives.
- Both public clones stayed clean according to `git status --porcelain`. No code or dependencies from them were run. Exact revisions, masked reports and source/documentation links are in BENCHMARK.md.
- Some attempted clone URLs in the earlier small-repo evaluation returned repository-not-found; neither vulnerable-repo clone in this benchmark failed.

## Demo script

1. Run `python -m unittest discover -s tests -v`.
2. Create a disposable directory containing `app.py` with a fake credential and `eval(input())`.
3. Run `python -m vibe_check.cli <sample-directory> --report demo-report.md`.
4. Show the masked finding, verdict and Markdown report; explain check limitations.
5. Use `--ai` and show the real explanation only if returned; otherwise show the unavailable message rather than a mock.

## Publishing and submission checklist

- [x] Test a real API generation and record the observed output and model.
- [ ] Review false positives and misses on representative code.
- [ ] Review historical fake test fixtures before publishing; pattern-based history audit found no confirmed real keys, but cannot guarantee completeness.
- [ ] Confirm the current official rules and BharatCode.txt format.
- [ ] Review, then create/push the public GitHub repository yourself.
- [ ] Submit on the official Build League page before 10 November 2026, 11:59 PM IST.
