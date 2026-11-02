# Progress — 2 November 2026

## Working

- Deterministic scanner and Markdown report with high/medium/info severity and FIX FIRST/REVIEW/SHIP verdicts.
- Masked secret findings and limited Python AST and JS/TS pattern checks.
- Optional BharatCode adapter sends fixed rule descriptions only. A labeled mock exists only in tests. Failed calls retain deterministic output.
- Local Git repository; no push or submission.

## Verification

- `python -m unittest discover -s tests -v`: 14 tests passed, including mocked API fallback and report masking.
- Sample one: fake Python credential plus eval, no named tests: 3 findings, FIX FIRST, exit 1. Credential shown as `abcd****`.
- Sample two: JavaScript child-process concatenation plus `new Function`: 2 findings, REVIEW, exit 1.
- All deliberately planted examples were found. These samples do not establish real-world accuracy. No false positives were observed in the two samples; no unplanted issues were independently audited.
- Model listing succeeded. Generation returned HTTP 402; real explanations remain unverified pending account access. Python's default TLS validation failed on this machine; an installed certifi bundle validated the model-list connection. Verification was not disabled.

## Known limitations

Patterns miss some secrets. JS/TS matching is not parsing and can report code-like strings or comments, miss multiline calls or aliases, and misattribute same-named exec functions. Missing-test observation covers only Python naming patterns and cannot establish whether tests exist elsewhere. Python syntax errors are skipped. The access-required message can also indicate a network or certificate failure.

## Demo script

1. Run `python -m unittest discover -s tests -v`.
2. Create a disposable directory containing `app.py` with a fake credential and `eval(input())`.
3. Run `python -m vibe_check.cli <sample-directory> --report demo-report.md`.
4. Show the masked finding, verdict and Markdown report; explain check limitations.
5. Once access works, use `--ai` and show a real explanation only if returned. Until then, show the unavailable message rather than a mock.

## Publishing and submission checklist

- [ ] Verify student access and test a real API generation; update the README.
- [ ] Review false positives and misses on representative code.
- [ ] Check demo files and Git history for secrets and private information.
- [ ] Confirm the current official rules and BharatCode.txt format.
- [ ] Review, then create/push the public GitHub repository yourself.
- [ ] Submit on the official Build League page before 10 November 2026, 11:59 PM IST.
