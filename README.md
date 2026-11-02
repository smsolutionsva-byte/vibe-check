# vibe-check

Review a local repository for potentially risky patterns before shipping. Findings show rule, file, line and masked evidence. This is a triage aid, not proof code is safe.

## Install

Requires Python 3.10+. From this folder run `python -m pip install -e .` then `vibe-check --help`. The scanner uses only the standard library. Without installation, use `python -m vibe_check.cli` from this directory.

## Usage

```powershell
vibe-check C:\path\to\repository
vibe-check C:\path\to\repository --report report.md
vibe-check C:\path\to\repository --ai
```

The default report is `vibe-check-report.md` in the current directory. High findings produce FIX FIRST and exit 1; medium findings produce REVIEW and exit 1; informational findings alone produce SHIP and exit 0. Usage and read/write errors exit 2.

Example using fake data:

```text
app.py:1: HIGH: hardcoded-credential: abcd****
app.py:2: MEDIUM: dynamic-code-execution: eval(...)
app.py:1: INFO: no-python-test-files-found: No test files matched common naming patterns. Tests may exist elsewhere.
3 finding(s)
FIX FIRST
```

## Scope and limitations

Secret detection uses patterns for AWS and GitHub tokens, private-key headers and common literal credential assignments. Values are masked; private key bodies are not displayed. Common dependency/build directories, lockfiles, symlinks and binary files are skipped. UI names such as passwordError/password_error are excluded from generic credential checks. Generic assignments in `.md`, `.markdown`, `.rst`, `.txt`, `.html`, `.htm` and `.adoc` are skipped to avoid tutorial false positives; provider-specific token and private-key patterns are still checked there. This precision tradeoff can miss real generic credentials or inline-script keys in documentation/HTML. Patterns can still miss secrets and flag harmless literals.

Python risk and literal-credential checks use the standard-library AST. Basic subprocess module/import aliases are resolved, with function-parameter shadowing and direct reassignment handled. Dynamic imports, arbitrary alias assignments and full Python scope/control-flow analysis are not covered. JavaScript/TypeScript risk checks for eval, new Function and concatenated child-process exec use lexical filtering and patterns, not full parsing. They ignore ordinary strings/comments and support basic multiline calls and child-process import aliases. Template interpolation, regex literals, binding scope and reassigned JS imports remain limitations. The Python missing-test observation only checks `test_*.py` and `*_test.py` filenames. Tests may exist elsewhere. Its file and line point to a source file, not proof that tests are absent.

`possible-sql-string-building` is a medium-severity review hint labelled **possible SQL string building**. It looks for a dynamic f-string or an addition expression containing a string literal in the first argument of a cursor-like `.execute` call. Receivers named `cursor`, `cur` or `db_cursor`, or simple variables assigned from `.cursor()`, are recognized. It is not proof of SQL injection. It does not trace query variables, `.format`/percent formatting or arbitrary cursor/data flows. **XSS, SSRF and full SQL injection detection are not covered.**

## BharatCode API

Set `BHARATCODE_API_KEY` and pass `--ai`. The adapter sends only fixed descriptions of triggered rules to the BharatCode Chat Completions API; it does not send source, paths, masked values or complete secrets. Findings remain available on failure. `AI explanations unavailable: BharatCode access required.` also appears for connection failures and does not diagnose the cause.

The [official API docs](https://bharatcode.ai/build) specify the endpoint and model used. A real generation succeeded on 2 November 2026 using `qwen-3.8-27b`. Mock output is used only in tests and labeled MOCK ONLY. On systems with certificate errors, configure `SSL_CERT_FILE` to a current trusted bundle; do not disable SSL verification. If certifi is already installed, PowerShell can set it for the current session with `$env:SSL_CERT_FILE = python -c "import certifi; print(certifi.where())"`.

## Demo and tests

Run `python -m unittest discover -s tests -v`. Create a disposable directory with a fake credential assignment and `eval(input())` in `app.py`, then scan it. The report should mask the value and show FIX FIRST. Do not use real credentials as demo data.

Real CLI output from a disposable `example.js` containing `eval(input);`, using `--ai` and model `qwen-3.8-27b`:

```text
example.js:1: MEDIUM: js-eval: eval(...)
  BharatCode explanation: This check flags a JavaScript or TypeScript line that appears to call `eval`, which may execute unsafe code. Review the flagged line and remove or justify the `eval` use.
1 finding(s)
REVIEW
```

`BharatCode.txt` follows the participant-supplied format and can be updated if BharatCode publishes a required format.

## Benchmark

See [BENCHMARK.md](BENCHMARK.md) for the frozen 90-case synthetic set, saved before/after measurements, per-rule results, remaining misses, and read-only comparisons with documented NodeGoat/PyGoat issues. These measurements are limited to the labelled cases; they do not establish general accuracy or security. Run `python benchmark/run.py --output benchmark/results/my-run.json` for a fresh measurement. Existing result files cannot be overwritten by the runner.

The final precision pass also has a separate 20-case held-out set, frozen before its rule changes and evaluated once afterward. Its result is recorded separately in BENCHMARK.md; rules were not tuned after observing it. The set is author-created and small, so it is not evidence of broad accuracy.

## Local web UI

Run `python -m vibe_check.web` from this folder, then paste a public GitHub repository link. It listens only on 127.0.0.1. Repositories are shallow-cloned to a temporary folder, never executed, and deleted after scanning. The Explain button sends only the fixed rule description to BharatCode, never repository content, and requires `BHARATCODE_API_KEY`.

