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

Secret detection uses patterns for AWS and GitHub tokens, private-key headers and common literal credential assignments. Values are masked; private key bodies are not displayed. Common dependency/build directories, lockfiles, symlinks and binary files are skipped. Patterns can miss secrets and flag harmless literals.

Python risk checks use the standard-library AST. JavaScript/TypeScript checks for eval, new Function and concatenated child-process exec use line patterns, not full parsing. They can match strings or comments and miss multiline calls or aliases. The Python missing-test observation only checks `test_*.py` and `*_test.py` filenames. Tests may exist elsewhere. Its file and line point to a source file, not proof that tests are absent.

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
