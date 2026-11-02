# vibe-check

Work in progress: a CLI to review AI-written code before shipping.

JS/TS checks are simple text patterns, not full parsing; they can miss issues or match code-like text in strings and comments. Python risk checks use the standard-library AST. Missing Python test filenames are informational and do not prove tests are absent.

High findings produce FIX FIRST and exit 1; medium findings produce REVIEW and exit 1; informational findings alone produce SHIP and exit 0. Errors exit 2.

Pass `--ai` to request optional BharatCode explanations using `BHARATCODE_API_KEY`. The model receives only predefined descriptions of the triggered rules, not paths, snippets or secret values. Missing credentials or API failures leave deterministic findings available. This integration has not been tested against the live API yet.

`BharatCode.txt` follows the participant-supplied format and can be updated if BharatCode publishes a required format.
