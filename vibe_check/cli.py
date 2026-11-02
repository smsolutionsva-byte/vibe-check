"""Command-line entry point; scanning is under construction."""

import argparse
from pathlib import Path
import sys
import os
from .secrets import scan
from .risks import scan as scan_risks
from .ai import explain


def main() -> int:
    parser = argparse.ArgumentParser(description="Review a local repository before shipping.")
    parser.add_argument("path", type=Path, help="Repository directory to review")
    parser.add_argument("--ai", action="store_true", help="Request optional BharatCode explanations")
    args = parser.parse_args()
    if not args.path.is_dir():
        parser.error("path must be an existing directory")
    try:
        findings = scan(args.path.resolve()) + scan_risks(args.path.resolve())
    except OSError as exc:
        print(f"Scan error: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"{finding.path}:{finding.line}: {finding.severity.upper()}: {finding.rule}: {finding.masked_value}")
        if args.ai:
            key = os.environ.get('BHARATCODE_API_KEY')
            explanation = explain(finding, key) if key else None
            if explanation:
                print(f"  Explanation: {explanation}")
            else:
                print('  Explanation unavailable; deterministic finding retained.')
    print(f"{len(findings)} finding(s)")
    levels = {f.severity for f in findings}
    print('FIX FIRST' if 'high' in levels else 'REVIEW' if 'medium' in levels else 'SHIP')
    return 1 if levels.intersection({'high', 'medium'}) else 0


if __name__ == "__main__":
    raise SystemExit(main())
