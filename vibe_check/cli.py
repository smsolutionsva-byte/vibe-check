"""Command-line entry point; scanning is under construction."""

import argparse
from pathlib import Path
import sys
import os
from .secrets import scan
from .risks import scan as scan_risks
from .ai import BharatCodeClient
from .report import render, verdict


def main() -> int:
    parser = argparse.ArgumentParser(description="Review a local repository before shipping.")
    parser.add_argument("path", type=Path, help="Repository directory to review")
    parser.add_argument("--ai", action="store_true", help="Request optional BharatCode explanations")
    parser.add_argument("--report", type=Path, default=Path('vibe-check-report.md'), help="Markdown report path")
    args = parser.parse_args()
    if not args.path.is_dir():
        parser.error("path must be an existing directory")
    try:
        findings = scan(args.path.resolve()) + scan_risks(args.path.resolve())
    except OSError as exc:
        print(f"Scan error: {exc}", file=sys.stderr)
        return 2
    explanations = []
    key = os.environ.get('BHARATCODE_API_KEY')
    client = BharatCodeClient(key) if args.ai and key else None
    unavailable = False
    for finding in findings:
        print(f"{finding.path}:{finding.line}: {finding.severity.upper()}: {finding.rule}: {finding.masked_value}")
        if args.ai:
            explanation = client.explain(finding) if client and not unavailable else None
            if explanation:
                print(f"  BharatCode explanation: {explanation}")
            else:
                unavailable = True
                print('  AI explanations unavailable: BharatCode access required.')
            explanations.append(explanation)
    try:
        args.report.write_text(render(findings, explanations, args.ai), encoding='utf-8')
    except OSError:
        print('Could not write Markdown report.', file=sys.stderr)
        return 2
    print(f"{len(findings)} finding(s)")
    levels = {f.severity for f in findings}
    print(verdict(findings))
    return 1 if levels.intersection({'high', 'medium'}) else 0


if __name__ == "__main__":
    raise SystemExit(main())
