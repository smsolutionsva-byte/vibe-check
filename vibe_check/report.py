"""Render evidence without fetching or including original source lines."""
from pathlib import Path


def verdict(findings):
    levels = {f.severity for f in findings}
    return 'FIX FIRST' if 'high' in levels else 'REVIEW' if 'medium' in levels else 'SHIP'


def clean(text):
    return str(text).replace('\\', '\\\\').replace('|', '\\|').replace('\r', ' ').replace('\n', ' ')


def render(findings, explanations=None, ai_requested=False):
    explanations = explanations or [None] * len(findings)
    rows = ['# vibe-check report', '', '**Verdict: ' + verdict(findings) + '**', '', '| Severity | Rule | File | Line | Evidence |', '| --- | --- | --- | ---: | --- |']
    for finding in findings:
        rows.append(f'| {clean(finding.severity)} | {clean(finding.rule)} | {clean(finding.path)} | {finding.line} | {clean(finding.masked_value)} |')
    if not findings:
        rows.append('| — | No findings | — | — | — |')
    if ai_requested:
        rows.extend(['', '## AI explanations', ''])
        for finding, explanation in zip(findings, explanations):
            rows.append(f'- {clean(finding.path)}:{finding.line} ({clean(finding.rule)}): {clean(explanation) if explanation else "AI explanations unavailable: BharatCode access required."}')
    rows.extend(['', 'Checks are limited and do not prove a repository is safe.', ''])
    return '\n'.join(rows)
