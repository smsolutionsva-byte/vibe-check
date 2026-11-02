"""Run frozen, labelled snippets without executing them or contacting an API."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vibe_check.secrets import scan as scan_secrets
from vibe_check.risks import scan as scan_risks


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def materialize(source):
    replacements = {
        '{{FAKE}}': 'ABCD' + 'not-a-real-credential-0123456789',
        '{{AWS}}': 'AK' + 'IA' + 'Z' * 16,
        '{{GITHUB}}': 'gh' + 'p_' + 'Z' * 36,
        '{{GITHUB_PAT}}': 'github_' + 'pat_' + 'Z' * 82,
        '{{PEM_BEGIN}}': '-----BEGIN ' + 'RSA PRIVATE KEY-----',
        '{{PGP_BEGIN}}': '-----BEGIN ' + 'PGP PRIVATE KEY BLOCK-----',
    }
    for token, value in replacements.items():
        source = source.replace(token, value)
    return source


def ratios(counts):
    tp, fp, fn = (counts[k] for k in ('TP', 'FP', 'FN'))
    return {**counts, 'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None}


def evaluate(case_file=ROOT / 'benchmark' / 'cases.json'):
    cases = json.loads(case_file.read_text(encoding='utf-8'))
    assert cases
    assert len({c['id'] for c in cases}) == len(cases)
    if case_file.name == 'cases.json':
        assert len(cases) == 90
        assert {g: sum(c['group'] == g for c in cases) for g in ('positive', 'negative', 'tricky')} == {'positive': 40, 'negative': 40, 'tricky': 10}
    elif case_file.name == 'heldout.json':
        assert len(cases) == 20 and all(c['group'] == 'heldout' for c in cases)
    totals = dict(TP=0, FP=0, TN=0, FN=0)
    per_rule = {}
    details = []
    for case in cases:
        expected = {(x['rule'], x['line']) for x in case['expected']}
        assert bool(expected) == (case['label'] == 'positive')
        with tempfile.TemporaryDirectory(prefix='vibe-benchmark-') as tmp:
            root = Path(tmp)
            path = root / case['file']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(materialize(case['source']), encoding='utf-8')
            findings = scan_secrets(root) + scan_risks(root)
            actual = {(f.rule, f.line) for f in findings if f.severity != 'info' and f.path == case['file']}
        tp, fp, fn = expected & actual, actual - expected, expected - actual
        counts = dict(TP=len(tp), FP=len(fp), FN=len(fn), TN=int(not expected and not actual))
        for k, v in counts.items(): totals[k] += v
        for rule in set(case['target_rules']) | {r for r, _ in expected | actual}:
            row = per_rule.setdefault(rule, dict(TP=0, FP=0, TN=0, FN=0))
            row['TP'] += sum(r == rule for r, _ in tp)
            row['FP'] += sum(r == rule for r, _ in fp)
            row['FN'] += sum(r == rule for r, _ in fn)
            row['TN'] += int(not expected and rule in case['target_rules'] and not any(r == rule for r, _ in actual))
        details.append({'id': case['id'], 'group': case['group'], 'label': case['label'],
                        'expected': sorted(expected), 'actual': sorted(actual), **counts})
    return {'dataset_sha256': digest(case_file),
            'scanner_sha256': {path.name: digest(path) for path in sorted((ROOT / 'vibe_check').glob('*.py'))},
            'git_revision': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
            'case_count': len(cases), 'metrics': ratios(totals),
            'per_rule': {k: ratios(v) for k, v in sorted(per_rule.items())}, 'cases': details}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cases', type=Path, default=ROOT / 'benchmark' / 'cases.json')
    args = parser.parse_args()
    if args.output.exists(): parser.error('refusing to overwrite an existing result')
    result = evaluate(args.cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
    print(json.dumps({'overall': result['metrics'], 'per_rule': result['per_rule']}, indent=2))


if __name__ == '__main__': main()
