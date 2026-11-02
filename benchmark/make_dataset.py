"""Reproduce the pre-labelled corpus. Does not import or run the scanner.

cases.json is the frozen source of truth for benchmark/run.py.
"""
import json
from pathlib import Path

cases = []


def add(group, file, source, rule, line=1, positive=True, reason=''):
    prefix = {'positive': 'P', 'negative': 'N', 'tricky': 'T'}[group]
    number = 1 + sum(c['group'] == group for c in cases)
    cases.append({'id': f'{prefix}{number:02}', 'group': group,
                  'label': 'positive' if positive else 'negative', 'file': file,
                  'source': source, 'target_rules': [rule],
                  'expected': [{'rule': rule, 'line': line}] if positive else [],
                  'reason': reason or ('Literal credential or code-execution review pattern.' if positive else 'No actionable review pattern; safe or illustrative context.')})


credential = 'hardcoded-credential'
for file, source in [
    ('app.py', 'api_key = "{{FAKE}}"\n'),
    ('app.py', 'secret_key = "{{FAKE}}"\n'),
    ('app.py', 'access_token = "{{FAKE}}"\n'),
    ('app.py', 'password = "{{FAKE}}"\n'),
    ('app.js', 'const apiKey = "{{FAKE}}";\n'),
    ('app.js', 'const config = {api_key: "{{FAKE}}"};\n'),
    ('app.ts', 'const apiKey: string = "{{FAKE}}";\n'),
    ('app.ts', 'const accessToken: string = "{{FAKE}}";\n'),
    ('app.go', 'apiKey := "{{FAKE}}"\n'),
    ('app.go', 'var api_key = "{{FAKE}}"\n'),
    ('app.php', '<?php $api_key = "{{FAKE}}";\n'),
    ('app.rb', 'api_key = "{{FAKE}}"\n'),
    ('app.rs', 'let api_key: &str = "{{FAKE}}";\n'),
    ('.env', 'API_KEY={{FAKE}}\n'),
    ('.env', 'export API_KEY="{{FAKE}}"\n'),
    ('app.py', 'api_key = b"{{FAKE}}"\n'),
]: add('positive', file, source, credential)

for file, source, rule in [
    ('app.py', 'token = "{{AWS}}"\n', 'aws-access-key'),
    ('app.go', 'key := "{{AWS}}"\n', 'aws-access-key'),
    ('app.js', 'const token = "{{GITHUB}}";\n', 'github-token'),
    ('app.rs', 'let token = "{{GITHUB_PAT}}";\n', 'github-token'),
    ('key.pem', '{{PEM_BEGIN}}\nNOT-A-REAL-KEY\n-----END RSA PRIVATE KEY-----\n', 'private-key-block'),
    ('key.asc', '{{PGP_BEGIN}}\nNOT-A-REAL-KEY\n-----END PGP PRIVATE KEY BLOCK-----\n', 'private-key-block'),
    ('app.rb', 'token = "{{GITHUB}}"\n', 'github-token'),
    ('.env', 'ACCESS_ID={{AWS}}\n', 'aws-access-key'),
]: add('positive', file, source, rule)

for file, source, rule, line in [
    ('app.py', 'eval(user_input)\n', 'dynamic-code-execution', 1),
    ('app.py', 'exec(user_input)\n', 'dynamic-code-execution', 1),
    ('app.py', 'import subprocess\nsubprocess.run(command, shell=True)\n', 'subprocess-shell-true', 2),
    ('app.py', 'import subprocess\nsubprocess.Popen(command, shell=True)\n', 'subprocess-shell-true', 2),
    ('app.js', 'eval(input);\n', 'js-eval', 1),
    ('app.ts', 'eval(input);\n', 'js-eval', 1),
    ('app.mjs', 'eval(input);\n', 'js-eval', 1),
    ('app.js', 'new Function(code);\n', 'js-new-function', 1),
    ('app.ts', 'new Function("x", code);\n', 'js-new-function', 1),
    ('app.cjs', 'new Function(code);\n', 'js-new-function', 1),
    ('app.js', 'const cp = require("child_process");\ncp.exec("echo " + input);\n', 'js-child-process-concatenation', 2),
    ('app.js', 'const {exec} = require("child_process");\nexec("echo " + input);\n', 'js-child-process-concatenation', 2),
    ('app.ts', 'import {exec} from "node:child_process";\nexec("echo " + input);\n', 'js-child-process-concatenation', 2),
    ('app.mjs', 'import * as cp from "child_process";\ncp.exec("echo " + input);\n', 'js-child-process-concatenation', 2),
    ('app.py', 'eval(\n    user_input\n)\n', 'dynamic-code-execution', 1),
    ('app.py', 'exec(\n    user_input\n)\n', 'dynamic-code-execution', 1),
]: add('positive', file, source, rule, line)

for file, source in [
    ('app.py', 'api_key = "your_api_key"\n'),
    ('app.js', 'const apiKey = "placeholder";\n'),
    ('app.ts', 'const apiKey = "<YOUR_API_KEY>";\n'),
    ('app.go', 'apiKey := "changeme"\n'),
    ('app.php', '<?php $api_key = "example_key";\n'),
    ('app.rb', 'secret_key = "secret-key"\n'),
    ('app.rs', 'let api_key = "your-key-here";\n'),
    ('.env', 'API_KEY=your_api_key\n'),
    ('app.py', 'api_key = os.environ["API_KEY"]\n'),
    ('app.js', 'const apiKey = process.env.API_KEY;\n'),
    ('app.ts', 'const apiKey: string = process.env.API_KEY!;\n'),
    ('app.go', 'apiKey := os.Getenv("API_KEY")\n'),
    ('app.php', '<?php $api_key = getenv("API_KEY");\n'),
    ('app.rb', 'api_key = ENV.fetch("API_KEY")\n'),
    ('app.rs', 'let api_key = std::env::var("API_KEY");\n'),
    ('.env', 'API_KEY=${API_KEY}\n'),
    ('README.md', 'Example: API_KEY="your_api_key"\n'),
    ('guide.rst', 'export SECRET_KEY="base64 encoded random bytes"\n'),
    ('README.md', 'Never use eval(user_input).\n'),
    ('guide.txt', 'Avoid new Function(code) in your application.\n'),
]: add('negative', file, source, credential if len(cases) < 58 else 'js-eval', positive=False)

for file, source, rule in [
    ('app.js', 'const m = /[a-z]+/.exec(text);\n', 'js-child-process-concatenation'),
    ('app.ts', 'const m = /abc/.exec(text + suffix);\n', 'js-child-process-concatenation'),
    ('app.py', 'import subprocess\nsubprocess.run(["echo", name], shell=False)\n', 'subprocess-shell-true'),
    ('app.py', 'message = "eval(user_input)"\n', 'dynamic-code-execution'),
    ('app.py', '# exec(user_input)\nvalue = 1\n', 'dynamic-code-execution'),
    ('app.js', '// eval(input);\nconst x = 1;\n', 'js-eval'),
    ('app.ts', '/* new Function(code) */\nconst x = 1;\n', 'js-new-function'),
    ('app.js', 'const message = "eval(input)";\n', 'js-eval'),
    ('app.ts', 'const message = "new Function(code)";\n', 'js-new-function'),
    ('app.js', '/*\neval(input);\n*/\n', 'js-eval'),
    ('app.ts', '/*\nnew Function(code);\n*/\n', 'js-new-function'),
    ('app.py', 'count = sum([1, 2, 3])\n', 'dynamic-code-execution'),
    ('app.js', 'const count = [1, 2].length;\n', 'js-eval'),
    ('app.go', 'fmt.Println("hello")\n', credential),
    ('app.php', '<?php echo "hello";\n', credential),
    ('app.rb', 'puts "hello"\n', credential),
    ('app.rs', 'fn main() { println!("hello"); }\n', credential),
    ('.env', 'PORT=8080\n', credential),
    ('app.py', '# api_key = "{{FAKE}}"\nvalue = 1\n', credential),
    ('app.js', '// const apiKey = "{{FAKE}}";\n', credential),
]: add('negative', file, source, rule, positive=False)

for file, source, rule, line, positive, reason in [
    ('app.py', 'import subprocess as sp\nsp.run(command, shell=True)\n', 'subprocess-shell-true', 2, True, 'Imported module alias, shell explicitly enabled.'),
    ('app.py', 'from subprocess import run as launch\nlaunch(command, shell=True)\n', 'subprocess-shell-true', 2, True, 'Imported call alias, shell explicitly enabled.'),
    ('app.ts', 'eval\n(\n input\n);\n', 'js-eval', 1, True, 'Multiline eval call.'),
    ('app.js', 'new\nFunction(code);\n', 'js-new-function', 1, True, 'Multiline Function constructor.'),
    ('app.ts', 'import {exec as launch} from "child_process";\nlaunch("echo " + input);\n', 'js-child-process-concatenation', 2, True, 'Named child-process import alias.'),
    ('app.py', 'api_key = (\n "{{FAKE}}"\n)\n', credential, 1, True, 'Multiline Python literal assignment.'),
    ('app.js', 'const cp = require("child_process");\ncp.exec(\n "echo " + input\n);\n', 'js-child-process-concatenation', 2, True, 'Multiline child-process concatenation.'),
    ('app.js', 'const x = 1; // eval(input);\n', 'js-eval', 1, False, 'Inline comment, not a call.'),
    ('app.ts', 'const doc = `eval(input)`;\n', 'js-eval', 1, False, 'Plain template text without interpolation.'),
    ('app.js', 'const cp = require("child_process");\nconst result = regex.exec(text + suffix);\n', 'js-child-process-concatenation', 2, False, 'Unrelated regex method despite child-process import.'),
]: add('tricky', file, source, rule, line, positive, reason)

assert len(cases) == 90
assert [sum(c['group'] == g for c in cases) for g in ('positive', 'negative', 'tricky')] == [40, 40, 10]
output = Path(__file__).with_name('cases.json')
with output.open('x', encoding='utf-8') as handle:
    json.dump(cases, handle, indent=2)
print('Wrote 90 pre-labelled cases. No scanner was imported or run.')
