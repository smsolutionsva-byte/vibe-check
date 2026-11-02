"""Freeze 20 evaluation cases before final precision changes; never run scanner."""
import json
from pathlib import Path

cases = []


def add(file, source, rule, line, positive, reason):
    cases.append({'id': f'H{len(cases) + 1:02}', 'group': 'heldout',
                  'label': 'positive' if positive else 'negative', 'file': file,
                  'source': source, 'target_rules': [rule],
                  'expected': [{'rule': rule, 'line': line}] if positive else [],
                  'reason': reason})


shell = 'subprocess-shell-true'
sql = 'possible-sql-string-building'
secret = 'hardcoded-credential'
add('a.py', 'import subprocess as jobs\njobs.check_output(cmd, shell=True)\n', shell, 2, True, 'Module alias with shell enabled.')
add('a.py', 'from subprocess import Popen as spawn\nspawn(cmd, shell=True)\n', shell, 2, True, 'Imported constructor alias.')
add('a.py', 'from subprocess import run\nrun(cmd, shell=True)\n', shell, 2, True, 'Direct imported subprocess call.')
add('a.py', 'import subprocess as processes\nprocesses.call(\n cmd,\n shell=True,\n)\n', shell, 2, True, 'Multiline module-alias call.')
add('a.py', 'cursor.execute(f"SELECT name FROM users WHERE id = {user_id}")\n', sql, 1, True, 'Interpolated SQL in same cursor call; review, not confirmed injection.')
add('a.py', 'cur.execute("SELECT * FROM users WHERE name=" + name)\n', sql, 1, True, 'Literal concatenated in same cursor call.')
add('a.py', 'reader = connection.cursor()\nreader.execute(f"SELECT * FROM {table}")\n', sql, 2, True, 'Cursor acquired under a nonstandard variable name.')
add('a.py', 'cursor.execute(\n "SELECT * FROM " + table + " WHERE id=" + str(item_id)\n)\n', sql, 1, True, 'Multiline string-building argument in same call.')
add('a.ts', 'const serviceApiKey: string = "{{FAKE}}";\n', secret, 1, True, 'Runtime synthetic literal credential remains reportable.')
add('README.md', 'An accidentally published access identifier: {{AWS}}\n', 'aws-access-key', 1, True, 'Provider-specific token pattern must still be checked in documentation.')
add('a.js', 'errors.passwordError = "Password must meet the requirements";\n', secret, 1, False, 'Password validation message, not a credential.')
add('a.ts', 'const invalidPasswordErrorMessage = "Incorrect password supplied";\n', secret, 1, False, 'User-interface error message variable.')
add('a.py', '"""Example password="{{FAKE}}" shown in a tutorial."""\n', secret, 1, False, 'Documentation-only Python string.')
add('lesson.html', '<pre>SELECT * FROM account WHERE password=\'arbitrary input\' OR 1=1</pre>\n', secret, 1, False, 'SQL tutorial markup, not an executable credential assignment.')
add('README.md', 'Testing the lesson: password="{{FAKE}}" is synthetic.\n', secret, 1, False, 'Generic credential example in documentation.')
add('a.py', 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n', sql, 1, False, 'Parameterized query with separately supplied values.')
add('a.py', 'query = "SELECT * FROM users WHERE id=" + item_id\ncursor.execute(query)\n', sql, 2, False, 'String building occurs elsewhere; intentionally outside this same-call rule, not a claim it is safe.')
add('a.py', 'task.execute(f"work on {item}")\n', sql, 1, False, 'Unrelated execute method, no cursor evidence.')
add('a.py', 'from subprocess import run as launch\nlaunch(["echo", item], shell=False)\n', shell, 2, False, 'Aliased subprocess with shell explicitly disabled.')
add('a.py', 'import subprocess as jobs\ndef task(jobs):\n    jobs.run(command, shell=True)\n', shell, 3, False, 'Function argument shadows imported module; scope challenge.')

assert len(cases) == 20
assert sum(c['label'] == 'positive' for c in cases) == 10
with Path(__file__).with_name('heldout.json').open('x', encoding='utf-8') as handle:
    json.dump(cases, handle, indent=2)
print('20 labelled held-out cases frozen; scanner not imported or run.')
