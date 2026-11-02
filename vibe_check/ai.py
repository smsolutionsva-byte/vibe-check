"""Optional BharatCode explanations, using only fixed rule descriptions."""
import json
import urllib.error
import urllib.request
from dataclasses import dataclass

URL = 'https://bharatcode.ai/api/model/v1/chat/completions'
MODEL = 'qwen-3.8-27b'
DESCRIPTIONS = {
    'aws-access-key': 'An AWS access key identifier was detected in a file.',
    'github-token': 'A GitHub token pattern was detected in a file.',
    'private-key-block': 'A private key block header was detected in a file.',
    'hardcoded-credential': 'A credential appears to be assigned a literal value.',
    'dynamic-code-execution': 'Python code calls eval or exec.',
    'subprocess-shell-true': 'Python subprocess is called with shell=True.',
    'js-eval': 'A JavaScript or TypeScript line matches an eval call.',
    'js-new-function': 'A JavaScript or TypeScript line matches a new Function call.',
    'js-child-process-concatenation': 'A JavaScript or TypeScript line matches child process exec with concatenation.',
    'no-python-test-files-found': 'No Python test files matched the naming patterns test_*.py or *_test.py.',
}


def explain(finding, key, opener=urllib.request.urlopen):
    description = DESCRIPTIONS.get(finding.rule)
    if description is None:
        return None
    payload = {'model': MODEL, 'messages': [{'role': 'user', 'content': 'Explain this static check in two short sentences, including uncertainty and a practical next step. Do not invent evidence: ' + description}]}
    request = urllib.request.Request(URL, data=json.dumps(payload).encode(), headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}, method='POST')
    try:
        with opener(request, timeout=20) as response:
            result = json.load(response)
        choice = result['choices'][0]
        text = choice['message']['content']
        return text.strip() if isinstance(text, str) and text.strip() else None
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return None


@dataclass
class BharatCodeClient:
    """Production adapter; credentials come from the caller's environment."""
    key: str

    def explain(self, finding):
        return explain(finding, self.key)
