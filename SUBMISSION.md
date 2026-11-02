# Submission draft

**Project name:** vibe-check

**Summary:** vibe-check is a Python CLI for reviewing AI-written code before it ships. It runs deterministic checks for common hardcoded secrets, risky code patterns and missing Python test filenames, then reports findings with file and line references and masked evidence. It can request plain-English explanations from BharatCode without sending source code or secret values. A Markdown report and severity-based verdict help developers decide what to review. The scanner works without API access; its pattern checks are a triage aid, not a security audit.
