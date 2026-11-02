# vibe-check report

**Verdict: FIX FIRST**

| Severity | Rule | File | Line | Evidence |
| --- | --- | --- | ---: | --- |
| high | private-key-block | artifacts/cert/server.key | 1 | [private key block] |
| high | hardcoded-credential | test/security/profile-test.js | 37 | User**** |
| medium | js-eval | app/routes/contributions.js | 32 | eval(...) |
| medium | js-eval | app/routes/contributions.js | 33 | eval(...) |
| medium | js-eval | app/routes/contributions.js | 34 | eval(...) |

Checks are limited and do not prove a repository is safe.
