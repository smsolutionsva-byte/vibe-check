# vibe-check report

**Verdict: FIX FIRST**

| Severity | Rule | File | Line | Evidence |
| --- | --- | --- | ---: | --- |
| high | hardcoded-credential | dockerized_labs/auth_failure_lab/app.py | 44 | 2022**** |
| high | hardcoded-credential | dockerized_labs/insufficient_logging_lab/README.md | 20 | secr**** |
| high | hardcoded-credential | dockerized_labs/insufficient_logging_lab/templates/lab1.html | 58 | secr**** |
| high | hardcoded-credential | dockerized_labs/insufficient_logging_lab/templates/secure-fix.html | 104 | secr**** |
| high | hardcoded-credential | dockerized_labs/sec_misconfig/Dockerfile | 13 | jwt_**** |
| high | aws-access-key | dockerized_labs/sec_misconfig/app.py | 58 | AKIA**** |
| high | hardcoded-credential | dockerized_labs/sensitive_data_exposure/entrypoint.sh | 11 | demo**** |
| high | hardcoded-credential | dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py | 8 | djan**** |
| high | hardcoded-credential | dockerized_labs/sensitive_data_exposure/templates/profile.html | 228 | supe**** |
| high | hardcoded-credential | dockerized_labs/sql_injection_lab/templates/index.html | 57 | anyt**** |
| high | hardcoded-credential | introduction/templates/Lab/SQL/sql.html | 63 | <b>a**** |
| high | hardcoded-credential | introduction/templates/Lab_2021/A3_Injection/injection.html | 72 | <b>a**** |
| high | hardcoded-credential | pygoat/settings.py | 23 | lr66**** |
| medium | subprocess-shell-true | dockerized_labs/command_injection_lab/app.py | 29 | subprocess.Popen(shell=True) |
| medium | dynamic-code-execution | dockerized_labs/command_injection_lab/app.py | 49 | eval(...) |
| info | no-python-test-files-found | PyGoatBot.py | 1 | No test files matched common naming patterns. Tests may exist elsewhere. |

Checks are limited and do not prove a repository is safe.
