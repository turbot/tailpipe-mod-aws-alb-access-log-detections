## Overview

Detect potential log poisoning attacks where attackers manipulate log files that may later be included by vulnerable applications. Log poisoning is an advanced exploitation technique used in conjunction with Local File Inclusion (LFI) vulnerabilities, where attackers first inject malicious code into logs and then use LFI to include and execute that code.

This detection identifies PHP code in User-Agent headers or URLs, where attackers often place their payloads to be written to log files. It looks for PHP tags, dangerous PHP functions like system(), exec(), and eval(), as well as encoded variants of these patterns. The detection also monitors for requests accessing common log files, which may indicate an attacker attempting to execute previously injected code.

**References**:
- [OWASP File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [OWASP Log Injection](https://owasp.org/www-community/attacks/Log_Injection)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [MITRE ATT&CK: Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/) 