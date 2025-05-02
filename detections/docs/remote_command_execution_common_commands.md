## Overview

Detect attempts to execute common system commands through potential remote command execution vulnerabilities. This detection identifies requests containing command patterns that indicate an attacker is trying to run operating system commands on the server by exploiting input validation flaws.

This detection monitors for common Unix commands (cat, wget, curl, bash, python, chmod), Windows commands (cmd.exe, powershell, net user), and various URL-encoded variants of these commands. These patterns may indicate reconnaissance activity, attempts to exfiltrate data, or efforts to establish persistent access through web application vulnerabilities.

**References**:
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Portswigger OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [MITRE ATT&CK: Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/) 