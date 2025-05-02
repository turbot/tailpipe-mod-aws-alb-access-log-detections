## Overview

Detect attempts to use shell operators and special characters that could enable command chaining and remote code execution. This detection identifies requests containing shell syntax that might allow attackers to execute multiple commands, redirect output, or otherwise manipulate command execution on the server.

This detection looks for common command separators (semicolons, ampersands), shell operators (pipes, redirection symbols), command substitution syntax (backticks, $(), ${}), and their URL-encoded variants. These patterns may indicate attempts to inject additional commands beyond what an application intends to execute, potentially leading to unauthorized system access or data exposure.

**References**:
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Portswigger OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [MITRE ATT&CK: Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/) 