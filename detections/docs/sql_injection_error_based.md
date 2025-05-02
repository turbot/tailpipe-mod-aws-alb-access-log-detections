## Overview

Detect error-based SQL injection attacks where attackers attempt to extract information by causing and exploiting database error messages. This technique relies on crafting SQL inputs that generate errors containing the data the attacker wants to retrieve when applications improperly handle and display database error messages.

This detection identifies common patterns used in error-based SQL injection, including functions like CONVERT(), CAST(), EXTRACTVALUE(), UPDATEXML(), and database-specific techniques that leverage error messages to extract data, system information, or configuration details.

**References**:
- [OWASP Error Based SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Error-based SQL Injection Techniques](https://www.exploit-db.com/docs/41397)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 