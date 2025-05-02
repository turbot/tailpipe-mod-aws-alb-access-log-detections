## Overview

Detect blind SQL injection attacks where attackers attempt to extract information from databases using boolean conditions or time delays when the application doesn't display database error messages. Blind SQL injection requires different techniques than traditional SQL injection since attackers cannot directly see the results of their injections.

This detection identifies patterns commonly used in blind SQL injection, including conditional statements (AND 1=1, AND 1=2), substring functions, ASCII value comparisons, and case statements that help attackers infer information about the database by observing whether the application behaves differently based on injected conditions.

**References**:
- [OWASP Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [Portswigger SQL Injection Blind Attacks](https://portswigger.net/web-security/sql-injection/blind)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 