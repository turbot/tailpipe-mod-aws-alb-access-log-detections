## Overview

Detect SQL injection attacks that use the User-Agent HTTP header rather than URL parameters to deliver malicious payloads. This technique is often used to bypass Web Application Firewalls (WAFs) and input filtering on URL parameters while attempting to exploit backend systems that log and process User-Agent information without proper validation.

This detection identifies SQL injection patterns in the User-Agent header, including SQL commands, comment markers, conditional statements, and database-specific reconnaissance techniques that could be used to compromise applications that fail to sanitize header values before using them in database operations.

**References**:
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [HTTP Header Injection](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 