## Overview

Detect UNION-based SQL injection attacks that attempt to join results from another unauthorized query to the original query's results. UNION-based SQL injection is a specific technique that allows attackers to combine the results of the original query with those from an injected query, potentially revealing sensitive data.

This detection looks for requests containing the UNION keyword followed by SELECT statements, along with common evasion techniques like breaking up keywords with special characters to bypass security filters.

**References**:
- [OWASP Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [Portswigger SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 