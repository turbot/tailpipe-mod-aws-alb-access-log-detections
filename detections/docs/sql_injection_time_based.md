## Overview

Detect time-based SQL injection attacks where attackers attempt to extract information from databases by measuring the time it takes for queries to execute. This technique is particularly useful in blind SQL injection scenarios where attackers cannot directly see the results of their injections, but can observe whether a query takes longer to execute depending on the injected condition.

This detection identifies patterns commonly used in time-based SQL injection, including functions like SLEEP(), BENCHMARK(), PG_SLEEP(), and WAITFOR DELAY statements across different database types that introduce measurable delays when conditions are true.

**References**:
- [OWASP Time-based Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [Portswigger Time-based Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind/time-delays)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 