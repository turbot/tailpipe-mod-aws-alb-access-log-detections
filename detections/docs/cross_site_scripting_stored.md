## Overview

Detect potential stored cross-site scripting (XSS) attack attempts where malicious scripts are being delivered to applications via POST or PUT requests, with the intention of having them stored in databases and later executed when other users view the affected content. Stored XSS is particularly dangerous because it affects all users who view the compromised content, not just those who click on a specific link.

This detection identifies JavaScript execution patterns in POST and PUT requests, including script tags, DOM manipulation functions, AJAX calls for data exfiltration, and common event handlers. It focuses on identifying potentially malicious code that could be stored and later executed in victim browsers when content is retrieved from the server.

**References**:
- [OWASP Stored XSS](https://owasp.org/www-community/attacks/xss/)
- [Portswigger Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE ATT&CK: Drive-by Compromise (T1189)](https://attack.mitre.org/techniques/T1189/) 