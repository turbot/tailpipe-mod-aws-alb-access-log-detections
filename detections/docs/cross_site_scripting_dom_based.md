## Overview

Detect potential DOM-based cross-site scripting (XSS) attack attempts where client-side scripts manipulate the Document Object Model (DOM) in unsafe ways. This type of XSS occurs entirely in the browser when JavaScript code processes data from untrusted sources (like URL fragments) and writes it to the DOM using unsafe methods, without proper validation or sanitization.

This detection identifies common DOM XSS source patterns (like location.hash, location.search) and sink patterns (like innerHTML, eval()) that can lead to script execution. It also looks for fragment identifiers often used in DOM XSS and DOM manipulation patterns that might indicate attempts to execute malicious JavaScript through DOM manipulation rather than server-side reflection.

**References**:
- [OWASP DOM-based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [Portswigger DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE ATT&CK: Drive-by Compromise (T1189)](https://attack.mitre.org/techniques/T1189/) 