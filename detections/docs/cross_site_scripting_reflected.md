## Overview

Detect reflected cross-site scripting (XSS) attack attempts where malicious scripts are embedded in URLs and executed when victims click on specially crafted links. This attack vector is commonly used in phishing campaigns where attackers send links that appear legitimate but contain JavaScript code that executes in the victim's browser context when the application reflects the input back to the user without proper sanitization.

This detection identifies common patterns used in reflected XSS attacks, including script tags, event handlers, JavaScript protocol usage, data URI schemes, and various HTML tags frequently abused to execute malicious JavaScript. It also accounts for URL-encoded variants used to bypass security filters.

**References**:
- [OWASP Reflected XSS](https://owasp.org/www-community/attacks/xss/)
- [Portswigger Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE ATT&CK: Drive-by Compromise (T1189)](https://attack.mitre.org/techniques/T1189/) 