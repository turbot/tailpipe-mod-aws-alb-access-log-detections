## Overview

Detect attempts to use directory traversal (path traversal) techniques to access files outside the intended directory. Directory traversal attacks exploit insufficient validation of user-supplied input and allow attackers to navigate beyond the web root or application directories to access sensitive files on the server's file system.

This detection identifies common path traversal patterns, including the use of "../" sequences, backslashes, and various URL-encoded variants of these characters that bypass simple filters. It also looks for Unicode/UTF-8 encoded traversal attempts, null byte injection techniques, and other exotic encoding methods used to evade security controls.

**References**:
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Portswigger Directory Traversal](https://portswigger.net/web-security/file-path-traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 