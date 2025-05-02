## Overview

Detect attempts to access common sensitive system files through Local File Inclusion (LFI) vulnerabilities. This detection identifies requests that specifically target well-known configuration files, system files, and logs that attackers commonly seek to read when exploiting LFI vulnerabilities in web applications.

This detection identifies attempts to access sensitive Unix files (/etc/passwd, /etc/shadow), Windows system files (win.ini, boot.ini), application configuration files (wp-config.php, .htaccess), and log files that may contain sensitive information. These access attempts may indicate reconnaissance activity or active exploitation of file inclusion vulnerabilities.

**References**:
- [OWASP File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK: Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/) 