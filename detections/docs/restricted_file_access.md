# Restricted File Access

## Description

This detection identifies attempts to access restricted application files, such as configuration files, that might reveal sensitive application data. Attackers target these files to gather credentials, API keys, and other sensitive configuration information.

## Remediation

1. Store sensitive configuration data outside the web root directory
2. Use environment variables or secure credential management systems instead of configuration files
3. Implement proper access controls and file permissions
4. Configure your web application firewall (WAF) to block access to sensitive configuration files
5. Regularly audit access logs for attempts to access restricted files

## Additional Information

- [OWASP File System Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_System_Security_Cheat_Sheet.html)
- [MITRE ATT&CK: T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html) 