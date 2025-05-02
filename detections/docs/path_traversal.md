# Path Traversal

## Description

This detection identifies directory traversal attacks using path sequences like '../' that attempt to access files outside the intended directory. Path traversal is a common vulnerability that allows attackers to access unauthorized files and directories on the server.

## Remediation

1. Validate and sanitize all file paths before using them in file operations
2. Implement proper access controls and user permission checks
3. Use a whitelist of allowed files/directories rather than trying to block malicious patterns
4. Configure your web application firewall (WAF) to block common directory traversal patterns
5. Consider using security libraries that automatically validate file paths

## Additional Information

- [OWASP Path Traversal Cheat Sheet](https://owasp.org/www-community/attacks/Path_Traversal)
- [MITRE ATT&CK: T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html) 