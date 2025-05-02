# Encoded Path Traversal

## Description

This detection identifies directory traversal attacks using URL encoded or otherwise obfuscated path sequences to bypass security filters. Attackers often encode path traversal sequences to evade detection by security mechanisms while still being interpreted correctly by the server.

## Remediation

1. Validate and sanitize all file paths after decoding them
2. Canonicalize paths before validation to ensure proper form
3. Implement proper access controls and user permission checks
4. Configure your web application firewall (WAF) to detect and block encoded traversal patterns
5. Consider using file access abstractions or security libraries that handle path canonicalization

## Additional Information

- [OWASP Path Traversal Cheat Sheet](https://owasp.org/www-community/attacks/Path_Traversal)
- [MITRE ATT&CK: T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html) 