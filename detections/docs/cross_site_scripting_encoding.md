# Cross-Site Scripting Encoding

## Description

This detection identifies attempts to use various encoding techniques to bypass XSS filters and security controls. Attackers often encode malicious payloads using HTML entities, hex encoding, Unicode/UTF-8 encoding, double encoding, mixed encoding, or Base64 encoding to evade detection.

## Remediation

1. Implement context-aware output encoding for all user-supplied content
2. Use security libraries that decode input before validation
3. Configure your web application firewall (WAF) to detect and block encoded payloads
4. Implement a strong Content Security Policy (CSP)
5. Regularly update your security tools to recognize new encoding bypass techniques

## Additional Information

- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) 