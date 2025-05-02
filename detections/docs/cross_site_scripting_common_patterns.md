# Cross-Site Scripting Common Patterns

## Description

This detection looks for common Cross-Site Scripting (XSS) attack patterns in HTTP requests and user-agent headers. XSS is a common web application vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.

## Remediation

1. Implement input validation and output encoding in your web applications
2. Use Content Security Policy (CSP) headers to restrict the sources of executable scripts
3. Configure your web application firewall (WAF) to block common XSS attack patterns
4. Consider implementing XSS mitigation in HTTP headers like X-XSS-Protection

## Additional Information

- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) 