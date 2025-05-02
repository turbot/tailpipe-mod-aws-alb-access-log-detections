# Cross-Site Scripting Attribute Injection

## Description

This detection identifies attempts to inject malicious event handlers or dangerous HTML attributes in HTTP requests and user-agent headers. Attribute-based XSS occurs when attackers inject JavaScript code into HTML attributes to execute when certain events are triggered.

## Remediation

1. Implement context-aware output encoding for HTML attributes
2. Use allowlisting for permitted HTML attributes when accepting HTML input
3. Configure your web application firewall (WAF) to block common event handlers
4. Implement Content Security Policy (CSP) with strict settings
5. Consider using security libraries that automatically sanitize HTML attributes

## Additional Information

- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) 