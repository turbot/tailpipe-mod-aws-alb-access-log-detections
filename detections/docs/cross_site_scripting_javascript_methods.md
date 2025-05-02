# Cross-Site Scripting JavaScript Methods

## Description

This detection identifies attempts to use JavaScript methods and properties that can be exploited to execute malicious code. Attackers may use DOM manipulation functions, execution methods, storage manipulation, or AJAX calls to perform malicious actions in the context of the victim's browser.

## Remediation

1. Implement strong Content Security Policy (CSP) that restricts JavaScript execution
2. Use client-side security frameworks that provide XSS protection
3. Configure your web application firewall (WAF) to block requests containing suspicious JavaScript methods
4. Implement proper input validation and output encoding for user-supplied content
5. Consider using security-focused JavaScript frameworks that automatically sanitize content

## Additional Information

- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) 