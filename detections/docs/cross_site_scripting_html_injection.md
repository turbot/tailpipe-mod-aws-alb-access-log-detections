# Cross-Site Scripting HTML Injection

## Description

This detection identifies attempts to inject HTML tags in HTTP requests and user-agent headers. Attackers can use HTML injection to manipulate page structure or load malicious content through tags like img, iframe, svg, and others that can execute JavaScript when rendered.

## Remediation

1. Implement HTML sanitization for all user inputs that appear in page content
2. Use allowlisting for permitted HTML tags when accepting HTML input
3. Configure your web application firewall (WAF) to block dangerous HTML tags
4. Implement Content Security Policy (CSP) to restrict what can be loaded and executed
5. Consider using HTML sanitization libraries that automatically remove dangerous tags

## Additional Information

- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) 