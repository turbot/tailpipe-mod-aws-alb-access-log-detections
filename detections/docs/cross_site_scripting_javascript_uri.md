# Cross-Site Scripting JavaScript URI

## Description

This detection identifies attempts to use JavaScript URI schemes in HTTP requests and user-agent headers. Attackers often use `javascript:` URIs in attributes like `href` or `src` to execute JavaScript code when a user interacts with the element.

## Remediation

1. Implement proper URL validation for all user-supplied URLs
2. Use allowlisting for permitted URI schemes (http, https, etc.)
3. Configure your web application firewall (WAF) to block javascript: and other dangerous URI schemes
4. Implement Content Security Policy (CSP) to restrict what can be loaded and executed
5. Consider using URL sanitization libraries that automatically remove dangerous URI schemes

## Additional Information

- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) 