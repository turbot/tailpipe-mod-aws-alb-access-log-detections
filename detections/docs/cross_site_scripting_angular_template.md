# Cross-Site Scripting Angular Template

## Description

This detection identifies attempts to exploit AngularJS template injection vulnerabilities. Attackers can use AngularJS-specific syntax like expressions in double curly braces `{{}}` or directives like `ng-init` to execute JavaScript within Angular templates when the application renders them.

## Remediation

1. Update to the latest version of Angular, which has improved security protections
2. Use Angular's built-in security features like DomSanitizer and the [SafeValue](https://angular.io/api/platform-browser/SafeValue) interface
3. Configure your web application firewall (WAF) to block Angular-specific injection patterns
4. Implement strong Content Security Policy (CSP) headers
5. Avoid rendering user input as Angular templates without strict sanitization

## Additional Information

- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [Angular Security Guide](https://angular.io/guide/security) 