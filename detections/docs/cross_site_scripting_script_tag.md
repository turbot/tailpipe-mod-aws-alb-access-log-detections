# Cross-Site Scripting Script Tag

## Description

This detection looks for script tag injections in HTTP requests and user-agent headers, which are commonly used in XSS attacks. Attackers inject script tags to execute arbitrary JavaScript code in the victim's browser when the page is rendered.

## Remediation

1. Implement proper input validation and output encoding, particularly for HTML contexts
2. Configure your web application firewall (WAF) to block requests containing script tags
3. Use Content Security Policy (CSP) headers to restrict script execution
4. Sanitize user inputs before rendering them in HTML contexts
5. Consider implementing XSS frameworks or libraries that automatically handle encoding

## Additional Information

- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) 