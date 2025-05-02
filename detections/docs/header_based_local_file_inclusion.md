# Header Based Local File Inclusion

## Description

This detection identifies local file inclusion attempts that use HTTP headers like User-Agent, Referer, or Cookie to inject file paths. Attackers may use HTTP headers to exploit LFI vulnerabilities when direct URL parameters are properly protected but header values are not.

## Remediation

1. Validate and sanitize all input, including HTTP headers, before using it in file operations
2. Implement proper access controls and white-listing for file access
3. Configure your web application firewall (WAF) to inspect and block suspicious patterns in HTTP headers
4. Use security libraries that automatically validate file paths
5. Avoid using user-controllable input in file system operations

## Additional Information

- [OWASP Testing for Local File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [MITRE ATT&CK: T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html) 