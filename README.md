# Security Headers Checker

A command-line tool to assess the security headers of web servers. This tool helps security professionals and developers identify missing or misconfigured HTTP security headers, which are critical for protecting web applications against various attacks.

![Security Headers Checker](https://via.placeholder.com/800x200/0073CF/FFFFFF?text=Security+Headers+Checker)

## Overview

Security Headers Checker evaluates a website's HTTP response headers against security best practices. It provides color-coded terminal output showing:

- 🔴 Missing security headers
- 🟢 Properly configured security headers
- 🟡 Present but insecurely configured headers

The tool checks for the following important security headers:

- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection
- Cache-Control

## Installation

### Prerequisites

- Python 3.6 or higher

### Setup

1. Clone the repository or download the script:
   ```bash
   git clone https://github.com/yourusername/security-headers-checker.git
   cd security-headers-checker
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

Check a website's security headers:

```bash
python checkheaders.py -u https://example.com
```

### Command-line Arguments

| Argument | Short | Long | Description |
|----------|-------|------|-------------|
| URL | `-u` | `--url` | URL to check (required) |
| JSON Output | `-j` | `--json` | Save results to JSON file |
| Insecure Mode | `-k` | `--insecure` | Allow insecure SSL connections (bypass certificate verification) |

### Examples

Check a website:
```bash
python checkheaders.py -u https://example.com
```

Check a website with a self-signed or untrusted SSL certificate:
```bash
python checkheaders.py -u https://example.com -k
```

Check a website and save results to JSON:
```bash
python checkheaders.py -u https://example.com -j results.json
```

## Output Example

The tool provides detailed, color-coded output in the terminal:

```
Checking security headers for: https://example.com

Raw Headers:
Date: Tue, 15 Apr 2025 14:51:17 GMT
Content-Type: text/html
Content-Length: 70
Connection: keep-alive
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff

Security Headers Assessment:
[✓] Strict-Transport-Security
    Value: max-age=31536000; includeSubDomains
    Enforces HTTPS connections, protecting against protocol downgrade attacks
[X] Content-Security-Policy
    Missing header. Controls which resources the browser is allowed to load, mitigating XSS attacks
[✓] X-Frame-Options
    Value: DENY
    Prevents clickjacking by controlling whether a page can be embedded in frames
[✓] X-Content-Type-Options
    Value: nosniff
    Prevents MIME-sniffing, ensuring the browser honors the declared content type
[X] Referrer-Policy
    Missing header. Controls how much referrer information is included with requests
[X] Permissions-Policy
    Missing header. Controls which browser features and APIs can be used on the page
[X] X-XSS-Protection
    Missing header. Legacy header to enable browser's XSS filtering (modern browsers use CSP instead)
[!!] Cache-Control
    Value: no-cache
    Insecurely configured. Controls browser caching, can prevent sensitive data from being cached
```

## JSON Output

When using the `-j` option, the tool generates a JSON file with the following structure:

```json
{
  "url": "https://example.com",
  "final_url": "https://example.com",
  "status_code": 200,
  "headers": {
    "Date": "Tue, 15 Apr 2025 14:51:17 GMT",
    "Content-Type": "text/html",
    "Content-Length": "70",
    "Connection": "keep-alive",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff"
  },
  "assessment": {
    "Strict-Transport-Security": {
      "status": "secure",
      "value": "max-age=31536000; includeSubDomains",
      "description": "Enforces HTTPS connections, protecting against protocol downgrade attacks"
    },
    "Content-Security-Policy": {
      "status": "missing",
      "value": null,
      "description": "Controls which resources the browser is allowed to load, mitigating XSS attacks"
    },
    // Additional headers...
  }
}
```

## Security Headers Information

| Header | Purpose | Secure Configuration |
|--------|---------|---------------------|
| Strict-Transport-Security | Enforces HTTPS connections | max-age of at least 6 months (15768000 seconds) |
| Content-Security-Policy | Controls resource loading | Should include default-src or script-src directives |
| X-Frame-Options | Prevents clickjacking | DENY or SAMEORIGIN |
| X-Content-Type-Options | Prevents MIME-sniffing | nosniff |
| Referrer-Policy | Controls referrer information | no-referrer, strict-origin, etc. |
| Permissions-Policy | Controls browser features | Any non-empty value |
| X-XSS-Protection | Legacy XSS protection | 1 or 1; mode=block |
| Cache-Control | Controls browser caching | no-store or private |

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Inspired by [SecurityHeaders.com](https://securityheaders.com)
- Built for security professionals and penetration testers

---

For more information on security headers, visit [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).