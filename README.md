# WebGuard — Application Security Assessment Toolkit

WebGuard is a Python-based security assessment toolkit that reviews HTTP security headers, basic cookie security attributes, and HTTPS usage. It produces structured JSON reports and complements manual web application testing performed with Burp Suite.

## Features

- HTTP security-header review
- HTTPS usage check
- Basic cookie attribute review
- Structured findings with IDs, severity, evidence, and remediation
- JSON report generation
- Manual vulnerability report template for authorized lab assessments

## Technology Stack

- Python 3.10+
- Requests
- Git and GitHub
- Burp Suite Community Edition
- PortSwigger Web Security Academy

## Project Structure

```text
webguard-appsec-assessment/
├── scripts/
│   └── webguard.py
├── findings/
│   ├── FINDING_TEMPLATE.md
│   └── WG-MANUAL-001-access-control.md
├── evidence/
│   └── WG-MANUAL-001/
├── docs/
├── reports/
├── .gitignore
└── README.md
```

## Installation

Clone the repository, then enter the project directory:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd webguard-appsec-assessment
python -m venv .venv
```

Activate the environment in Git Bash on Windows:

```bash
source .venv/Scripts/activate
```

Install the dependency:

```bash
python -m pip install -r requirements.txt
```

## Usage

Run a basic assessment against a system you own or are authorized to assess:

```bash
python scripts/webguard.py https://example.com
```

Save the report to a specific file:

```bash
python scripts/webguard.py https://example.com --output reports/example-assessment-v1.1.json
```

The report contains the target URL, HTTP response status, security checks, findings, severity labels, and remediation recommendations.

## Manual Assessment

WebGuard's manual assessment workflow uses Burp Suite and authorized PortSwigger Web Security Academy labs.

Each documented finding should include:
- Summary and affected endpoint
- Reproduction steps
- Sanitized evidence
- Impact and root cause
- Recommended remediation
- Retest result

## Security and Scope

Only assess systems you own or have explicit authorization to test. The automated checker makes one GET request and does not follow redirects. Avoid including secrets, credentials, personal data, or session tokens in reports.

## Limitations

- Missing headers do not automatically prove exploitable vulnerabilities.
- Severity values are preliminary review priorities and need contextual validation.
- Cookie attribute checks are heuristic.
- This is not a comprehensive vulnerability scanner.
- Manual lab findings are separate from automated checker results.

## Future Improvements

- HTML report export
- Unit tests
- More robust URL and redirect handling
- Configurable checks and report formats
- Continuous integration testing

## Disclaimer

WebGuard is an educational portfolio project intended for authorized security assessment and defensive learning.
