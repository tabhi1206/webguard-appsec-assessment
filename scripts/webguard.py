
import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

VERSION = "1.1"

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "LOW",
        "purpose": "Helps browsers enforce HTTPS on future connections.",
        "remediation": (
            "For HTTPS sites, evaluate enabling HSTS with an appropriate "
            "max-age after confirming all relevant subdomains support HTTPS."
        ),
    },
    "Content-Security-Policy": {
        "severity": "LOW",
        "purpose": "Restricts permitted sources of scripts and other content.",
        "remediation": (
            "Design and test a CSP suited to the application. Start with "
            "Report-Only where appropriate before enforcing it."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "purpose": "Helps prevent MIME-type sniffing when set to nosniff.",
        "remediation": "Consider sending X-Content-Type-Options: nosniff.",
    },
    "Referrer-Policy": {
        "severity": "INFO",
        "purpose": "Controls referrer information sent by the browser.",
        "remediation": (
            "Choose a policy appropriate for the application's privacy "
            "requirements, such as strict-origin-when-cross-origin."
        ),
    },
    "Permissions-Policy": {
        "severity": "INFO",
        "purpose": "Controls access to selected browser features.",
        "remediation": (
            "Consider restricting browser features the application does "
            "not need. Configure directives for the actual use case."
        ),
    },
}


def make_finding(
    finding_id,
    title,
    severity,
    status,
    evidence,
    impact,
    remediation,
):
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "status": status,
        "evidence": evidence,
        "impact": impact,
        "remediation": remediation,
    }


def assess_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not allowed.")

    # One GET request only; redirects are deliberately not followed.
    response = requests.get(
        url,
        timeout=10,
        allow_redirects=False,
        headers={"User-Agent": f"WebGuard/{VERSION}"},
    )

    headers = response.headers
    findings = []

    if parsed.scheme != "https":
        findings.append(make_finding(
            "WG-001",
            "Target URL uses HTTP",
            "MEDIUM",
            "OBSERVED",
            f"The supplied URL uses the {parsed.scheme} scheme.",
            "Data sent over an unencrypted HTTP connection may be exposed "
            "or modified in transit.",
            "Use HTTPS and configure HTTP-to-HTTPS redirection on the server. "
            "Verify the TLS certificate and deployment before relying on it.",
        ))

    for index, (header, info) in enumerate(SECURITY_HEADERS.items(), start=2):
        value = headers.get(header)

        if value:
            findings.append(make_finding(
                f"WG-{index:03d}",
                f"{header} is present",
                "INFO",
                "OBSERVED",
                f"Response header value: {value}",
                info["purpose"],
                "Review the value and confirm it matches the application's "
                "security requirements.",
            ))
        else:
            findings.append(make_finding(
                f"WG-{index:03d}",
                f"{header} was not observed",
                info["severity"],
                "REVIEW",
                f"{header} was absent from the received response.",
                info["purpose"],
                info["remediation"],
            ))

    # Read individual Set-Cookie headers where supported.
    cookie_headers = response.raw.headers.getlist("Set-Cookie")

    if not cookie_headers:
        findings.append(make_finding(
            "WG-007",
            "No cookies set in this response",
            "INFO",
            "OBSERVED",
            "No Set-Cookie header was observed in this response.",
            "This response did not set a cookie. Other routes or responses "
            "may behave differently.",
            "If the application uses session cookies, review their flags "
            "on the responses that issue them.",
        ))
    else:
        for index, cookie in enumerate(cookie_headers, start=1):
            # Only inspect the cookie attributes, not the cookie's value.
            parts = [part.strip() for part in cookie.split(";")]
            attributes = {
                part.split("=", 1)[0].strip().lower()
                for part in parts[1:]
                if part
            }

            missing = []
            if "secure" not in attributes:
                missing.append("Secure")
            if "httponly" not in attributes:
                missing.append("HttpOnly")
            if not any(
                part.lower().startswith("samesite=")
                for part in parts[1:]
            ):
                missing.append("SameSite")

            findings.append(make_finding(
                f"WG-{7 + index:03d}",
                f"Cookie {index} attribute review",
                "LOW" if missing else "INFO",
                "REVIEW" if missing else "OBSERVED",
                (
                    "Potentially missing attributes: " + ", ".join(missing)
                    if missing
                    else "Secure, HttpOnly, and SameSite attributes observed."
                ),
                "Cookie flags help reduce certain risks, but the right "
                "configuration depends on the cookie's purpose and usage.",
                "Review each cookie individually. Use Secure for HTTPS, "
                "HttpOnly when JavaScript access is unnecessary, and an "
                "appropriate SameSite policy. Verify application behavior.",
            ))

    counts = Counter(item["severity"] for item in findings)

    return {
        "tool": "WebGuard",
        "version": VERSION,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "http_status": response.status_code,
        "redirect_location": headers.get("Location"),
        "content_type": headers.get("Content-Type"),
        "summary": {
            "total_checks": len(findings),
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "info": counts["INFO"],
            "review_required": sum(
                1 for item in findings if item["status"] == "REVIEW"
            ),
        },
        "findings": findings,
        "limitations": [
            "This is a basic HTTP configuration review, not a penetration test.",
            "Missing headers are observations, not proof of exploitable flaws.",
            "Severity is an initial review priority, not a validated risk rating.",
            "Only one GET request is made; redirects are not followed.",
            "Only the supplied URL and response are assessed.",
            "Cookie checks are heuristic and require application context.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="WebGuard: HTTP security configuration checker"
    )
    parser.add_argument(
        "url",
        help="URL of a system you own or are authorized to assess",
    )
    parser.add_argument(
        "--output",
        default="reports/webguard-report.json",
        help="Path for the JSON report",
    )
    args = parser.parse_args()

    try:
        report = assess_url(args.url)
    except (ValueError, requests.RequestException) as exc:
        print(f"WebGuard error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"\nWebGuard v{VERSION} — Assessment Results")
    print(f"Target: {report['target']}")
    print(f"HTTP status: {report['http_status']}")

    print("\nSummary:")
    for key, value in report["summary"].items():
        print(f"  {key.replace('_', ' ').title()}: {value}")

    print("\nFindings:")
    for item in report["findings"]:
        print(
            f"[{item['severity']}] {item['id']} — "
            f"{item['title']} ({item['status']})"
        )
        print(f"  Evidence: {item['evidence']}")
        print(f"  Remediation: {item['remediation']}")

    output_path = Path(args.output)

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
        print(f"\nJSON report saved to: {output_path}")
    except OSError as exc:
        print(f"Could not write report: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
