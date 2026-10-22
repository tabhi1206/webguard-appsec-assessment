# WG-MANUAL-001 — Client-Controlled Access Control

## Finding Details

- **Category:** Broken Access Control
- **Severity:** High — provisional; validate against demonstrated impact
- **Status:** Lab finding documented
- **Testing tool:** Burp Suite
- **Environment:** Authorized PortSwigger Web Security Academy lab

## Summary

The lab tests whether administrative access is controlled by the server or by a client-controlled cookie value.

## Steps to Reproduce

1. Open the assigned lab and inspect the application's requests using Burp Suite.
2. Identify the relevant `Admin` cookie in the authorized lab.
3. In the lab request, change `Admin=false` to `Admin=true`.
4. Request the `/admin` path.
5. Record the actual server response and whether administrative functionality becomes accessible.

## Evidence

- **Evidence file:** `evidence/WG-MANUAL-001/`
- **Request:** Sanitized request showing the relevant cookie and requested path.
- **Response:** Sanitized response demonstrating the actual result.

Only claim successful privilege escalation if the lab response confirms it.

## Impact

If the server trusts a client-controlled cookie to authorize administrative operations, an attacker may be able to gain privileges without authorization.

## Root Cause

The application may rely on client-controlled state instead of enforcing administrative authorization on the server.

## Remediation

- Enforce authorization on the server for every privileged operation.
- Do not trust client-controlled cookies for roles or privileges.
- Derive permissions from trusted server-side identity and authorization data.
- Add tests confirming ordinary users cannot access administrative endpoints.

## Retest

- **Status:** Pending documentation
- **Result:** Record the observed result from the completed lab.
