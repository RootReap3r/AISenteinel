# Security Policy

## Scope

This policy covers the AI Sentinel codebase:

- `collect.ps1` — PowerShell data collection script
- `sentinel_dashboard.html` — AI-powered analysis dashboard

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private [Security Advisories](../../security/advisories/new) feature to report
vulnerabilities confidentially. This prevents public disclosure before a fix is available.

Include the following in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact (what an attacker could do)
- Affected file(s) and approximate line numbers if known
- Suggested fix if you have one

## What to Report

Things worth reporting:

- API key leakage or exposure via the dashboard
- Malicious JSON payload that causes unintended behavior in the dashboard (XSS, etc.)
- `collect.ps1` behavior that writes, modifies, or deletes files beyond the output JSON
- Logic that could be abused to exfiltrate collected host data to a third party
- Dependency or supply chain issues if dependencies are added in the future

Things outside scope:

- "The tool collects sensitive data" — this is intentional and documented
- Issues requiring physical access to the machine
- Social engineering

## Response

I aim to acknowledge reports within 72 hours and provide a fix or mitigation timeline
within 7 days for confirmed issues.

## Disclosure

Please allow reasonable time for a fix before public disclosure. Coordinated disclosure
is appreciated and will be credited in the release notes unless you prefer to remain anonymous.
