# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅        |
| 0.2.x   | ❌        |
| 0.1.x   | ❌        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please use [GitHub's private Security Advisory form](https://github.com/jbovet/oxidized-skills/security/advisories/new) to report vulnerabilities confidentially. This ensures the report is only visible to the maintainer until a fix is ready.

Include in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Disclosure Policy

Once a fix is available:

1. A patch release is published
2. A GitHub Security Advisory is created
3. The reporter is credited (unless they prefer to remain anonymous)

## Scope

This policy covers the `oxidized-skills` binary and its built-in scanners. Third-party tools (`shellcheck`, `gitleaks`, `semgrep`) have their own security policies.

## Out of Scope

- Vulnerabilities in external tools wrapped by oxidized-skills
- Issues in skills being audited (those are findings, not vulnerabilities in this tool)
- Denial of service via extremely large input files
