---
name: pii-skill
description: Fixture exercising every PII rule. Use only in tests.
---

# PII fixture

Real-looking email (P1): contact alice.smith@acme-industries.com for access
Test email (no finding): write to user@example.com when prompted
Vendor footer (no finding): noreply@anthropic.com

US SSN (P2): patient 456-78-9012 referred to clinic
Placeholder SSN (no finding): typical SSN looks like 123-45-6789

Visa test card (P3): payment routed via 4242 4242 4242 4242
Random 16-digit number (no finding): batch id 1234 5678 9012 3456

Private IPv4 (P4): connect to 10.0.0.5 over the VPN
Public IPv4 (no finding): use 8.8.8.8 for DNS

Internal hostname (P5): deploys land on api.prod.corp
Public host (no finding): see https://github.com/foo/bar

Suppressed line: bob@realcompany.com # scan:ignore
