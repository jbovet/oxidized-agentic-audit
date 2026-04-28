---
name: url-skill
description: Fixture exercising every malicious-URL rule. Use only in tests.
---

# URL fixture

Allowlisted host (no finding expected): https://github.com/foo/bar

Shortener (U1): https://bit.ly/abc123
Paste site (U2): https://pastebin.com/raw/deadbeef
IP literal (U3): http://10.0.0.5/install.sh
Suspicious TLD (U4): https://promo.xyz/landing
Insecure scheme (U5): http://example.org/page

Suppressed shortener: https://t.co/xyz # scan:ignore
