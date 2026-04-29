---
name: obfuscation-skill
description: Fixture exercising every obfuscation rule. Use only in tests.
---

# Obfuscation fixture

Plain prose should never trigger any rule even when it goes on for many words and many lines and never repeats.

A long base64 payload hidden in prose: VGhpc0lzU29tZUJhc2U2NEVuY29kZWREYXRhMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE0=

A long hex blob in prose: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

A high-entropy non-base64 token: aZ!Q9#7xL@2pN&8sK*4mR%6vT$3yU^1wE+0qO~5iY-jH=bG?cF/dD

Suppressed payload should be silent: VGhpc0lzU29tZUJhc2U2NEVuY29kZWREYXRhMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE0= # scan:ignore

```
# Inside a fenced code block — must be ignored:
VGhpc0lzU29tZUJhc2U2NEVuY29kZWREYXRhMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE0=
```

A URL is excluded by design: https://example.com/aZ9Q7xL2pN8sK4mR6vT3yU1wE0qO5iY8

Inline code should be ignored: `VGhpc0lzU29tZUJhc2U2NEVuY29kZWREYXRhMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE0=`
