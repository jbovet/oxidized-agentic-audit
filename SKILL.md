---
name: auditing-skills
description: Scans AI agent skill directories for dangerous bash patterns, prompt injection, supply chain risks, and SKILL.md structure violations. Use when reviewing, validating, or security-auditing a skill before deployment — or when asked to check a skill for security issues, prompt injection, hardcoded secrets, or compliance with Anthropic's authoring guidelines.
allowed-tools:
  - Bash(oxidized-agentic-audit)
  - Read
  - Glob
sample-prompts:
  - "audit this skill for security issues"
  - "check this skill for prompt injection"
  - "scan my skill directory before deployment"
  - "run a security audit on ./my-skill"
  - "check for hardcoded secrets in this skill"
  - "validate my SKILL.md structure"
  - "audit all skills in this directory"
metadata:
  author: jbovet
  version: 0.5.0
  license: MIT
  tags:
    - security
    - auditing
    - prompt-injection
    - static-analysis
    - supply-chain
---

# Security Auditing for Agent Skills

Run `oxidized-agentic-audit scan <path>` to scan a skill directory. The tool checks shell scripts, SKILL.md frontmatter, prompt injection vectors, and package install patterns.

## Quick start

```bash
# Single skill
oxidized-agentic-audit scan ./path/to/skill

# All skills in a collection directory
oxidized-agentic-audit scan-all ./path/to/skills/
```

## Output formats

```bash
# Human-readable terminal output (default)
oxidized-agentic-audit scan ./skill

# Machine-readable JSON
oxidized-agentic-audit scan ./skill --format json

# SARIF 2.1.0 for GitHub Code Scanning
oxidized-agentic-audit scan ./skill --format sarif --output report.sarif
```

## Strict mode

Treat warnings as errors (exit code 1 on any warning):

```bash
oxidized-agentic-audit scan ./skill --strict
```

## Score threshold (CI gate)

Fail if the security score falls below a minimum (0–100):

```bash
oxidized-agentic-audit scan ./skill --strict --min-score 80
oxidized-agentic-audit scan-all ./skills/ --strict --min-score 80
```

## Custom configuration

```bash
oxidized-agentic-audit scan ./skill --config ./oxidized-agentic-audit.toml
```

## Utility commands

```bash
# Check which external tools are available (shellcheck, gitleaks, semgrep)
oxidized-agentic-audit check-tools

# List all built-in rules with severity and description
oxidized-agentic-audit list-rules

# Explain a specific rule with remediation guidance
oxidized-agentic-audit explain bash/CAT-A1
```

## Interpreting results

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Audit passed |
| 1 | Audit failed (errors found, or warnings in strict mode) |
| 2 | Runtime error (bad config, missing path) |

Severity levels:

| Level | Meaning |
|-------|---------|
| Error | Must fix before deployment |
| Warning | Should fix, becomes error in strict mode |
| Info | Informational, no action required |

## Pre-deployment audit workflow

Copy this checklist and check off each step:

```
Audit progress:
- [ ] Step 1: Check external tools are available
- [ ] Step 2: Run full audit in strict mode
- [ ] Step 3: Interpret results — exit code 0 required to pass
- [ ] Step 4: Fix each finding (use `explain` for remediation guidance)
- [ ] Step 5: Re-audit to confirm clean
```

**Step 1: Check tools**
```bash
oxidized-agentic-audit check-tools
```

**Step 2: Full strict audit**
```bash
oxidized-agentic-audit scan ./skill --strict
```

**Step 3: Interpret** — Exit code 0 = ready to deploy. Any other exit code: proceed to Step 4.

**Step 4: Fix findings**

For each finding, get remediation guidance:
```bash
oxidized-agentic-audit explain <rule-id>   # e.g. oxidized-agentic-audit explain bash/CAT-A1
```

**Step 5: Re-audit**

Repeat Step 2 until exit code is 0.

## Remediation loop

When findings are reported:

1. For each **Error**: run `oxidized-agentic-audit explain <rule-id>` to get remediation guidance, then fix the issue
2. For each **Warning**: evaluate — fix before deployment, or suppress with a ticket if intentional
3. Re-run the audit after each batch of fixes
4. Only proceed when exit code is 0

**Suppressing intentional findings** (requires justification):
```bash
# Trailing inline comment on any shell line:
some-command  # scan:ignore (or # audit:ignore)
 
# Or use .oxidized-agentic-audit-ignore for file/line-scoped suppression with ticket tracking
```

## Sample output

**Passing audit:**
```
✓ bash_patterns   0 findings
✓ prompt          0 findings
✓ frontmatter     0 findings
✓ package_install 0 findings
Audit passed. Exit code: 0
```

**Failing audit (errors found):**
```
✗ prompt          1 finding
  [ERROR] prompt/override-ignore — instruction override detected — SKILL.md:3
✗ bash_patterns   1 finding
  [ERROR] bash/CAT-A1 — Pipe to shell (RCE) — scripts/install.sh:12
Audit failed. Exit code: 1
```

Fix each Error, then re-run. Warnings do not block unless `--strict` is active.

## Scanner coverage

Core scanners (no external tools required):

- **bash_patterns** — 19 regex rules for RCE, credential exfiltration, destructive ops, reverse shells, privilege escalation
- **typescript** — same dangerous-pattern rules applied to TypeScript / JavaScript files
- **prompt** — 19 patterns for instruction override, role manipulation, jailbreak attempts, data exfiltration
- **frontmatter** — 15 rules for SKILL.md structure, name format, description quality, allowed-tools safety
- **package_install** — package manager calls without pinned registry, unpinned versions

External tool wrappers (auto-skipped when not installed):

- **shellcheck** — shell script linting
- **secrets** — hardcoded secrets via gitleaks
- **semgrep** — static analysis rules

## Going deeper

**Full rule reference with remediation guidance**: See [RULES.md](RULES.md)
**Per-category triage guide**: See [TRIAGE.md](TRIAGE.md)
