# Contributing to oxidized-agentic-audit

Thank you for your interest in contributing! This document covers how to report bugs, propose features, and submit pull requests.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Development Setup](#development-setup)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Commit Style](#commit-style)
- [Adding or Modifying Rules](#adding-or-modifying-rules)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## Reporting Bugs

Before opening an issue, check if it already exists. When filing a bug:

1. Use the **Bug Report** issue template
2. Include the output of `oxidized-agentic-audit check-tools`
3. Include the command you ran and the full output
4. Mention your OS and `oxidized-agentic-audit --version`

For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do **not** open a public issue.

## Suggesting Features

Open a **Feature Request** issue. Describe:

- The problem you're trying to solve
- The proposed solution
- Alternatives you considered

## Development Setup

Requires Rust (stable) and [`just`](https://github.com/casey/just).

```bash
git clone https://github.com/jbovet/oxidized-agentic-audit
cd oxidized-agentic-audit

# Install the pre-commit hook
just install-hooks

# Run the full check suite
just ci
```

### Common tasks

```bash
just          # fmt → lint → test (default)
just fmt      # auto-format
just lint     # clippy -D warnings
just test     # cargo test
just ci       # fmt-check + lint + test (mirrors CI)
just scan     # run the tool against its own test fixtures
```

### External tools (optional)

Some scanners wrap external binaries. Install them for full local coverage:

```bash
brew install shellcheck gitleaks   # macOS
pip install semgrep
```

Run `just check-tools` to see which are available.

## Repository Secrets (maintainers)

The release workflow requires one repository secret beyond the automatically
provided `GITHUB_TOKEN`:

| Secret | Required for | How to create |
|--------|-------------|---------------|
| `PACKAGES_PAT` | Making newly-pushed GHCR images public via the GitHub API | Create a classic Personal Access Token with `write:packages` scope at **Settings → Developer settings → Personal access tokens**, then add it to the repo at **Settings → Secrets and variables → Actions**. |

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b fix/my-bug-fix
   ```
2. Make your changes, keeping commits focused and atomic
3. Add or update tests for any changed behaviour
4. Run `just ci` — it must pass cleanly
5. Update `CHANGELOG.md` under `[Unreleased]`
6. Open a PR against `main` and fill out the PR template

PRs that fail CI or break existing tests will not be merged.

## Commit Style

Use conventional commit prefixes:

| Prefix | When to use |
|--------|-------------|
| `feat:` | New rule, scanner, or user-facing feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `test:` | Test additions or fixes |
| `refactor:` | Code change that is not a fix or feature |
| `chore:` | Build, CI, dependency updates |

Example: `feat: add CAT-I1 rule for curl pipe to bash`

## Adding or Modifying Rules

Rules live in `src/scanners/`. Each scanner has its own file with inline rule definitions.

When adding a rule:

1. Assign the next available rule ID in the relevant category
2. Add a unit test in `tests/` covering both a match and a non-match case
3. Add the rule to the table in `README.md`
4. Add an entry to `CHANGELOG.md`

When modifying a regex, run the full test suite — existing tests act as regression guards.
