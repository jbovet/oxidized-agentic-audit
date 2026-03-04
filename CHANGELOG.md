# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-03-04

### Added
- **TypeScript/JavaScript security scanner** — new built-in `typescript` scanner (no external tools required) detects risky patterns in `*.ts`, `*.tsx`, `*.mts`, `*.js`, `*.mjs` files across five categories: arbitrary code execution (`eval()`, `new Function()`), shell execution via `child_process` (`execSync`, `spawnSync`, `exec`, `spawn`, `execFile`), credential access (SSH keys, AWS, kubeconfig paths), reverse shells/backdoors (raw Node.js `net` socket connections), and unallowlisted outbound network calls (`fetch`/`axios`/`got`). Supports inline `// audit:ignore` suppression and domain allowlist for outbound rules.
- **`pkg/F1-yarn` rule** — flags `yarn add`/`yarn install` without an explicit `--registry` flag.
- **`pkg/F1-pnpm` rule** — flags `pnpm add`/`pnpm install` without an explicit `--registry` flag.
- **`frontmatter/name-dir-mismatch` rule** — reports when the `name` field in `SKILL.md` does not match the skill's parent directory name, catching packaging mistakes before publication.
- **Suppression path validation** — `.oxidized-skills-ignore` entries are now validated; paths that do not exist inside the skill directory emit a warning instead of silently being ignored.
- **Semgrep config validation** — the semgrep scanner now validates the resolved config path before invoking the tool, providing an actionable error when the config file is missing.
- **Comprehensive regression test suite** — new test modules for frontmatter, bash patterns, TypeScript, and package-install scanners covering edge cases and suppress logic.

### Changed
- Bash pattern scanner refactored for cleaner rule definitions and improved parse-error resilience.
- Prompt injection scanner logic streamlined; false-positive rate reduced on boilerplate files.
- Scanner module restructured with shared `collect_files` and `is_suppressed_inline` helpers, reducing duplication across all built-in scanners.
- `Finding` and `ScanResult` types have improved `Display` and `Debug` implementations.

### Fixed
- Linter warnings (`clippy`) resolved across scanner modules.
- Semgrep scanner no longer emits spurious errors when the config path contains whitespace.

## [0.2.0] - 2026-03-02

### Added
- **Security score & letter grade** — every `audit` and `audit-all` report now includes a composite 0–100 security score and an A–F letter grade, computed from finding severity and count; visible in all output formats (pretty, JSON, SARIF).
- **Per-scanner score & grade** — each `ScanResult` carries its own `scanner_score` and `scanner_grade` fields, computed on raw (pre-suppression) findings so suppressed rules don't artificially inflate the score.
- **`--min-score` CI gate** — `audit` and `audit-all` accept `--min-score <N>` (0–100); exits with code 1 when the skill scores below the threshold, enabling score-based quality gates in CI pipelines.
- **GitHub Action** (`jbovet/oxidized-skills`) — composite action that auto-downloads the correct binary for the runner platform, auto-detects single-skill vs collection mode, generates a SARIF report, and uploads results to GitHub Code Scanning.
- **`min-score` input for the GitHub Action** — pass `min-score: 80` in the action config to fail PR checks when any audited skill scores below the threshold.

### Changed
- Collection summary table now renders `N err, N warn, N info` column labels instead of the terse `Ne Nw Ni` format.
- Collection summary rows are annotated with a red `[< N]` marker when `--min-score` is active and the skill falls below the threshold.
- Collection summary footer now appends a `N below min-score (N)` counter when one or more skills fail the score gate.

## [0.1.1] - 2026-02-27

### Added
- **Feature**: Enhanced audit output with indication of disabled/missing scanners.
- **Infrastructure**: Added `dependabot.yml` and updated CI for multi-OS testing.
- **Docs**: Added support guidelines and expanded auditing skills documentation.

### Changed
- **Optimization**: Significant performance improvements for Semgrep scanner using local rules and configuration.

### Fixed
- **Fix**: Resolved `Default` trait lints and Semgrep configuration loading errors.

### Added

- **Bash pattern scanner** — 19 regex rules across 8 categories (RCE, credential exfiltration, destructive ops, reverse shells, privilege escalation, unsafe variable expansion, outbound network)
- **Prompt injection scanner** — 19 patterns for instruction override, role manipulation, jailbreak attempts, data exfiltration, code injection, system prompt extraction, delimiter injection, fictional framing, and priority override; auto-skips benign boilerplate files
- **Frontmatter auditor** — 15 rules validating `SKILL.md` structure: missing file, reserved brand names, XML injection, name format, field length limits, vague names, body length, Windows paths, third-person description, trigger context, time-sensitive content, and unscoped `Bash` in `allowed-tools`
- **Package install auditor** — detects `npm install`, `bun add`, `pip install` without explicit registry, unpinned `@latest` versions, and unapproved registries
- **Shell script linting** — `shellcheck` wrapper, auto-skipped when tool is not installed
- **Secret scanning** — `gitleaks` wrapper, auto-skipped when tool is not installed
- **Static analysis** — `semgrep` wrapper with 30-second timeout, gracefully skips when network is blocked or tool unavailable
- **`audit-all` command** — audits every skill in a collection directory with a summary table
- **Multiple output formats** — pretty terminal, JSON, and SARIF 2.1.0 (compatible with GitHub Code Scanning)
- **Suppression system** — inline `# audit:ignore` trailing comments and `.oxidized-skills-ignore` file with ticket tracking
- **Configurable allowlists** — registry allowlist for `pkg/F3-registry`; domain allowlist for `bash/CAT-H1`
- **`list-rules` command** — lists all built-in rules with severity and description
- **`explain` command** — shows details and remediation guidance for a specific rule
- **`check-tools` command** — reports which external tools are available on PATH
- **Parallel scanning** — concurrent scanner execution via `rayon`
- **Docker images** — slim (~8 MB, scratch base) and full (~245 MB, includes shellcheck + gitleaks + semgrep) variants published to GHCR
- **CI/CD** — GitHub Actions workflows for CI (test + lint + fmt) and release (binaries + Docker images)

[Unreleased]: https://github.com/jbovet/oxidized-skills/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jbovet/oxidized-skills/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jbovet/oxidized-skills/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jbovet/oxidized-skills/releases/tag/v0.1.1
[0.1.0]: https://github.com/jbovet/oxidized-skills/releases/tag/v0.1.0
