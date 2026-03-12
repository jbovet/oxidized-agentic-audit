# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **CLI commands renamed** — `audit` is now `scan` and `audit-all` is now `scan-all`. Internal types and suppression markers (`# audit:ignore`) remain unchanged.

## [0.4.0] - 2026-03-09

### Added
- **Agent auditing** — new `audit --type agent` command scans `AGENT.md` files via the new `agent_frontmatter` scanner, detecting bare `Bash` tool usage, unconstrained MCP servers, missing required fields, and prompt-injection patterns in system prompts.
- **`audit-all --type agent`** — collection-level audit over directories of agents, with the same summary table and `--min-score` gate as skill collection audits.
- **`agent/bare-tool` rule** — warns when `tools:` lists `Bash` without a command scope (e.g. `Bash(find,ls)`), granting unrestricted shell access.
- **`agent/unconstrained-mcp-server` rule** — warns when an MCP server entry has no tool allowlist.
- **`skip-download` input for the GitHub Action** — set `skip-download: 'true'` to use a binary already present in `PATH`, bypassing the release-download flow. Intended for CI jobs that build the binary locally.

### Changed
- **Project renamed** from `oxidized-skills` to `oxidized-agentic-audit` across all source files, documentation, CI workflows, Docker images, and configuration. The binary, crate, and GitHub Action are all now `oxidized-agentic-audit`. Suppression files are renamed from `.oxidized-skills-ignore` to `.oxidized-agentic-audit-ignore`.
- **`action-test` CI job** now builds the binary from source and passes `skip-download: 'true'` to the local action, eliminating the dependency on a published GitHub release during CI runs.

## [0.3.1] - 2026-03-06

### Security

- **`bash/CAT-A1` — pipe-to-shell** now detects absolute shell paths (`| /bin/bash`, `| /usr/bin/env bash`) and `dash` in addition to bare shell names, closing bypass via absolute paths and environment launchers.
- **`bash/CAT-B1/B2/B3` — credential path detection** extended to hard-coded `/root/` and `/home/<user>/` paths; previously only `$HOME`, `${HOME}`, and `~` prefixes were matched, missing common container and multi-user scenarios.
- **`bash/CAT-B4` — env-var exfiltration** now also detects `--data`, `--data-binary`, `--data-urlencode` (curl) and `--post-data` (wget), closing bypasses that used long-form flags instead of `-d`.
- **`bash/CAT-D1` — netcat reverse shell** now detects `ncat` in addition to `nc`, and accepts `--exec` as well as `-e`, closing a gap on systems where `ncat` replaces `nc` (e.g., RHEL/CentOS).
- **`bash/CAT-D2` — bash `/dev/tcp` reverse shell** pattern broadened to match the stdout-only redirect form (`bash -i >/dev/tcp/...`) and the `exec`-file-descriptor forms (`exec 3<>/dev/tcp/...`), which were not caught by the previous single-form regex.
- **`bash/CAT-E2` — SUID bit** now matches `chmod u+s`, `chmod a+s`, `chmod ug+s` (symbolic) and numeric modes like `chmod 4755`, `chmod 6755` (SUID+SGID). Previously only `chmod +s` was detected.
- **`prompt/inject-delimiter` (P17)** extended with Llama 3 special tokens (`<|begin_of_text|>`, `<|start_header_id|>`, `<|end_header_id|>`, `<|eot_id|>`, `<|end_of_text|>`); previously only ChatML (OpenAI) and Llama 2 `[INST]` delimiters were covered.
- **DoS via oversized files** — all built-in scanners (`bash_patterns`, `typescript`, `prompt`, `package_install`, `frontmatter`) now use a shared `read_file_limited` helper that refuses to read files larger than 10 MB, emitting an `Info` finding instead of attempting to load gigabyte-scale inputs into memory.
- **`typescript` scanner config key** — the `[scanners]` TOML key is now `typescript` (matching the scanner name used in reports), with a `typescript_patterns` alias for backward compatibility. Previously, `typescript = false` in the config was silently ignored because the struct field was mismatched.
- **`read_file_limited` — special-file DoS hardened**: the helper now calls `std::fs::metadata` (stat) to verify `FileType::is_file()` *before* calling `File::open`, preventing the thread from blocking on FIFOs or sockets. Character devices (e.g. `/dev/zero`) and named pipes that previously reported `size == 0` and bypassed the 10 MB guard are now rejected immediately. `metadata()` errors are propagated explicitly instead of being silently swallowed via `unwrap_or(0)`.
- **`read_file_limited` — TOCTOU-free size guard**: the file is opened once, then `file.metadata()` (i.e. `fstat(fd)`) is used for the size pre-check — the size limit now applies to the exact inode that was opened, not a path that could be swapped by a concurrent symlink rename between the stat and the read.
- **`read_file_limited` — hard read cap**: `Read::take(MAX_FILE_SIZE_BYTES + 1)` caps the actual kernel copy independently of the `fstat` result, providing defence-in-depth for files that grow between the size check and the read (append-heavy logs, `/proc` pseudo-files).
- **`bash/CAT-D2` — false-positive eliminated**: `>?&?` changed to `>&?`, making the `>` redirection character mandatory. `bash -i /dev/tcp/host/port` (passing `/dev/tcp` as a plain argument, not a redirect) no longer matches.

## [0.3.0] - 2026-03-04

### Added
- **TypeScript/JavaScript security scanner** — new built-in `typescript` scanner (no external tools required) detects risky patterns in `*.ts`, `*.tsx`, `*.mts`, `*.js`, `*.mjs` files across five categories: arbitrary code execution (`eval()`, `new Function()`), shell execution via `child_process` (`execSync`, `spawnSync`, `exec`, `spawn`, `execFile`), credential access (SSH keys, AWS, kubeconfig paths), reverse shells/backdoors (raw Node.js `net` socket connections), and unallowlisted outbound network calls (`fetch`/`axios`/`got`). Supports inline `// audit:ignore` suppression and domain allowlist for outbound rules.
- **`pkg/F1-yarn` rule** — flags `yarn add`/`yarn install` without an explicit `--registry` flag.
- **`pkg/F1-pnpm` rule** — flags `pnpm add`/`pnpm install` without an explicit `--registry` flag.
- **`frontmatter/name-dir-mismatch` rule** — reports when the `name` field in `SKILL.md` does not match the skill's parent directory name, catching packaging mistakes before publication.
- **Suppression path validation** — `.oxidized-agentic-audit-ignore` entries are now validated; paths that do not exist inside the skill directory emit a warning instead of silently being ignored.
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
- **GitHub Action** (`jbovet/oxidized-agentic-audit`) — composite action that auto-downloads the correct binary for the runner platform, auto-detects single-skill vs collection mode, generates a SARIF report, and uploads results to GitHub Code Scanning.
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
- **Suppression system** — inline `# audit:ignore` trailing comments and `.oxidized-agentic-audit-ignore` file with ticket tracking
- **Configurable allowlists** — registry allowlist for `pkg/F3-registry`; domain allowlist for `bash/CAT-H1`
- **`list-rules` command** — lists all built-in rules with severity and description
- **`explain` command** — shows details and remediation guidance for a specific rule
- **`check-tools` command** — reports which external tools are available on PATH
- **Parallel scanning** — concurrent scanner execution via `rayon`
- **Docker images** — slim (~8 MB, scratch base) and full (~245 MB, includes shellcheck + gitleaks + semgrep) variants published to GHCR
- **CI/CD** — GitHub Actions workflows for CI (test + lint + fmt) and release (binaries + Docker images)

[Unreleased]: https://github.com/jbovet/oxidized-agentic-audit/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/jbovet/oxidized-agentic-audit/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/jbovet/oxidized-agentic-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jbovet/oxidized-agentic-audit/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jbovet/oxidized-agentic-audit/releases/tag/v0.1.1
[0.1.0]: https://github.com/jbovet/oxidized-agentic-audit/releases/tag/v0.1.0
