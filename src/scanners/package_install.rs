//! Package installation audit scanner.
//!
//! Detects unsafe package installation patterns in shell scripts that may
//! introduce supply-chain vulnerabilities.  This is a built-in scanner — no
//! external tool is required.
//!
//! # Rules
//!
//! | ID | Sev | What it checks |
//! |----|-----|----------------|
//! | `pkg/F1-npm` | Warning | `npm install` without explicit `--registry` |
//! | `pkg/F1-bun` | Warning | `bun add` without explicit `--registry` |
//! | `pkg/F1-pip` | Warning | `pip install` without explicit `--index-url` |
//! | `pkg/F1-yarn` | Warning | `yarn add` without explicit `--registry` |
//! | `pkg/F1-pnpm` | Warning | `pnpm add/install` without explicit `--registry` |
//! | `pkg/F2-unpinned` | Warning | `@latest` — unpinned version |
//! | `pkg/F3-registry` | Warning | Registry URL not in allowlist |
//!
//! # Scanned file types
//!
//! `*.sh`, `*.bash`, `*.zsh`
//!
//! # Suppression
//!
//! Individual lines can be suppressed with an inline `# audit:ignore` or
//! `# oxidized-skills:ignore` trailing comment. Registry URLs are also
//! checked against [`Config::allowlist`](crate::config::AllowlistConfig::registries).

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{collect_files, is_suppressed_inline, RuleInfo, Scanner};
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

// Match patterns (positive match, no lookahead needed)
static RE_NPM_INSTALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bnpm\s+(install|i|add)\b").unwrap());

static RE_BUN_ADD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bbun\s+(add|install)\b").unwrap());

static RE_PIP_INSTALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bpip3?\s+install\b").unwrap());

static RE_YARN_ADD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\byarn\s+(add|install)\b").unwrap());

static RE_PNPM_ADD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bpnpm\s+(add|install|i)\b").unwrap());

static RE_LATEST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@latest\b").unwrap());

// Accept both `--registry <url>` (space) and `--registry=<url>` (equals sign).
static RE_HAS_REGISTRY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)--registry[=\s]").unwrap());

static RE_HAS_INDEX_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(--index-url\s|-i\s)").unwrap());

static RE_REGISTRY_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)--registry[=\s](https?://\S+)").unwrap());

// Extracts the hostname from a URL (strips userinfo, stops at path/query/fragment/port).
// Mirrors RE_URL_HOST in bash_patterns.rs so registry allowlist matching is consistent.
static RE_REGISTRY_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)https?://(?:[^@/?#\s]+@)?([^/?#:\s]+)").unwrap());

fn make_snippet(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.len() > 120 {
        // Slice at a char boundary — a raw byte index can
        // fall mid-codepoint and panic on multi-byte UTF-8.
        let cut = trimmed
            .char_indices()
            .nth(117)
            .map(|(i, _)| i)
            .unwrap_or(trimmed.len());
        format!("{}...", &trimmed[..cut])
    } else {
        trimmed.to_string()
    }
}

#[allow(clippy::too_many_arguments)]
fn emit(
    findings: &mut Vec<Finding>,
    id: &str,
    severity: Severity,
    message: &str,
    remediation: &str,
    file: &std::path::Path,
    line_num: usize,
    line: &str,
) {
    findings.push(Finding {
        rule_id: id.to_string(),
        message: message.to_string(),
        severity,
        file: Some(file.to_path_buf()),
        line: Some(line_num),
        column: None,
        scanner: "package_install".to_string(),
        snippet: Some(make_snippet(line)),
        suppressed: false,
        suppression_reason: None,
        remediation: Some(remediation.to_string()),
    });
}

/// Built-in scanner for unsafe package installation patterns.
///
/// Scans `*.sh`, `*.bash`, and `*.zsh` files for `npm install`, `bun add`,
/// and `pip install` commands that are missing explicit registry flags or
/// use unpinned `@latest` versions.  Registry URLs are validated against
/// the [`allowlist.registries`](crate::config::AllowlistConfig::registries)
/// configuration.
///
/// See the [module-level documentation](self) for the full rule table.
pub struct PackageInstallScanner;

impl Scanner for PackageInstallScanner {
    fn name(&self) -> &'static str {
        "package_install"
    }

    fn description(&self) -> &'static str {
        "Package install audit — detects unregistered/unpinned installs"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn scan(&self, path: &Path, config: &Config) -> ScanResult {
        let start = Instant::now();
        let files = collect_files(path, &["sh", "bash", "zsh"]);
        let mut findings = Vec::new();

        // Allowlist entries are already lowercase (normalized at Config load time);
        // just filter out empty strings and borrow as &str slices.
        let allowed_registries: Vec<&str> = config
            .allowlist
            .registries
            .iter()
            .filter(|r| !r.is_empty())
            .map(String::as_str)
            .collect();

        for file in &files {
            let content = match std::fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for (line_num, line) in content.lines().enumerate() {
                let line_num = line_num + 1;

                let trimmed = line.trim();
                if trimmed.starts_with('#') && !trimmed.starts_with("#!") {
                    continue;
                }

                if is_suppressed_inline(line) {
                    continue;
                }

                // npm install without --registry
                if RE_NPM_INSTALL.is_match(line) && !RE_HAS_REGISTRY.is_match(line) {
                    emit(
                        &mut findings,
                        "pkg/F1-npm",
                        Severity::Warning,
                        "npm install without --registry — may pull from unexpected source",
                        "Specify --registry explicitly: npm install --registry https://registry.npmjs.org",
                        file,
                        line_num,
                        line,
                    );
                }

                // bun add without --registry
                if RE_BUN_ADD.is_match(line) && !RE_HAS_REGISTRY.is_match(line) {
                    emit(
                        &mut findings,
                        "pkg/F1-bun",
                        Severity::Warning,
                        "bun add without --registry — may pull from unexpected source",
                        "Specify --registry explicitly",
                        file,
                        line_num,
                        line,
                    );
                }

                // pip install without --index-url
                if RE_PIP_INSTALL.is_match(line) && !RE_HAS_INDEX_URL.is_match(line) {
                    emit(
                        &mut findings,
                        "pkg/F1-pip",
                        Severity::Warning,
                        "pip install without --index-url — may pull from unexpected source",
                        "Specify --index-url explicitly: pip install --index-url https://pypi.org/simple/",
                        file,
                        line_num,
                        line,
                    );
                }

                // yarn add/install without --registry
                if RE_YARN_ADD.is_match(line) && !RE_HAS_REGISTRY.is_match(line) {
                    emit(
                        &mut findings,
                        "pkg/F1-yarn",
                        Severity::Warning,
                        "yarn add without --registry — may pull from unexpected source",
                        "Specify --registry explicitly: yarn add --registry https://registry.npmjs.org <pkg>",
                        file,
                        line_num,
                        line,
                    );
                }

                // pnpm add/install without --registry
                if RE_PNPM_ADD.is_match(line) && !RE_HAS_REGISTRY.is_match(line) {
                    emit(
                        &mut findings,
                        "pkg/F1-pnpm",
                        Severity::Warning,
                        "pnpm add/install without --registry — may pull from unexpected source",
                        "Specify --registry explicitly: pnpm add --registry https://registry.npmjs.org <pkg>",
                        file,
                        line_num,
                        line,
                    );
                }

                // @latest unpinned version
                if RE_LATEST.is_match(line) {
                    emit(
                        &mut findings,
                        "pkg/F2-unpinned",
                        Severity::Warning,
                        "@latest install — unpinned, supply chain risk on future runs",
                        "Pin to an exact version: @1.2.3",
                        file,
                        line_num,
                        line,
                    );
                }

                // Registry allowlist check
                if let Some(caps) = RE_REGISTRY_URL.captures(line) {
                    if let Some(url) = caps.get(1) {
                        let url_str = url.as_str();
                        // Extract only the hostname so that a path like
                        // `https://evil.com/registry.npmjs.org/` cannot spoof
                        // an allowlisted entry via substring matching.
                        let host = RE_REGISTRY_HOST
                            .captures(url_str)
                            .and_then(|c| c.get(1))
                            .map(|m| m.as_str().to_lowercase())
                            .unwrap_or_default();
                        let is_allowed = !host.is_empty()
                            && allowed_registries.iter().any(|entry| {
                                host == *entry
                                    || host
                                        .strip_suffix(entry)
                                        .is_some_and(|prefix| prefix.ends_with('.'))
                            });

                        if !is_allowed {
                            emit(
                                &mut findings,
                                "pkg/F3-registry",
                                Severity::Warning,
                                &format!("Registry URL not in allowlist: {}", url_str),
                                "Add registry to oxidized-skills.toml [allowlist.registries] or use an approved registry",
                                file,
                                line_num,
                                line,
                            );
                        }
                    }
                }
            }
        }

        ScanResult {
            scanner_name: "package_install".to_string(),
            findings,
            files_scanned: files.len(),
            skipped: false,
            skip_reason: None,
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
            scanner_score: None,
            scanner_grade: None,
        }
    }
}

/// Returns the [`RuleInfo`] catalogue for every package install rule.
///
/// Used by the `list-rules` and `explain` CLI commands to display rule
/// metadata without running a scan.
pub fn rules() -> Vec<RuleInfo> {
    vec![
        RuleInfo {
            id: "pkg/F1-npm",
            severity: "warning",
            scanner: "package_install",
            message: "npm install without --registry — may pull from unexpected source",
            remediation: "Specify --registry explicitly: npm install --registry https://registry.npmjs.org",
        },
        RuleInfo {
            id: "pkg/F1-bun",
            severity: "warning",
            scanner: "package_install",
            message: "bun add without --registry — may pull from unexpected source",
            remediation: "Specify --registry explicitly",
        },
        RuleInfo {
            id: "pkg/F1-pip",
            severity: "warning",
            scanner: "package_install",
            message: "pip install without --index-url — may pull from unexpected source",
            remediation: "Specify --index-url explicitly: pip install --index-url https://pypi.org/simple/",
        },
        RuleInfo {
            id: "pkg/F1-yarn",
            severity: "warning",
            scanner: "package_install",
            message: "yarn add without --registry — may pull from unexpected source",
            remediation: "Specify --registry explicitly: yarn add --registry https://registry.npmjs.org <pkg>",
        },
        RuleInfo {
            id: "pkg/F1-pnpm",
            severity: "warning",
            scanner: "package_install",
            message: "pnpm add/install without --registry — may pull from unexpected source",
            remediation: "Specify --registry explicitly: pnpm add --registry https://registry.npmjs.org <pkg>",
        },
        RuleInfo {
            id: "pkg/F2-unpinned",
            severity: "warning",
            scanner: "package_install",
            message: "@latest install — unpinned, supply chain risk on future runs",
            remediation: "Pin to an exact version: @1.2.3",
        },
        RuleInfo {
            id: "pkg/F3-registry",
            severity: "warning",
            scanner: "package_install",
            message: "Registry URL not in allowlist",
            remediation: "Add registry to oxidized-skills.toml [allowlist.registries] or use an approved registry",
        },
    ]
}
