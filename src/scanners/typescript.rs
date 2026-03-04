//! TypeScript and JavaScript security pattern scanner.
//!
//! Detects risky patterns in TypeScript/JavaScript files across six categories
//! using pure Rust regex matching — no external tool required.
//!
//! # Categories
//!
//! | Category | Severity | What it detects |
//! |----------|----------|-----------------|
//! | **A** — Arbitrary Code Execution | Error | `eval()`, `new Function()` |
//! | **B** — Shell Execution | Warning/Info | `child_process` import, `execSync`/`spawnSync` (sync), `exec`/`spawn`/`execFile` (async) |
//! | **C** — Credential Access | Error | Paths referencing SSH keys, AWS, or kubeconfig files |
//! | **D** — Reverse Shell / Backdoors | Error | Node.js `net` module raw socket connections |
//! | **H** — Unallowlisted Outbound | Info | `fetch`/`axios`/`got` to domains not in allowlist |
//!
//! # Scanned file types
//!
//! `*.ts`, `*.tsx`, `*.mts`, `*.js`, `*.mjs`
//!
//! # Suppression
//!
//! Individual lines can be suppressed with an inline `// audit:ignore` or
//! `// oxidized-skills:ignore` trailing comment.  Category H findings are also
//! automatically suppressed when every URL on the line resolves to a domain in
//! [`Config::allowlist`](crate::config::AllowlistConfig::domains).

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{collect_files, RuleInfo, Scanner};
use regex::{Regex, RegexSet};
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Pattern table
// ---------------------------------------------------------------------------

/// A single regex-based TypeScript/JavaScript security rule.
struct TsPattern {
    id: &'static str,
    severity: Severity,
    message: &'static str,
    remediation: &'static str,
}

static PATTERNS: &[TsPattern] = &[
    // ── Category A: Arbitrary Code Execution ────────────────────────────────
    TsPattern {
        id: "typescript/CAT-A1",
        severity: Severity::Error,
        message: "eval() call — arbitrary code execution risk",
        remediation:
            "Avoid eval(); use explicit function calls, JSON.parse(), or switch statements",
    },
    TsPattern {
        id: "typescript/CAT-A2",
        severity: Severity::Error,
        message: "new Function() — dynamic code construction, arbitrary code execution risk",
        remediation: "Avoid new Function(); use explicit functions or dispatch tables",
    },
    // ── Category B: Shell Execution via child_process ───────────────────────
    TsPattern {
        id: "typescript/CAT-B1",
        severity: Severity::Warning,
        message: "child_process module imported — enables shell command execution",
        remediation:
            "Avoid importing child_process in skills; use typed API clients instead of shell commands",
    },
    TsPattern {
        id: "typescript/CAT-B2",
        severity: Severity::Warning,
        message: "execSync/spawnSync call — executes shell commands synchronously",
        remediation:
            "Replace synchronous shell calls with typed API clients or Node.js built-in equivalents",
    },
    TsPattern {
        id: "typescript/CAT-B3",
        severity: Severity::Info,
        message: "exec/spawn/execFile call — possible async shell execution; verify child_process context",
        remediation:
            "If imported from child_process, replace with typed API clients; add // audit:ignore if unrelated to child_process",
    },
    // ── Category C: Credential File Access ──────────────────────────────────
    TsPattern {
        id: "typescript/CAT-C1",
        severity: Severity::Error,
        message: "SSH private key path detected — credential access risk",
        remediation: "Skills must not read SSH keys; use agent-provided auth tokens instead",
    },
    TsPattern {
        id: "typescript/CAT-C2",
        severity: Severity::Error,
        message: "AWS credentials path detected — credential exfiltration risk",
        remediation:
            "Skills must not read ~/.aws/credentials; pass credentials via environment variables",
    },
    TsPattern {
        id: "typescript/CAT-C3",
        severity: Severity::Error,
        message: "Kubernetes kubeconfig path detected — credential access risk",
        remediation: "Skills must not read ~/.kube/config; use in-cluster service accounts",
    },
    // ── Category D: Reverse Shell / Backdoors ───────────────────────────────
    TsPattern {
        id: "typescript/CAT-D1",
        severity: Severity::Error,
        message: "Node.js net module raw socket — potential reverse shell or backdoor",
        remediation:
            "Skills must not open raw TCP sockets; use HTTPS APIs for all network communication",
    },
    // ── Category H: Unallowlisted Outbound Network ──────────────────────────
    TsPattern {
        id: "typescript/CAT-H1",
        severity: Severity::Info,
        message: "Outbound HTTP call detected — verify domain is in allowed list",
        remediation: "Add the domain to oxidized-skills.toml [allowlist.domains]",
    },
];

// ---------------------------------------------------------------------------
// Compiled regexes
// ---------------------------------------------------------------------------

/// Captures the hostname from an HTTP/HTTPS URL.
///
/// Strips optional userinfo (`user:pass@`) and stops at `/?#:\s` to prevent
/// fragment-based allowlist bypass tricks (e.g. `evil.com#.github.com`).
static RE_URL_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)https?://(?:[^@/?#\s]+@)?([^/?#:\s]+)").unwrap());

/// Inline suppression marker for TypeScript/JavaScript files.
///
/// Recognizes `// audit:ignore` and `// oxidized-skills:ignore` at end-of-line.
static RE_TS_SUPPRESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)//\s*(audit|oxidized-skills):ignore\s*$").unwrap());

/// Pre-compiled `RegexSet` for TypeScript/JavaScript patterns.
///
/// Indices correspond 1:1 to the [`PATTERNS`] array.  The `RegexSet` provides
/// a fast O(lines × patterns) first-pass; per-line cost grows only for lines
/// that actually match.
static PATTERN_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // CAT-A1: eval() — exclude method calls like obj.eval() using a
        // negated character class before the keyword.
        r"(?:^|[^.a-zA-Z_$])eval\s*\(",
        // CAT-A2: new Function() dynamic constructor
        r"\bnew\s+Function\s*\(",
        // CAT-B1: child_process CommonJS require or ES module import
        r#"(?i)(?:require\s*\(\s*['"]child_process['"]|from\s+['"]child_process['"])"#,
        // CAT-B2: execSync / spawnSync / execFileSync — synchronous shell execution.
        // These names are distinct enough to pattern-match without the module context.
        r"\b(?:execSync|spawnSync|execFileSync)\s*\(",
        // CAT-B3: exec / spawn / execFile — async child_process variants.
        // Lower-confidence than sync forms (these names appear in other contexts too);
        // severity is Info so authors can verify child_process context before acting.
        // Uses the same negative-lookbehind pattern as CAT-A1 to exclude method calls
        // like `/regex/.exec(str)` or `db.exec(query)` where the name is preceded by `.`.
        r"(?:^|[^.a-zA-Z_$])(?:exec|execFile|spawn)\s*\(",
        // CAT-C1: SSH key paths (covers private keys and config files)
        r"(?i)\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa|id_dsa|id_xmss|authorized_keys|known_hosts)",
        // CAT-C2: AWS credentials file
        r"(?i)\.aws[/\\]credentials",
        // CAT-C3: Kubernetes kubeconfig
        r"(?i)\.kube[/\\]config",
        // CAT-D1: Node.js net module raw socket construction
        r"(?i)\bnet\.(?:createConnection|createServer|connect|Socket)\s*\(",
        // CAT-H1: Outbound fetch / axios / got / ky with a literal HTTPS URL.
        // Checks for the most common HTTP client libraries used in skills.
        r#"(?i)(?:fetch|axios\.(?:get|post|put|delete|patch|head|request)|got\.(?:get|post|stream)|ky\.(?:get|post|put|delete|patch))\s*\(\s*['"`]https?://"#,
    ])
    .unwrap()
});

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Returns `true` if `line` ends with a JS/TS inline suppression marker.
///
/// # Examples
///
/// ```
/// use oxidized_skills::scanners::typescript::is_suppressed_ts;
///
/// assert!(is_suppressed_ts("fetch('https://evil.com') // audit:ignore"));
/// assert!(!is_suppressed_ts("fetch('https://evil.com')"));
/// ```
pub fn is_suppressed_ts(line: &str) -> bool {
    RE_TS_SUPPRESS.is_match(line)
}

/// Returns `true` when every HTTP/HTTPS URL on `line` resolves to an allowlisted domain.
///
/// A URL is allowlisted when its hostname either exactly matches an entry or is a
/// subdomain (e.g. `api.github.com` matches `github.com`).  Returns `false` if
/// the line contains no URLs at all.
fn domain_is_allowed(line: &str, allowed: &std::collections::HashSet<&str>) -> bool {
    let mut found_any = false;
    for cap in RE_URL_HOST.captures_iter(line) {
        let host = match cap.get(1) {
            Some(m) => m.as_str().to_lowercase(),
            None => continue,
        };
        if host.is_empty() {
            continue;
        }
        found_any = true;

        // Exact match first (O(1) HashSet lookup).
        if allowed.contains(host.as_str()) {
            continue;
        }

        // Subdomain match: `api.github.com` matches allowlist entry `github.com`.
        let host_is_allowed = allowed.iter().any(|entry| {
            host.strip_suffix(*entry)
                .is_some_and(|prefix| prefix.ends_with('.'))
        });

        if !host_is_allowed {
            return false;
        }
    }
    found_any
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Built-in scanner for dangerous TypeScript and JavaScript security patterns.
///
/// Scans `*.ts`, `*.tsx`, `*.mts`, `*.js`, and `*.mjs` files line-by-line
/// against a compiled [`RegexSet`] covering arbitrary code execution, shell
/// access, credential reads, raw socket backdoors, and outbound HTTP calls.
/// No external tool is required — all matching is performed in pure Rust.
///
/// Single-line comments (`// ...`) and lines with an inline suppression marker
/// (`// audit:ignore`) are skipped automatically.
///
/// See the [module-level documentation](self) for the full rule table.
pub struct TypeScriptScanner;

impl Scanner for TypeScriptScanner {
    fn name(&self) -> &'static str {
        "typescript_patterns"
    }

    fn description(&self) -> &'static str {
        "Dangerous TypeScript/JavaScript pattern scanner (Categories A-H) — pure Rust regex"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn scan(&self, path: &Path, config: &Config) -> ScanResult {
        let start = Instant::now();
        let files = collect_files(path, &["ts", "tsx", "mts", "js", "mjs"]);
        let mut findings = Vec::new();

        // Pre-build allowlist HashSet once for O(1) domain lookups per line.
        let allowed_domains: std::collections::HashSet<&str> = config
            .allowlist
            .domains
            .iter()
            .filter(|e| !e.is_empty())
            .map(String::as_str)
            .collect();

        for file in &files {
            let content = match std::fs::read_to_string(file) {
                Ok(c) => c,
                Err(e) => {
                    // Surface I/O errors as Info findings so the author knows
                    // a file was skipped rather than silently passing.
                    findings.push(Finding {
                        rule_id: "typescript/read-error".to_string(),
                        message: format!("Could not read file: {}", e),
                        severity: Severity::Info,
                        file: Some(file.clone()),
                        line: None,
                        column: None,
                        scanner: self.name().to_string(),
                        snippet: None,
                        suppressed: false,
                        suppression_reason: None,
                        remediation: Some(
                            "Check file permissions and ensure the file is valid UTF-8".to_string(),
                        ),
                    });
                    continue;
                }
            };

            for (line_num, line) in content.lines().enumerate() {
                let line_num = line_num + 1;
                let trimmed = line.trim();

                // Skip single-line comments entirely.
                if trimmed.starts_with("//") {
                    continue;
                }

                // Skip lines with an inline JS/TS suppression marker.
                if is_suppressed_ts(line) {
                    continue;
                }

                // Fast pre-filter: skip lines that match nothing.
                let matches = PATTERN_SET.matches(line);
                if !matches.matched_any() {
                    continue;
                }

                for idx in matches.iter() {
                    let pattern = &PATTERNS[idx];

                    // CAT-H1: suppress when every URL on the line is allowlisted.
                    if pattern.id == "typescript/CAT-H1"
                        && domain_is_allowed(line, &allowed_domains)
                    {
                        continue;
                    }

                    // Truncate long snippets at a char boundary to avoid panics
                    // on multi-byte UTF-8 codepoints.
                    let snippet = if line.len() > 120 {
                        let cut = line
                            .char_indices()
                            .nth(117)
                            .map(|(i, _)| i)
                            .unwrap_or(line.len());
                        format!("{}...", &line[..cut])
                    } else {
                        line.to_string()
                    };

                    findings.push(Finding {
                        rule_id: pattern.id.to_string(),
                        message: pattern.message.to_string(),
                        severity: pattern.severity.clone(),
                        file: Some(file.clone()),
                        line: Some(line_num),
                        column: None,
                        scanner: self.name().to_string(),
                        snippet: Some(snippet.trim().to_string()),
                        suppressed: false,
                        suppression_reason: None,
                        remediation: Some(pattern.remediation.to_string()),
                    });
                }
            }
        }

        ScanResult {
            scanner_name: self.name().to_string(),
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

// ---------------------------------------------------------------------------
// Rule catalogue
// ---------------------------------------------------------------------------

/// Returns the [`RuleInfo`] catalogue for every TypeScript pattern rule.
///
/// Used by the `list-rules` and `explain` CLI commands to display rule
/// metadata without running a scan.
pub fn rules() -> Vec<RuleInfo> {
    PATTERNS
        .iter()
        .map(|p| RuleInfo {
            id: p.id,
            severity: match p.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "info",
            },
            scanner: "typescript_patterns",
            message: p.message,
            remediation: p.remediation,
        })
        .collect()
}
