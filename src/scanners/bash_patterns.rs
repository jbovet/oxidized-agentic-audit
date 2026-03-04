//! Dangerous bash pattern scanner.
//!
//! Detects risky shell patterns across **eight categories** using pure Rust
//! regex matching — no external tool required.
//!
//! # Categories
//!
//! | Category | Severity | What it detects |
//! |----------|----------|-----------------|
//! | **A** — Remote Code Execution | Error | Pipe-to-shell, `eval`, `source <(curl …)` |
//! | **B** — Credential Exfiltration | Error | Access to `~/.ssh/`, `~/.aws/`, env-to-network |
//! | **C** — Destructive Operations | Error | `rm -rf ~/`, `dd` to block devices |
//! | **D** — Reverse Shell / Backdoors | Error | Netcat `-e`, bash `/dev/tcp`, Python socket |
//! | **E** — Privilege Escalation | Warning | `sudo su`, SUID bit |
//! | **G** — Unsafe Variable Expansion | Warning | Unquoted `rm -rf $VAR`, `bash -c "$VAR"` |
//! | **H** — Unallowlisted Outbound | Info | `curl`/`wget` to domains not in allowlist |
//!
//! # Scanned file types
//!
//! `*.sh`, `*.bash`, `*.zsh`
//!
//! # Suppression
//!
//! Individual lines can be suppressed with an inline `# audit:ignore` or
//! `# oxidized-skills:ignore` trailing comment. Category H findings are also
//! suppressed when every URL on the line resolves to a domain in
//! [`Config::allowlist`](crate::config::AllowlistConfig::domains).

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{collect_files, is_suppressed_inline, RuleInfo, Scanner};
use regex::{Regex, RegexSet};
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

/// A single regex-based bash pattern rule.
///
/// Each pattern carries a rule identifier, severity level, human-readable
/// message, and remediation guidance.  The actual regex matching is done via
/// the [`PATTERN_SET`] `RegexSet` — the index in the `PATTERNS` array
/// corresponds to the index in the `RegexSet`.
struct BashPattern {
    id: &'static str,
    severity: Severity,
    message: &'static str,
    remediation: &'static str,
}

// Captures the hostname from an HTTP/HTTPS URL.
// - Strips optional userinfo (user:pass@) so attacker@github.com extracts github.com.
// - Stops at '/', '?', '#', ':', or whitespace so fragment tricks like
//   evil.com#.github.com cannot spoof an allowlisted domain.
static RE_URL_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)https?://(?:[^@/?#\s]+@)?([^/?#:\s]+)").unwrap());

/// Returns true when **every** URL on `line` resolves to an allowlisted domain.
///
/// A finding is suppressed only when all hosts are safe; if even one URL on
/// the line points at an unapproved domain the function returns `false` so the
/// finding is emitted (e.g. `curl https://github.com https://evil.com/sh`).
///
/// Matching rules per host: exact match OR host ends with `.<entry>` (subdomain).
/// Empty allowlist entries are ignored to prevent `ends_with(".")` matching any FQDN.
fn domain_is_allowed(line: &str, allowed: &std::collections::HashSet<&str>) -> bool {
    // Iterate over every URL found on the line.  The finding is suppressed only
    // when at least one URL is present and all of them are allowlisted.
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

        // Fast O(1) exact match via HashSet
        if allowed.contains(host.as_str()) {
            continue;
        }

        // Fallback: subdomain match (e.g. sub.github.com matches github.com)
        let host_is_allowed = allowed.iter().any(|entry| {
            host.strip_suffix(entry)
                .is_some_and(|prefix| prefix.ends_with('.'))
        });

        if !host_is_allowed {
            return false;
        }
    }

    found_any
}

static PATTERNS: &[BashPattern] = &[
    // Category A: Remote Code Execution
    BashPattern {
        id: "bash/CAT-A1",
        severity: Severity::Error,

        message: "Pipe to shell — potential remote code execution",
        remediation: "Download to a temp file, verify checksum, then execute explicitly",
    },
    BashPattern {
        id: "bash/CAT-A2",
        severity: Severity::Error,

        message: "eval of dynamic content — arbitrary code execution risk",
        remediation: "Avoid eval; use explicit function calls or case statements",
    },
    BashPattern {
        id: "bash/CAT-A3",
        severity: Severity::Error,
        message: "Source from URL — executes arbitrary remote shell code",
        remediation: "Download to a file, review content, then source explicitly",
    },
    BashPattern {
        id: "bash/CAT-A4",
        severity: Severity::Error,
        message: "Download to temp file then execute — two-step RCE vector",
        remediation: "Use package manager or verified binary download with checksum",
    },
    // Category B: Credential Exfiltration
    BashPattern {
        id: "bash/CAT-B1",
        severity: Severity::Error,
        message: "Access to ~/.ssh/ — SSH key exfiltration risk",
        remediation: "SSH keys should never be read by skill scripts",
    },
    BashPattern {
        id: "bash/CAT-B2",
        severity: Severity::Error,
        message: "Access to ~/.aws/ — AWS credential exfiltration risk",
        remediation: "AWS credentials should never be read by skill scripts",
    },
    BashPattern {
        id: "bash/CAT-B3",
        severity: Severity::Error,
        message: "Access to ~/.kube/config — Kubernetes credential exfiltration risk",
        remediation: "Kubeconfig should never be read by skill scripts",
    },
    BashPattern {
        id: "bash/CAT-B4",
        severity: Severity::Error,
        message: "Environment variable sent as HTTP POST body — exfiltration risk",
        remediation: "Never send environment variables to external endpoints",
    },
    BashPattern {
        id: "bash/CAT-B5",
        severity: Severity::Error,
        message: "env output piped to network tool — full environment exfiltration",
        remediation: "Never pipe env output to outbound network tools",
    },
    // Category C: Destructive Operations
    BashPattern {
        id: "bash/CAT-C1",
        severity: Severity::Error,
        message: "rm -rf on home or root directory — potentially irreversible destruction",
        remediation: "Scope rm operations to specific subdirectories with validated paths",
    },
    BashPattern {
        id: "bash/CAT-C2",
        severity: Severity::Error,
        message: "dd disk wipe — overwrites storage device",
        remediation: "dd to block devices should never appear in skill scripts",
    },
    // Category D: Reverse Shell / Backdoors
    BashPattern {
        id: "bash/CAT-D1",
        severity: Severity::Error,
        message: "Netcat reverse shell — opens interactive shell to remote host",
        remediation: "Netcat with -e flag is a reverse shell. Remove immediately.",
    },
    BashPattern {
        id: "bash/CAT-D2",
        severity: Severity::Error,
        message: "Bash TCP reverse shell — /dev/tcp backdoor",
        remediation: "Bash /dev/tcp redirection is a reverse shell. Remove immediately.",
    },
    BashPattern {
        id: "bash/CAT-D3",
        severity: Severity::Error,
        message: "Python socket-based reverse shell pattern",
        remediation: "Python socket connect pattern is a known reverse shell. Remove immediately.",
    },
    // Category E: Privilege Escalation
    BashPattern {
        id: "bash/CAT-E1",
        severity: Severity::Warning,
        message: "sudo shell — unintended privilege escalation",
        remediation: "Skills should not require root. Specify exact sudo commands if unavoidable.",
    },
    BashPattern {
        id: "bash/CAT-E2",
        severity: Severity::Warning,
        message: "SUID bit — persistent privilege escalation vector",
        remediation: "Setting SUID bit on binaries is a privilege escalation risk",
    },
    // Category G: Unsafe Variable Expansion
    BashPattern {
        id: "bash/CAT-G1",
        severity: Severity::Warning,
        message: "rm -rf with unquoted variable — empty variable may delete current directory",
        remediation: "Quote the variable: rm -rf \"$VARNAME\" and validate it is non-empty first",
    },
    BashPattern {
        id: "bash/CAT-G2",
        severity: Severity::Warning,
        message: "Shell invoked with variable argument — command injection risk",
        remediation: "Avoid bash -c with variable content. Use functions or explicit commands.",
    },
    // Category H: Unallowlisted Outbound Network
    BashPattern {
        id: "bash/CAT-H1",
        severity: Severity::Info,
        message: "Outbound HTTP call detected — verify domain is in allowed list",
        remediation: "Ensure domain is in oxidized-skills.toml [allowlist.domains]",
    },
];

/// Pre-compiled set of all bash pattern regexes for O(1) first-pass filtering.
///
/// A line that matches nothing in this set can be skipped entirely without
/// testing each individual pattern.  The set indices correspond 1:1 to the
/// `PATTERNS` array.
static PATTERN_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\|\s*(bash|sh|zsh|fish|ksh)\b",           // CAT-A1
        r#"(?i)\beval\s*["'`\$\(]"#,                    // CAT-A2
        r"(?i)\bsource\s*<\s*\(\s*(curl|wget|fetch)",   // CAT-A3
        r"(?i)(curl|wget).+/tmp/.+&&\s*(bash|sh|exec)", // CAT-A4
        r"(\$\{?HOME\}?|~)/\.ssh/",                     // CAT-B1
        r"(\$\{?HOME\}?|~)/\.aws/",                     // CAT-B2
        r"(\$\{?HOME\}?|~)/\.kube/config",              // CAT-B3
        r#"(?i)(curl|wget).+\-d\s+["']?\$"#,            // CAT-B4
        r"(?i)\benv\b.+\|\s*(curl|wget|nc)",            // CAT-B5
        r"(?i)\brm\s+(-[rRfF]+\s+){0,3}(\$HOME|~/|/\s*$|\$\{HOME\})", // CAT-C1
        r"(?i)\bdd\s+if=/dev/(urandom|zero|random)\s+of=/dev/", // CAT-C2
        r"(?i)\bnc\s+(-[a-z]+\s+)*-e\s+/bin/",          // CAT-D1
        r"bash\s+-i\s+>&\s*/dev/tcp/",                  // CAT-D2
        r"(?i)python\S*\s+-c\s+.*socket.*connect",      // CAT-D3
        r"(?i)\bsudo\s+(su|bash|sh)\b",                 // CAT-E1
        r"\bchmod\s+[+u]s\b",                           // CAT-E2
        r#"(?i)\brm\s+-[rRfF]+\s+\$[a-zA-Z_][a-zA-Z0-9_]*(?:[^/"\{]|$)"#, // CAT-G1
        r#"(?i)(bash|sh)\s+-c\s+["']?\$[a-zA-Z_]"#,     // CAT-G2
        r"(?i)(curl|wget)\s+https?://",                 // CAT-H1
    ])
    .unwrap()
});

/// Built-in scanner for dangerous shell patterns and command execution anti-patterns.
///
/// Scans `*.sh`, `*.bash`, and `*.zsh` files line-by-line against a static
/// table of compiled regexes covering categories A through H.  No external
/// tool is required — all matching is performed in pure Rust.
///
/// Comments (lines starting with `#`, except shebangs) and lines with an
/// inline suppression marker are skipped automatically.
///
/// See the [module-level documentation](self) for the full category table.
pub struct BashPatternScanner;

impl Scanner for BashPatternScanner {
    fn name(&self) -> &'static str {
        "bash_patterns"
    }

    fn description(&self) -> &'static str {
        "Dangerous bash pattern scanner (Categories A-H) — pure Rust regex"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn scan(&self, path: &Path, config: &Config) -> ScanResult {
        let start = Instant::now();
        let files = collect_files(path, &["sh", "bash", "zsh"]);
        let mut findings = Vec::new();

        // Guard: PATTERNS and PATTERN_SET must stay in sync.
        // If they drift (e.g. a pattern added to one but not the other) the
        // indexing below will panic at runtime.  This assert fires immediately
        // in debug/test builds so the mismatch is caught at development time.
        debug_assert_eq!(
            PATTERNS.len(),
            PATTERN_SET.len(),
            "bash PATTERNS and PATTERN_SET are out of sync — add/remove from both arrays"
        );

        // Build HashSet once for O(1) exact-match lookups in domain_is_allowed.
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
                    // Surface I/O errors (permissions, encoding) as Info findings
                    // so the author knows a file was not scanned.
                    findings.push(Finding {
                        rule_id: "bash/read-error".to_string(),
                        message: format!("Could not read file: {}", e),
                        severity: crate::finding::Severity::Info,
                        file: Some(file.clone()),
                        line: None,
                        column: None,
                        scanner: "bash_patterns".to_string(),
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

                // Skip comments (but not shebangs)
                let trimmed = line.trim();
                if trimmed.starts_with('#') && !trimmed.starts_with("#!") {
                    continue;
                }

                // Check inline suppression
                if is_suppressed_inline(line) {
                    continue;
                }

                // Fast O(1) pre-filter: skip the line entirely if no
                // pattern matches.  Only test individual regexes for
                // the matching indices.
                let matches = PATTERN_SET.matches(line);
                if !matches.matched_any() {
                    continue;
                }

                for idx in matches.iter() {
                    let pattern = &PATTERNS[idx];

                    // CAT-H1: skip if the domain is in the allowlist
                    if pattern.id == "bash/CAT-H1" && domain_is_allowed(line, &allowed_domains) {
                        continue;
                    }

                    let snippet = if line.len() > 120 {
                        // Slice at a char boundary — a raw byte index can
                        // fall mid-codepoint and panic on multi-byte UTF-8.
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
                        severity: pattern.severity,
                        file: Some(file.clone()),
                        line: Some(line_num),
                        column: None,
                        scanner: "bash_patterns".to_string(),
                        snippet: Some(snippet.trim().to_string()),
                        suppressed: false,
                        suppression_reason: None,
                        remediation: Some(pattern.remediation.to_string()),
                    });
                }
            }
        }

        ScanResult {
            scanner_name: "bash_patterns".to_string(),
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

/// Returns the [`RuleInfo`] catalogue for every bash pattern rule.
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
            scanner: "bash_patterns",
            message: p.message,
            remediation: p.remediation,
        })
        .collect()
}
