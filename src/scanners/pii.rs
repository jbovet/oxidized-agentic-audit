//! Personally Identifiable Information (PII) scanner.
//!
//! Detects real-looking PII hardcoded into skill bundles — emails, US SSNs,
//! credit-card numbers (Luhn-validated), private IPv4 addresses, and
//! internal hostnames. This is **separate from** the secrets scanner
//! (gitleaks): secrets are credentials; PII is leaked context that does
//! not authenticate but does identify real people, customers, or
//! infrastructure.
//!
//! | ID | Sev | What it checks |
//! |----|-----|----------------|
//! | `pii/P1-email`         | Warning | Email address (test/example/`noreply@*` excluded) |
//! | `pii/P2-ssn`           | Error   | US SSN format `123-45-6789` (placeholder ranges excluded) |
//! | `pii/P3-credit-card`   | Error   | 13–19 digit card number that passes Luhn |
//! | `pii/P4-private-ipv4`  | Info    | RFC 1918 private IPv4 (10/8, 172.16/12, 192.168/16) |
//! | `pii/P5-internal-host` | Warning | Hostname ending in `.internal`/`.corp`/`.local`/`.lan`/`.intranet` |
//!
//! # Scanned file types
//!
//! `*.md`, `*.markdown`, `*.sh`, `*.bash`, `*.zsh`. PII most often appears
//! in example commands and prose; source-language files routinely contain
//! patterns that look PII-like (test fixtures, regex literals) and would
//! produce too many false positives.
//!
//! # Suppression
//!
//! Inline `# scan:ignore` comments and `.oxidized-agentic-audit-ignore`
//! entries silence specific findings.

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{collect_files, is_suppressed_inline, read_file_limited, RuleInfo, Scanner};
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

/// RFC-5322-ish email matcher. Intentionally permissive — false positives
/// are filtered out by [`is_example_email`].
static RE_EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").unwrap());

/// US SSN format `NNN-NN-NNNN`.
static RE_SSN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{3})-(\d{2})-(\d{4})\b").unwrap());

/// Candidate credit-card runs: 13–19 digits with optional `-` or space
/// separators every 4 digits. Validated by Luhn before emitting.
static RE_CC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").unwrap());

/// IPv4 dotted quad — used by both the private-range check and the
/// internal-host overlap suppression.
static RE_IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").unwrap());

/// Hostnames whose TLD is one of the common internal/private suffixes.
/// Anchored to a non-letter boundary on the left to avoid matching
/// `final.local` inside a longer identifier.
static RE_INTERNAL_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})*)\.(internal|corp|local|lan|intranet)\b").unwrap()
});

fn make_snippet(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.len() > 120 {
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
    message: String,
    remediation: &str,
    file: &Path,
    line_num: usize,
    line: &str,
) {
    findings.push(Finding {
        rule_id: id.to_string(),
        message,
        severity,
        file: Some(file.to_path_buf()),
        line: Some(line_num),
        column: None,
        scanner: "pii".to_string(),
        snippet: Some(make_snippet(line)),
        suppressed: false,
        suppression_reason: None,
        remediation: Some(remediation.to_string()),
    });
}

/// Returns `true` when an email belongs to a documented test/placeholder
/// domain or a generic no-reply mailbox. These addresses are not real PII
/// and would produce noise if flagged.
fn is_example_email(addr: &str) -> bool {
    let lower = addr.to_ascii_lowercase();
    let local = lower.split('@').next().unwrap_or("");
    let domain = lower.rsplit('@').next().unwrap_or("");

    // RFC 2606 reserved test domains, plus common placeholders.
    let placeholder_domains: &[&str] = &[
        "example.com",
        "example.org",
        "example.net",
        "example.edu",
        "test.com",
        "test.org",
        "localhost",
        "domain.com",
        "email.com",
        "mail.com",
    ];
    if placeholder_domains.contains(&domain) {
        return true;
    }
    if domain.ends_with(".example")
        || domain.ends_with(".test")
        || domain.ends_with(".invalid")
        || domain.ends_with(".localhost")
    {
        return true;
    }

    // Generic non-personal mailboxes. The local-part check is intentional —
    // `noreply@gmail.com` is still a real address but `noreply@*` is the
    // standard "do not reply" pattern used in vendor footers and headers.
    matches!(
        local,
        "noreply" | "no-reply" | "donotreply" | "do-not-reply" | "user" | "username" | "you"
    )
}

/// Returns `true` for SSN values that fall in placeholder/invalid ranges.
/// Filtering them out reduces noise from documentation that says
/// "your SSN looks like 123-45-6789".
fn is_placeholder_ssn(area: u32, group: u32, serial: u32) -> bool {
    // Famous placeholder.
    if area == 123 && group == 45 && serial == 6789 {
        return true;
    }
    // SSA-invalid ranges per https://www.ssa.gov/employer/randomization.html
    if area == 0 || area == 666 || (900..=999).contains(&area) {
        return true;
    }
    if group == 0 || serial == 0 {
        return true;
    }
    false
}

/// Returns `true` if `digits` (already stripped of separators) passes the
/// Luhn checksum used for credit-card validation.
fn luhn_valid(digits: &str) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for c in digits.chars().rev() {
        let Some(mut d) = c.to_digit(10) else {
            return false;
        };
        if alt {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alt = !alt;
    }
    sum % 10 == 0
}

/// Returns the digit-only form of a credit-card candidate, dropping
/// separators. Returns `None` if the run is not 13–19 digits long.
fn cc_digits_only(s: &str) -> Option<String> {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if (13..=19).contains(&digits.len()) {
        Some(digits)
    } else {
        None
    }
}

/// Returns `true` if `(a, b, c, d)` is a private-range IPv4 per RFC 1918,
/// loopback (127/8), or link-local (169.254/16).
fn is_private_ipv4(a: u32, b: u32, _c: u32, _d: u32) -> bool {
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || a == 127
        || (a == 169 && b == 254)
}

/// Built-in scanner for hardcoded personally identifiable information.
///
/// See the [module-level documentation](self) for the full rule table.
pub struct PiiScanner;

impl Scanner for PiiScanner {
    fn name(&self) -> &'static str {
        "pii"
    }

    fn description(&self) -> &'static str {
        "PII audit — flags hardcoded emails, SSNs, credit cards, private IPs, and internal hostnames"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn scan(&self, path: &Path, _config: &Config) -> ScanResult {
        let start = Instant::now();
        let files = collect_files(path, &["md", "markdown", "sh", "bash", "zsh"]);
        let mut findings = Vec::new();

        for file in &files {
            let content = match read_file_limited(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for (line_num, line) in content.lines().enumerate() {
                let line_num = line_num + 1;

                if is_suppressed_inline(line) {
                    continue;
                }

                // P1 — email
                for m in RE_EMAIL.find_iter(line) {
                    let addr = m.as_str();
                    if is_example_email(addr) {
                        continue;
                    }
                    emit(
                        &mut findings,
                        "pii/P1-email",
                        Severity::Warning,
                        format!("Hardcoded email address: {addr}"),
                        "Replace with a placeholder (user@example.com) or move the address to a runtime configuration.",
                        file,
                        line_num,
                        line,
                    );
                }

                // P2 — SSN
                for caps in RE_SSN.captures_iter(line) {
                    let area: u32 = caps.get(1).unwrap().as_str().parse().unwrap_or(0);
                    let group: u32 = caps.get(2).unwrap().as_str().parse().unwrap_or(0);
                    let serial: u32 = caps.get(3).unwrap().as_str().parse().unwrap_or(0);
                    if is_placeholder_ssn(area, group, serial) {
                        continue;
                    }
                    emit(
                        &mut findings,
                        "pii/P2-ssn",
                        Severity::Error,
                        format!("US SSN-formatted number: {area:03}-{group:02}-XXXX"),
                        "Remove the SSN. If a placeholder is needed, use 000-00-0000 or 123-45-6789.",
                        file,
                        line_num,
                        line,
                    );
                }

                // P3 — credit card (Luhn)
                for m in RE_CC.find_iter(line) {
                    if let Some(digits) = cc_digits_only(m.as_str()) {
                        if luhn_valid(&digits) {
                            // Skip if the same run is also a Luhn-valid IPv4-like token —
                            // RE_CC requires 13+ digits so plain IPv4s never reach here.
                            let last4 = &digits[digits.len() - 4..];
                            emit(
                                &mut findings,
                                "pii/P3-credit-card",
                                Severity::Error,
                                format!(
                                    "Luhn-valid credit-card number ({} digits, ending {}): redact",
                                    digits.len(),
                                    last4
                                ),
                                "Remove the card number. Use 4242 4242 4242 4242 (Stripe test card) for examples.",
                                file,
                                line_num,
                                line,
                            );
                        }
                    }
                }

                // P4 — private IPv4
                for caps in RE_IPV4.captures_iter(line) {
                    let a: u32 = caps.get(1).unwrap().as_str().parse().unwrap_or(0);
                    let b: u32 = caps.get(2).unwrap().as_str().parse().unwrap_or(0);
                    let c: u32 = caps.get(3).unwrap().as_str().parse().unwrap_or(0);
                    let d: u32 = caps.get(4).unwrap().as_str().parse().unwrap_or(0);
                    // Reject obvious non-IPs (any octet > 255).
                    if a > 255 || b > 255 || c > 255 || d > 255 {
                        continue;
                    }
                    if is_private_ipv4(a, b, c, d) {
                        emit(
                            &mut findings,
                            "pii/P4-private-ipv4",
                            Severity::Info,
                            format!("Private IPv4 address: {a}.{b}.{c}.{d}"),
                            "Internal addresses leak network topology. Replace with a placeholder or move into runtime config.",
                            file,
                            line_num,
                            line,
                        );
                    }
                }

                // P5 — internal hostname
                for m in RE_INTERNAL_HOST.find_iter(line) {
                    let host = m.as_str();
                    emit(
                        &mut findings,
                        "pii/P5-internal-host",
                        Severity::Warning,
                        format!("Internal hostname: {host}"),
                        "Hostnames in internal TLDs leak infrastructure. Move into runtime config or replace with a placeholder.",
                        file,
                        line_num,
                        line,
                    );
                }
            }
        }

        ScanResult {
            scanner_name: "pii".to_string(),
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

/// Returns the [`RuleInfo`] catalogue for every PII rule.
pub fn rules() -> Vec<RuleInfo> {
    vec![
        RuleInfo {
            id: "pii/P1-email",
            severity: "warning",
            scanner: "pii",
            message: "Hardcoded email address",
            remediation: "Replace with a placeholder or runtime configuration.",
        },
        RuleInfo {
            id: "pii/P2-ssn",
            severity: "error",
            scanner: "pii",
            message: "US SSN-formatted number",
            remediation: "Remove the SSN; use 000-00-0000 if a placeholder is required.",
        },
        RuleInfo {
            id: "pii/P3-credit-card",
            severity: "error",
            scanner: "pii",
            message: "Luhn-valid credit-card number",
            remediation:
                "Remove the card number; use a documented test card (e.g. 4242 4242 4242 4242).",
        },
        RuleInfo {
            id: "pii/P4-private-ipv4",
            severity: "info",
            scanner: "pii",
            message: "Private IPv4 address (RFC 1918, loopback, link-local)",
            remediation: "Move internal addresses into runtime configuration.",
        },
        RuleInfo {
            id: "pii/P5-internal-host",
            severity: "warning",
            scanner: "pii",
            message: "Internal hostname (.internal/.corp/.local/.lan/.intranet)",
            remediation: "Move internal hostnames into runtime configuration.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_known_valid() {
        // Visa test number.
        assert!(luhn_valid("4242424242424242"));
        // Generic Luhn-valid sample.
        assert!(luhn_valid("79927398713"));
    }

    #[test]
    fn luhn_rejects_invalid() {
        assert!(!luhn_valid("1234567890123456"));
        assert!(!luhn_valid("0000000000000001"));
        assert!(!luhn_valid(""));
    }

    #[test]
    fn example_email_recognised() {
        assert!(is_example_email("alice@example.com"));
        assert!(is_example_email("bob@example.org"));
        assert!(is_example_email("user@anything.test"));
        assert!(is_example_email("noreply@anthropic.com"));
        assert!(is_example_email("no-reply@vendor.io"));
    }

    #[test]
    fn real_email_not_filtered() {
        assert!(!is_example_email("alice@acme.com"));
        assert!(!is_example_email("jane.doe@university.edu"));
    }

    #[test]
    fn placeholder_ssn_recognised() {
        assert!(is_placeholder_ssn(123, 45, 6789));
        assert!(is_placeholder_ssn(0, 12, 3456));
        assert!(is_placeholder_ssn(666, 12, 3456));
        assert!(is_placeholder_ssn(900, 12, 3456));
    }

    #[test]
    fn real_ssn_not_filtered() {
        assert!(!is_placeholder_ssn(456, 78, 9012));
    }

    #[test]
    fn private_ipv4_ranges() {
        assert!(is_private_ipv4(10, 0, 0, 1));
        assert!(is_private_ipv4(192, 168, 1, 1));
        assert!(is_private_ipv4(172, 20, 0, 1));
        assert!(is_private_ipv4(127, 0, 0, 1));
        assert!(is_private_ipv4(169, 254, 0, 1));
        assert!(!is_private_ipv4(8, 8, 8, 8));
        assert!(!is_private_ipv4(172, 32, 0, 1)); // outside 16-31
    }
}
