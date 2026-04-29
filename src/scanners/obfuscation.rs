//! Obfuscation / high-entropy payload scanner.
//!
//! Markdown skill bodies sometimes hide encoded instructions inside otherwise
//! prose-looking text — base64 blobs, hex strings, or arbitrary high-entropy
//! tokens that the LLM may decode and execute.  This scanner flags suspicious
//! tokens that appear **outside** fenced code blocks (where embedded payloads
//! legitimately belong) and **outside** URLs (which the
//! [`malicious_urls`](crate::scanners::malicious_urls) scanner already covers).
//!
//! | ID | Sev | What it checks |
//! |----|-----|----------------|
//! | `obfusc/O1-base64`       | Warning | Base64-charset token ≥ 60 chars (mixed-case + digit/`+/=`) |
//! | `obfusc/O2-hex-blob`     | Warning | Hex-charset token ≥ 40 chars |
//! | `obfusc/O3-high-entropy` | Warning | Any token ≥ 40 chars with Shannon entropy > 4.5 bits/char |
//!
//! # Scanned file types
//!
//! `*.md`, `*.markdown` only. Source files routinely contain base64/hex
//! literals (test fixtures, regex constants, embedded keys) and would
//! produce too many false positives.
//!
//! # What is excluded
//!
//! - **Fenced code blocks** (lines between triple-backtick fences) — encoded
//!   payloads inside code blocks are usually legitimate.
//! - **Inline code spans** (`` `...` ``) — stripped before tokenisation.
//! - **URLs** (`http://…`, `https://…`) — high-entropy by nature; flagged
//!   by `malicious_urls` instead.
//!
//! # Suppression
//!
//! Inline `# scan:ignore` comments (recognised on the same line) and
//! `.oxidized-agentic-audit-ignore` entries silence specific findings.
//!
//! # Why these thresholds
//!
//! - **Base64 ≥ 60 chars** — 45 decoded bytes; below that, base64-looking
//!   identifiers (UUIDs, short hashes) dominate. The mixed-class requirement
//!   filters out all-uppercase English words and acronyms.
//! - **Hex ≥ 40 chars** — SHA-1 length; below that, git short hashes and
//!   inline byte sequences are too common.
//! - **Entropy > 4.5 bits/char** — English prose averages 4.0–4.5 bits/char;
//!   random base64 ≈ 6.0; 4.5 is the inflection point that separates them.

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{collect_files, is_suppressed_inline, read_file_limited, RuleInfo, Scanner};
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

const MIN_BASE64_LEN: usize = 60;
const MIN_HEX_LEN: usize = 40;
const MIN_ENTROPY_LEN: usize = 40;
const ENTROPY_THRESHOLD: f64 = 4.5;

/// Strips backtick inline code spans (`` `...` ``) from a line.  Used to
/// remove inline literals before tokenising prose for entropy checks.
static RE_INLINE_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`[^`]*`").unwrap());

/// Strips http/https URLs from a line — those are flagged by malicious_urls,
/// not by the obfuscation scanner.
static RE_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"https?://\S+").unwrap());

/// Recognises a triple-backtick fence opener / closer at the start of a line.
/// Markdown technically allows tildes too, but skill files in this codebase
/// use backticks exclusively.
static RE_FENCE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*```").unwrap());

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
        scanner: "obfuscation".to_string(),
        snippet: Some(make_snippet(line)),
        suppressed: false,
        suppression_reason: None,
        remediation: Some(remediation.to_string()),
    });
}

/// Computes Shannon entropy in bits/char over the byte histogram of `s`.
/// ASCII-only — multi-byte UTF-8 bytes are counted individually, which is
/// fine because non-ASCII tokens are not the obfuscation target.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Returns `true` if every byte in `tok` is a base64 alphabet character
/// (`A-Z a-z 0-9 + / = -` — the `-` covers URL-safe base64).
fn is_base64_charset(tok: &str) -> bool {
    !tok.is_empty()
        && tok
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'-')
}

/// Returns `true` if `tok` contains at least an uppercase letter, a lowercase
/// letter, **and** a digit or one of `+ / =`. This filters out all-caps
/// English words like "ABCDEFGHIJ..." which match the base64 charset but
/// are not encoded payloads.
fn has_base64_diversity(tok: &str) -> bool {
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit_or_special = false;
    for b in tok.bytes() {
        if b.is_ascii_uppercase() {
            has_upper = true;
        } else if b.is_ascii_lowercase() {
            has_lower = true;
        } else if b.is_ascii_digit() || b == b'+' || b == b'/' || b == b'=' {
            has_digit_or_special = true;
        }
    }
    has_upper && has_lower && has_digit_or_special
}

/// Returns `true` if every byte in `tok` is a hex digit (`0-9 a-f A-F`).
fn is_hex_charset(tok: &str) -> bool {
    !tok.is_empty() && tok.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Built-in scanner for high-entropy / encoded payloads in markdown bodies.
///
/// See the [module-level documentation](self) for the full rule table.
pub struct ObfuscationScanner;

impl Scanner for ObfuscationScanner {
    fn name(&self) -> &'static str {
        "obfuscation"
    }

    fn description(&self) -> &'static str {
        "Obfuscation audit — flags base64, hex, and high-entropy payloads in markdown prose"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn scan(&self, path: &Path, _config: &Config) -> ScanResult {
        let start = Instant::now();
        let files = collect_files(path, &["md", "markdown"]);
        let mut findings = Vec::new();

        for file in &files {
            let content = match read_file_limited(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Track fenced-code-block state across lines.
            let mut in_fence = false;

            for (line_num, line) in content.lines().enumerate() {
                let line_num = line_num + 1;

                // Toggle fence state on triple-backtick lines.  The fence
                // line itself is never analysed.
                if RE_FENCE.is_match(line) {
                    in_fence = !in_fence;
                    continue;
                }
                if in_fence {
                    continue;
                }

                if is_suppressed_inline(line) {
                    continue;
                }

                // Remove inline code spans and URLs before tokenising.
                let stripped = RE_INLINE_CODE.replace_all(line, " ");
                let stripped = RE_URL.replace_all(&stripped, " ");

                for tok_raw in stripped.split_whitespace() {
                    // Strip common markdown punctuation that hugs tokens.
                    let tok = tok_raw.trim_matches(|c: char| {
                        matches!(
                            c,
                            '.' | ','
                                | ';'
                                | ':'
                                | '!'
                                | '?'
                                | '('
                                | ')'
                                | '['
                                | ']'
                                | '"'
                                | '\''
                                | '*'
                                | '_'
                        )
                    });

                    if tok.len() < MIN_ENTROPY_LEN {
                        continue;
                    }

                    // O1 — base64 charset, mixed-class, length ≥ 60.
                    if tok.len() >= MIN_BASE64_LEN
                        && is_base64_charset(tok)
                        && has_base64_diversity(tok)
                    {
                        emit(
                            &mut findings,
                            "obfusc/O1-base64",
                            Severity::Warning,
                            format!(
                                "Suspicious base64 token in prose ({} chars): {}…",
                                tok.len(),
                                &tok[..tok.len().min(24)]
                            ),
                            "Move encoded payloads inside fenced code blocks, or decode and inline the literal value the skill actually needs.",
                            file,
                            line_num,
                            line,
                        );
                        // Skip O2/O3 for this token — already classified.
                        continue;
                    }

                    // O2 — hex charset, length ≥ 40.
                    if tok.len() >= MIN_HEX_LEN && is_hex_charset(tok) {
                        emit(
                            &mut findings,
                            "obfusc/O2-hex-blob",
                            Severity::Warning,
                            format!(
                                "Suspicious hex blob in prose ({} chars): {}…",
                                tok.len(),
                                &tok[..tok.len().min(24)]
                            ),
                            "Hex blobs in prose may hide encoded payloads. If this is a hash or known constant, move it into a fenced code block.",
                            file,
                            line_num,
                            line,
                        );
                        continue;
                    }

                    // O3 — generic high-entropy token (≥ 40 chars, > 4.5 bits/char).
                    let entropy = shannon_entropy(tok);
                    if entropy > ENTROPY_THRESHOLD {
                        emit(
                            &mut findings,
                            "obfusc/O3-high-entropy",
                            Severity::Warning,
                            format!(
                                "High-entropy token in prose ({} chars, {:.2} bits/char): {}…",
                                tok.len(),
                                entropy,
                                &tok[..tok.len().min(24)]
                            ),
                            "High-entropy strings outside code blocks may carry obfuscated instructions. Move opaque payloads into fenced code blocks or replace with a clear identifier.",
                            file,
                            line_num,
                            line,
                        );
                    }
                }
            }
        }

        ScanResult {
            scanner_name: "obfuscation".to_string(),
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

/// Returns the [`RuleInfo`] catalogue for every obfuscation rule.
pub fn rules() -> Vec<RuleInfo> {
    vec![
        RuleInfo {
            id: "obfusc/O1-base64",
            severity: "warning",
            scanner: "obfuscation",
            message: "Suspicious base64 token in prose",
            remediation: "Move encoded payloads inside fenced code blocks or decode them.",
        },
        RuleInfo {
            id: "obfusc/O2-hex-blob",
            severity: "warning",
            scanner: "obfuscation",
            message: "Suspicious hex blob in prose",
            remediation: "Move hex blobs into fenced code blocks if they are legitimate.",
        },
        RuleInfo {
            id: "obfusc/O3-high-entropy",
            severity: "warning",
            scanner: "obfuscation",
            message: "High-entropy token in prose",
            remediation:
                "Move opaque payloads into fenced code blocks or replace with a clear identifier.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_uniform_alphabet_is_high() {
        // Pure base64 random data should be > 5.5 bits/char.
        let s = "aB3+/xYz9KmN7pQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlM";
        let e = shannon_entropy(s);
        assert!(e > 5.0, "expected entropy > 5.0 for varied base64, got {e}");
    }

    #[test]
    fn entropy_of_repetition_is_low() {
        let s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(shannon_entropy(s), 0.0);
    }

    #[test]
    fn entropy_of_english_prose_is_below_threshold() {
        // ~4.0–4.3 bits/char for typical English.
        let s = "the quick brown fox jumps over the lazy dog every single morning";
        let e = shannon_entropy(s);
        assert!(
            e < ENTROPY_THRESHOLD,
            "English prose should be below 4.5; got {e}"
        );
    }

    #[test]
    fn base64_charset_diversity_rejects_uppercase_only() {
        let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJ";
        assert!(is_base64_charset(s));
        assert!(
            !has_base64_diversity(s),
            "all-uppercase must not pass diversity gate"
        );
    }

    #[test]
    fn base64_charset_diversity_accepts_mixed() {
        let s = "VGhpc0lzU29tZUJhc2U2NEVuY29kZWREYXRhMTIzNDU2Nzg5MEFCQ0RFRkdISUo=";
        assert!(is_base64_charset(s));
        assert!(has_base64_diversity(s));
    }

    #[test]
    fn hex_charset_recognises_sha256() {
        let s = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(is_hex_charset(s));
        assert_eq!(s.len(), 64);
    }
}
