//! Script-mixing and homoglyph scanner.
//!
//! Detects mixed Unicode scripts and visually-confusing character substitutions
//! commonly used in prompt-injection and supply-chain attacks. This includes:
//!
//! - **Homoglyphs**: Greek ο (U+03BF) masquerading as Latin o, Cyrillic а (U+0430)
//!   as Latin a, etc.
//! - **Script mixing**: Cyrillic characters embedded in Latin text (especially in
//!   identifier-like contexts such as frontmatter names/descriptions).
//! - **Bidirectional formatting**: RTL-override (U+202E), LTR-override (U+202D),
//!   and other control characters that can reverse text direction.
//!
//! | ID | Sev | What it checks |
//! |----|-----|----------------|
//! | `script/SM1-homoglyph` | Warning | Visually-confusing homoglyph substitution |
//! | `script/SM2-bidi-override` | Error | Bidirectional text-direction override marks |
//! | `script/SM3-mixed-scripts` | Warning | Cyrillic/Greek mixed with Latin in identifiers |
//!
//! # Scanned file types
//!
//! `SKILL.md` and `AGENT.md` frontmatter (name, description, compatibility fields)
//! and `*.md` skill body content. Source files (`*.rs`, `*.sh`, etc.) are excluded
//! because they routinely contain legitimate Unicode escape sequences.

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{is_suppressed_inline, read_file_limited, RuleInfo, Scanner};
use std::path::Path;
use std::time::Instant;

// ============================================================================
// Homoglyph mappings: characters that look similar but are from different
// scripts, commonly substituted in phishing and prompt-injection attacks.
// ============================================================================

/// Returns true if the character is a known homoglyph substitute.
/// Maps to a human-readable name of the real character it mimics.
fn get_homoglyph_info(c: char) -> Option<(&'static str, &'static str)> {
    match c {
        // Greek letters masquerading as Latin
        'ο' => Some(("Greek o", "Latin 'o' (U+006F)")), // U+03BF
        'ν' => Some(("Greek nu", "Latin 'v' (U+0076)")), // U+03BD
        'τ' => Some(("Greek tau", "Latin 't' (U+0074)")), // U+03C4
        'ρ' => Some(("Greek rho", "Latin 'p' (U+0070)")), // U+03C1
        'α' => Some(("Greek alpha", "Latin 'a' (U+0061)")), // U+03B1
        'β' => Some(("Greek beta", "Latin 'b' (U+0062)")), // U+03B2
        'ε' => Some(("Greek epsilon", "Latin 'e' (U+0065)")), // U+03B5
        'ζ' => Some(("Greek zeta", "Latin 'z' (U+007A)")), // U+03B6
        'η' => Some(("Greek eta", "Latin 'n' (U+006E)")), // U+03B7
        'κ' => Some(("Greek kappa", "Latin 'k' (U+006B)")), // U+03BA
        'λ' => Some(("Greek lambda", "Latin 'l' (U+006C)")), // U+03BB
        'μ' => Some(("Greek mu", "Latin 'u' (U+0075)")), // U+03BC
        'σ' => Some(("Greek sigma", "Latin 's' (U+0073)")), // U+03C3
        'ς' => Some(("Greek final sigma", "Latin 's' (U+0073)")), // U+03C2
        'χ' => Some(("Greek chi", "Latin 'x' (U+0078)")), // U+03C7
        'ψ' => Some(("Greek psi", "Latin 'y' (U+0079)")), // U+03C8

        // Cyrillic letters masquerading as Latin
        'а' => Some(("Cyrillic a", "Latin 'a' (U+0061)")), // U+0430
        'е' => Some(("Cyrillic e", "Latin 'e' (U+0065)")), // U+0435
        'о' => Some(("Cyrillic o", "Latin 'o' (U+006F)")), // U+043E
        'р' => Some(("Cyrillic r", "Latin 'p' (U+0070)")), // U+0440
        'с' => Some(("Cyrillic s", "Latin 's' (U+0073)")), // U+0441
        'у' => Some(("Cyrillic u", "Latin 'u' (U+0075)")), // U+0443
        'х' => Some(("Cyrillic h", "Latin 'h' (U+0068)")), // U+0445
        'н' => Some(("Cyrillic n", "Latin 'n' (U+006E)")), // U+043D
        'в' => Some(("Cyrillic v", "Latin 'b' (U+0062)")), // U+0432
        'м' => Some(("Cyrillic m", "Latin 'm' (U+006D)")), // U+043C

        // Latin Extended / IPA that look like ASCII
        'ɪ' => Some(("Latin Small Capital I", "Latin 'i' (U+0069)")), // U+026A
        'ᴛ' => Some(("Latin Small Capital T", "Latin 't' (U+0074)")), // U+1D1B

        _ => None,
    }
}

/// Returns true if character is Cyrillic.
fn is_cyrillic(c: char) -> bool {
    matches!(c as u32, 0x0400..=0x04FF)
}

/// Returns true if character is Greek.
fn is_greek(c: char) -> bool {
    matches!(c as u32, 0x0370..=0x03FF)
}

/// Returns true if character is Latin (basic ASCII or extended Latin).
fn is_latin(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c as u32, 0x0100..=0x024F)
}

/// Returns true if character is a bidirectional control character.
fn is_bidi_override(c: char) -> bool {
    matches!(
        c as u32,
        0x202A // Left-to-Right Embedding
        | 0x202B // Right-to-Left Embedding
        | 0x202C // Pop Directional Formatting
        | 0x202D // Left-to-Right Override
        | 0x202E // Right-to-Left Override
        | 0x2066 // Left-to-Right Isolate
        | 0x2067 // Right-to-Left Isolate
        | 0x2068 // First Strong Isolate
        | 0x2069 // Pop Directional Isolate
    )
}

/// Analyze a string for script-mixing issues.
/// Returns (has_homoglyphs, has_bidi, has_mixed_scripts).
fn analyze_string(s: &str) -> (bool, bool, bool) {
    let mut has_homoglyphs = false;
    let mut has_bidi = false;
    let mut has_mixed_scripts = false;

    let mut has_latin = false;
    let mut has_cyrillic = false;
    let mut has_greek = false;

    for c in s.chars() {
        if get_homoglyph_info(c).is_some() {
            has_homoglyphs = true;
        }
        if is_bidi_override(c) {
            has_bidi = true;
        }

        if is_latin(c) {
            has_latin = true;
        }
        if is_cyrillic(c) {
            has_cyrillic = true;
        }
        if is_greek(c) {
            has_greek = true;
        }
    }

    // Mixed scripts: Latin mixed with Cyrillic or Greek.
    if (has_greek || has_cyrillic) && has_latin {
        has_mixed_scripts = true;
    }

    (has_homoglyphs, has_bidi, has_mixed_scripts)
}

/// Scan a single file and collect findings.
fn scan_file(file: &Path, findings: &mut Vec<Finding>) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_file_limited(file)?;

    // Determine if this is a frontmatter file (SKILL.md or AGENT.md)
    let is_frontmatter_file = file
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == "SKILL.md" || n == "AGENT.md")
        .unwrap_or(false);

    if is_frontmatter_file {
        // Parse and scan frontmatter fields.
        scan_frontmatter(&content, file, findings);
    }

    // Scan markdown body (lines outside frontmatter).
    scan_markdown_body(&content, file, findings);

    Ok(())
}

/// Parse frontmatter and scan name, description, and compatibility fields.
fn scan_frontmatter(content: &str, file: &Path, findings: &mut Vec<Finding>) {
    let mut lines = content.lines().enumerate();

    // First line must be the opening `---`.
    let Some((_, first)) = lines.next() else {
        return;
    };
    if first.trim() != "---" {
        return;
    }

    for (idx, line) in lines {
        let line_num = idx + 1;

        if line.trim() == "---" {
            // End of frontmatter
            break;
        }

        // Skip comments
        if line.trim().starts_with('#') {
            continue;
        }

        // Extract field value.
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim();

            // Skip empty values
            if value.is_empty() {
                continue;
            }

            // Only scan frontmatter fields that are identifiers or descriptions.
            if matches!(key.as_str(), "name" | "description" | "compatibility") {
                if is_suppressed_inline(line) {
                    continue;
                }

                check_script_issues(
                    value, file, line_num, line, findings, true, // is_frontmatter
                );
            }
        }
    }
}

/// Scan markdown body (all lines, including those in code blocks).
/// Code blocks are excluded to avoid false positives in examples.
fn scan_markdown_body(content: &str, file: &Path, findings: &mut Vec<Finding>) {
    let mut in_code_block = false;

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;

        // Track code blocks.
        if line.trim().starts_with("```") {
            in_code_block = !in_code_block;
            continue;
        }

        // Skip lines inside code blocks and suppressed lines.
        if in_code_block || is_suppressed_inline(line) {
            continue;
        }

        // Skip frontmatter.
        if line.trim() == "---" {
            // Naive approach: toggle a flag. This works for well-formed files.
            continue;
        }

        check_script_issues(line, file, line_num, line, findings, false);
    }
}

/// Check a single line for script-mixing issues.
fn check_script_issues(
    text: &str,
    file: &Path,
    line_num: usize,
    full_line: &str,
    findings: &mut Vec<Finding>,
    is_frontmatter: bool,
) {
    let (has_homoglyphs, has_bidi, has_mixed_scripts) = analyze_string(text);

    if has_bidi {
        findings.push(Finding {
            rule_id: "script/SM2-bidi-override".to_string(),
            message: "Bidirectional text-direction override mark detected (potential RTL attack)"
                .to_string(),
            severity: Severity::Error,
            file: Some(file.to_path_buf()),
            line: Some(line_num),
            column: None,
            scanner: "script_mixing".to_string(),
            snippet: Some(make_snippet(full_line)),
            suppressed: false,
            suppression_reason: None,
            remediation: Some(
                "Remove bidirectional override characters. These are rarely needed in legitimate \
                 skill content and are a common vector for prompt-injection attacks."
                    .to_string(),
            ),
        });
    }

    if has_homoglyphs {
        let (fake_name, real_char) = get_homoglyph_info(
            text.chars()
                .find(|c| get_homoglyph_info(*c).is_some())
                .unwrap(),
        )
        .unwrap();

        findings.push(Finding {
            rule_id: "script/SM1-homoglyph".to_string(),
            message: format!(
                "Homoglyph detected: {} masquerading as {}",
                fake_name, real_char
            ),
            severity: Severity::Warning,
            file: Some(file.to_path_buf()),
            line: Some(line_num),
            column: None,
            scanner: "script_mixing".to_string(),
            snippet: Some(make_snippet(full_line)),
            suppressed: false,
            suppression_reason: None,
            remediation: Some(
                "Replace the character with its ASCII equivalent. Homoglyphs are often used \
                 to bypass filters or create visually-deceptive prompts."
                    .to_string(),
            ),
        });
    }

    // For mixed-script detection, be stricter in frontmatter (identifiers should be ASCII).
    if has_mixed_scripts && is_frontmatter {
        findings.push(Finding {
            rule_id: "script/SM3-mixed-scripts".to_string(),
            message: "Mixed scripts detected in frontmatter field (potential obfuscation attack)"
                .to_string(),
            severity: Severity::Warning,
            file: Some(file.to_path_buf()),
            line: Some(line_num),
            column: None,
            scanner: "script_mixing".to_string(),
            snippet: Some(make_snippet(full_line)),
            suppressed: false,
            suppression_reason: None,
            remediation: Some(
                "Skill identifiers (name, compatibility) should use only ASCII Latin characters. \
                 Replace non-Latin characters with their ASCII equivalents."
                    .to_string(),
            ),
        });
    }
}

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

/// Built-in scanner for script-mixing and homoglyph attacks.
///
/// See the [module-level documentation](self) for the full rule table.
pub struct ScriptMixingScanner;

impl Scanner for ScriptMixingScanner {
    fn name(&self) -> &'static str {
        "script_mixing"
    }

    fn description(&self) -> &'static str {
        "Script-mixing scanner — detects homoglyphs and bidirectional text attacks"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn scan(&self, path: &Path, _config: &Config) -> ScanResult {
        let start = Instant::now();
        let mut findings = Vec::new();

        // Collect markdown and frontmatter files.
        let mut candidates = Vec::new();

        // Scan SKILL.md and AGENT.md files (frontmatter).
        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n == "SKILL.md" || n == "AGENT.md")
                    .unwrap_or(false)
            })
        {
            candidates.push(entry.path().to_path_buf());
        }

        // Scan all markdown files.
        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|e| e == "md" || e == "markdown")
                    .unwrap_or(false)
            })
        {
            let p = entry.path().to_path_buf();
            // Skip if already added as SKILL.md / AGENT.md
            if !candidates.contains(&p) {
                candidates.push(p);
            }
        }

        let files_scanned = candidates.len();

        for file in candidates {
            if scan_file(&file, &mut findings).is_err() {
                // Silently skip files that can't be read
                continue;
            }
        }

        ScanResult {
            scanner_name: self.name().to_string(),
            findings,
            files_scanned,
            skipped: false,
            skip_reason: None,
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
            scanner_score: None,
            scanner_grade: None,
        }
    }
}

/// Returns metadata for all rules detected by this scanner.
pub fn rules() -> Vec<RuleInfo> {
    vec![
        RuleInfo {
            id: "script/SM1-homoglyph",
            severity: "warning",
            scanner: "script_mixing",
            message: "Visually-confusing homoglyph substitution (e.g., Greek ο as Latin o)",
            remediation: "Replace the character with its ASCII equivalent. Homoglyphs are often \
                          used to bypass filters or create visually-deceptive prompts.",
        },
        RuleInfo {
            id: "script/SM2-bidi-override",
            severity: "error",
            scanner: "script_mixing",
            message: "Bidirectional text-direction override marks (RTL-override, etc.)",
            remediation: "Remove bidirectional override characters. These are rarely needed in \
                          legitimate skill content and are a common vector for prompt-injection \
                          attacks.",
        },
        RuleInfo {
            id: "script/SM3-mixed-scripts",
            severity: "warning",
            scanner: "script_mixing",
            message: "Mixed Unicode scripts in frontmatter identifiers",
            remediation: "Skill identifiers should use only ASCII Latin characters. Replace \
                          non-Latin characters with their ASCII equivalents.",
        },
    ]
}
