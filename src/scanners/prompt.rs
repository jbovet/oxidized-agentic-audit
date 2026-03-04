//! Prompt injection pattern scanner.
//!
//! Detects common prompt injection and manipulation patterns in skill
//! description files using pure Rust regex matching — no external tool
//! required.
//!
//! # Categories
//!
//! | Group | Severity | What it detects |
//! |-------|----------|-----------------|
//! | Direct Instruction Override | Error | "ignore previous instructions", "disregard", "forget" |
//! | Role Manipulation | Error/Warning | Role escalation, impersonation, restrictions bypass |
//! | Jailbreak Keywords | Error | DAN mode, developer mode, safety bypass |
//! | Data Exfiltration | Warning | Send data to endpoints, read credentials |
//! | Code/Shell Injection | Error | Execute arbitrary code, run without validation |
//! | Excessive Permissions | Warning | Mass deletion, sudo/root usage |
//! | System Prompt Extraction | Error | Reveal system prompt, initial instructions |
//! | Delimiter / Context Injection | Error | `<instructions>`, `[INST]`, `<\|im_start\|>` tokens |
//! | Fictional Framing | Warning | Hypothetical scenarios used to bypass policies |
//! | Priority Override | Warning | `OVERRIDE:`, `NEW TASK:`, `SYSTEM OVERRIDE:` |
//!
//! # Scanned file types
//!
//! `*.md`, `*.txt`, `*.yaml`, `*.yml`
//!
//! # Exclusions
//!
//! Well-known non-skill files (`LICENSE`, `CHANGELOG`, `NOTICE`, `AUTHORS`,
//! etc.) are automatically skipped to avoid false positives on legal
//! boilerplate.

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{collect_files, RuleInfo, Scanner};
use regex::RegexSet;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

/// A single regex-based prompt injection pattern rule.
///
/// Each pattern carries a rule identifier, severity level, human-readable
/// message, and remediation guidance.  The actual regex matching is done via
/// the [`PATTERN_SET`] `RegexSet` — the index in the `PATTERNS` array
/// corresponds to the index in the `RegexSet`.
struct PromptPattern {
    id: &'static str,
    severity: Severity,
    message: &'static str,
    remediation: &'static str,
}

static PATTERNS: &[PromptPattern] = &[
    // Direct Instruction Override
    PromptPattern {
        id: "prompt/override-ignore",
        severity: Severity::Error,
        message: "Prompt injection: instruction override — 'ignore previous instructions'",
        remediation: "Remove instruction override language from skill description",
    },
    PromptPattern {
        id: "prompt/override-disregard",
        severity: Severity::Error,
        message: "Prompt injection: instruction override — 'disregard previous instructions'",
        remediation: "Remove instruction override language from skill description",
    },
    PromptPattern {
        id: "prompt/override-forget",
        severity: Severity::Error,
        message: "Prompt injection: instruction override — 'forget everything'",
        remediation: "Remove instruction override language from skill description",
    },
    // Role Manipulation
    PromptPattern {
        id: "prompt/role-escalation",
        severity: Severity::Error,
        message: "Prompt injection: role escalation — assigns admin/root identity",
        remediation: "Remove role escalation language from skill description",
    },
    PromptPattern {
        id: "prompt/role-impersonation",
        severity: Severity::Warning,
        message: "Prompt injection: role impersonation — 'pretend to be different AI'",
        remediation: "Remove role impersonation language from skill description",
    },
    PromptPattern {
        id: "prompt/restrictions-bypass",
        severity: Severity::Error,
        message: "Prompt injection: restrictions bypass — 'act without restrictions'",
        remediation: "Remove restrictions bypass language from skill description",
    },
    // Jailbreak Keywords
    PromptPattern {
        id: "prompt/jailbreak-dan",
        severity: Severity::Error,
        message: "Prompt injection: DAN (Do Anything Now) jailbreak attempt",
        remediation: "Remove jailbreak keywords from skill description",
    },
    PromptPattern {
        id: "prompt/jailbreak-devmode",
        severity: Severity::Error,
        message: "Prompt injection: developer mode activation attempt",
        remediation: "Remove developer mode activation language from skill description",
    },
    PromptPattern {
        id: "prompt/jailbreak-bypass",
        severity: Severity::Error,
        message: "Prompt injection: safety/security bypass attempt",
        remediation: "Remove safety bypass language from skill description",
    },
    // Data Exfiltration
    PromptPattern {
        id: "prompt/exfil-send",
        severity: Severity::Warning,
        message: "Prompt injection: data exfiltration — send data to external endpoint",
        remediation: "Remove data exfiltration instructions from skill description",
    },
    PromptPattern {
        id: "prompt/exfil-read",
        severity: Severity::Warning,
        message: "Prompt injection: credential access — read passwords/secrets/tokens",
        remediation: "Remove credential access instructions from skill description",
    },
    // Code/Shell Injection
    PromptPattern {
        id: "prompt/inject-execute",
        severity: Severity::Error,
        message: "Prompt injection: arbitrary code execution instruction",
        remediation: "Remove arbitrary code execution instructions from skill description",
    },
    PromptPattern {
        id: "prompt/inject-unvalidated",
        severity: Severity::Error,
        message: "Prompt injection: run without validation instruction",
        remediation: "Remove unvalidated execution instructions from skill description",
    },
    // Excessive Permissions
    PromptPattern {
        id: "prompt/perm-delete-all",
        severity: Severity::Warning,
        message: "Prompt injection: mass deletion instruction",
        remediation: "Remove mass deletion instructions from skill description",
    },
    PromptPattern {
        id: "prompt/perm-sudo",
        severity: Severity::Warning,
        message: "Prompt injection: privilege escalation instruction (sudo/root)",
        remediation: "Remove privilege escalation instructions from skill description",
    },
    // System Prompt Extraction
    PromptPattern {
        id: "prompt/exfil-sysPrompt",
        severity: Severity::Error,
        message: "Prompt injection: system prompt extraction attempt",
        remediation:
            "Remove instructions that attempt to reveal the system prompt or base instructions",
    },
    // Delimiter / Context Injection
    PromptPattern {
        id: "prompt/inject-delimiter",
        severity: Severity::Error,
        message:
            "Prompt injection: model context delimiter — attempts to break instruction boundary",
        remediation: "Remove model-specific delimiter tokens from skill description",
    },
    // Fictional / Hypothetical Framing
    PromptPattern {
        id: "prompt/jailbreak-fiction",
        severity: Severity::Warning,
        message: "Prompt injection: fictional/hypothetical framing — common jailbreak technique",
        remediation:
            "Remove fictional framing language that may be used to bypass content policies",
    },
    // Priority Override Keywords
    PromptPattern {
        id: "prompt/override-priority",
        severity: Severity::Warning,
        message: "Prompt injection: priority override keyword — attempts to hijack AI attention",
        remediation:
            "Remove priority override keywords (OVERRIDE:, NEW TASK:) from skill description",
    },
];

/// File names (case-insensitive, extension stripped) that are never skill
/// instructions.  Scanning them for prompt injection produces only false
/// positives — legal boilerplate, changelogs, and attribution files cannot
/// actually instruct the AI at runtime.
const BENIGN_FILENAMES: &[&str] = &[
    "license",
    "licence",
    "changelog",
    "notice",
    "authors",
    "contributors",
    "copying",
    "patents",
    "version",
    "history",
];

/// Returns `true` when `path` is a known non-skill file that should be
/// excluded from prompt injection scanning.
fn is_benign_file(path: &Path) -> bool {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    BENIGN_FILENAMES.contains(&stem.as_str())
}

/// Pre-compiled set of all prompt injection regexes for O(1) first-pass filtering.
///
/// A line that matches nothing in this set can be skipped entirely without
/// testing each individual pattern.  The set indices correspond 1:1 to the
/// `PATTERNS` array.
static PATTERN_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", // P01
        r"(?i)disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?|guidelines?)", // P02
        r"(?i)forget\s+(everything|all|what)\s+(you|i)\s+(told|said|know)", // P03
        r"(?i)you\s+are\s+(now\s+)?(a|an|the)\s+(root|admin|system|super)\s*(user|administrator)?", // P04
        r"(?i)pretend\s+(to\s+be|you('re| are))\s+(a\s+)?(different|another|new)\s+(ai|assistant|system)", // P05
        r"(?i)act\s+as\s+(if\s+)?(you\s+)?(have\s+)?(no|without)\s+(restrictions?|limits?|rules?)", // P06
        r"(?i)(DAN|do\s+anything\s+now)\s+mode", // P07
        r"(?i)developer\s+mode\s+(enabled?|activate|on)", // P08
        r"(?i)bypass\s+(safety|security|content)\s+(filter|check|restriction)s?", // P09
        r"(?i)(send|post|transmit|exfiltrate)\s+.{0,30}(to|via)\s+(http|https|webhook|url|endpoint)", // P10
        r"(?i)(read|access|get|extract)\s+.{0,20}(password|secret|key|token|credential)s?", // P11
        r"(?i)execute\s+(any|arbitrary|untrusted)\s+(code|command|script)s?",               // P12
        r"(?i)run\s+.{0,20}without\s+(checking|validation|sanitiz)",                        // P13
        r"(?i)\b(delete|remove|rm)\s+(-[rfRF]{1,4}\s+)?(/|~/|\.\./|\*|all\b|everything\b)", // P14
        r"(?i)\bsudo\b|as\s+root|with\s+(elevated|admin)\s+priv",                           // P15
        r"(?i)(repeat|print|show|reveal|output|display)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|prompt\s+template|base\s+instructions?)", // P16
        r"(?i)(</?(?:instructions?|system|prompt)>|\[/?INST\]|<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>)", // P17
        r"(?i)(for\s+a\s+fictional\s+(story|scenario)|hypothetically\s+speaking|in\s+a\s+(simulation|hypothetical|fictional)\s+(scenario|world|context)|let('s|\s+us)\s+pretend|imagine\s+(you\s+are|that\s+you\b))", // P18
        r"(?i)\b(OVERRIDE|NEW\s+TASK|SYSTEM\s+OVERRIDE):\s*", // P19
    ])
    .unwrap()
});

/// Built-in scanner for prompt injection and manipulation vulnerabilities.
///
/// Scans `*.md`, `*.txt`, `*.yaml`, and `*.yml` files line-by-line against
/// a static table of compiled regexes covering 10 prompt injection
/// categories.  No external tool is required.
///
/// Files whose stem matches a known non-skill name (e.g. `LICENSE`,
/// `CHANGELOG`) are skipped automatically to prevent false positives on
/// legal boilerplate.
///
/// See the [module-level documentation](self) for the full category table.
pub struct PromptScanner;

impl Scanner for PromptScanner {
    fn name(&self) -> &'static str {
        "prompt"
    }

    fn description(&self) -> &'static str {
        "Prompt injection pattern scanner — pure Rust regex"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn scan(&self, path: &Path, _config: &Config) -> ScanResult {
        let start = Instant::now();
        let files = collect_files(path, &["md", "txt", "yaml", "yml"]);
        let mut findings = Vec::new();

        for file in &files {
            // Skip well-known non-skill files (LICENSE, CHANGELOG, NOTICE, …)
            // that are legal/attribution boilerplate and cannot inject prompts.
            if is_benign_file(file) {
                continue;
            }

            let content = match std::fs::read_to_string(file) {
                Ok(c) => c,
                Err(e) => {
                    findings.push(Finding {
                        rule_id: "prompt/read-error".to_string(),
                        message: format!("Could not read file: {}", e),
                        severity: Severity::Info,
                        file: Some(file.clone()),
                        line: None,
                        column: None,
                        scanner: "prompt".to_string(),
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

                // Fast O(1) pre-filter: skip the line entirely if no
                // pattern matches.  Only test individual regexes for
                // the matching indices.
                let matches = PATTERN_SET.matches(line);
                if !matches.matched_any() {
                    continue;
                }

                for idx in matches.iter() {
                    let pattern = &PATTERNS[idx];

                    // Use char_indices() to find a safe UTF-8 boundary;
                    // raw byte slicing at 117 would panic on multi-byte chars.
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
                        severity: pattern.severity,
                        file: Some(file.clone()),
                        line: Some(line_num),
                        column: None,
                        scanner: "prompt".to_string(),
                        snippet: Some(snippet.trim().to_string()),
                        suppressed: false,
                        suppression_reason: None,
                        remediation: Some(pattern.remediation.to_string()),
                    });
                }
            }
        }

        ScanResult {
            scanner_name: "prompt".to_string(),
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

/// Returns the [`RuleInfo`] catalogue for every prompt injection rule.
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
            scanner: "prompt",
            message: p.message,
            remediation: p.remediation,
        })
        .collect()
}
