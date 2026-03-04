//! SKILL.md frontmatter and metadata validator.
//!
//! Validates that every skill directory contains a well-formed `SKILL.md`
//! file with correct YAML frontmatter.  This is a built-in scanner — no
//! external tool is required.
//!
//! # Rules
//!
//! | ID | Sev | What it checks |
//! |----|-----|----------------|
//! | `frontmatter/missing-skill-md` | Error | `SKILL.md` must exist |
//! | `frontmatter/readme-in-skill` | Warning | `README.md` should not co-exist |
//! | `frontmatter/xml-in-frontmatter` | Error | No `<`/`>` in name or description |
//! | `frontmatter/name-reserved-word` | Error | Name must not contain "claude"/"anthropic" |
//! | `frontmatter/invalid-name-format` | Warning | Name must be lowercase-kebab-case |
//! | `frontmatter/name-too-long` | Warning | Name must be ≤ 64 characters |
//! | `frontmatter/name-too-vague` | Warning | Name must not be a generic term |
//! | `frontmatter/description-missing` | Warning | Description must exist and be non-empty |
//! | `frontmatter/description-too-long` | Warning | Description must be ≤ 1024 characters |
//! | `frontmatter/description-not-third-person` | Warning | Must use third person voice |
//! | `frontmatter/description-no-trigger` | Info | Should include "when to use" context |
//! | `frontmatter/bare-bash-tool` | Warning | `Bash` in allowed-tools must be scoped |
//! | `frontmatter/skill-body-too-long` | Warning | SKILL.md must be ≤ 500 lines |
//! | `frontmatter/windows-path` | Warning | No backslash paths |
//! | `frontmatter/time-sensitive-content` | Warning | No date-conditional language |
//! | `frontmatter/name-directory-mismatch` | Warning | `name` must match the directory name |
//!
//! # Frontmatter parsing
//!
//! A lightweight YAML subset parser is used instead of a full YAML crate.
//! It supports scalar `key: value` pairs, block sequences (`- item`), and
//! flow sequences (`[item, item]`), which covers everything the Claude
//! Skills specification requires.

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{RuleInfo, Scanner};
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Compile-time constants and static regexes
// ---------------------------------------------------------------------------

/// Generic terms that by themselves make a skill name meaningless.
const VAGUE_NAME_TERMS: &[&str] = &["helper", "utils", "tools", "data", "files", "documents"];

/// First/second-person patterns that indicate a description is not written in
/// third person, as required by the Claude agent skills best-practices guide.
static RE_FIRST_PERSON: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)\b(I can|I will|I'll|I am|I'm|you can|you should|you will|you'll)\b")
        .unwrap()
});

/// Windows-style backslash path separator.  Forward slashes should be used in
/// SKILL.md to ensure cross-platform compatibility.
static RE_WINDOWS_PATH: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"[a-zA-Z]:\\|[a-zA-Z0-9_][\\][a-zA-Z0-9_]").unwrap());

/// Date-conditional language that will become stale over time.
/// Matches patterns like "before August 2025", "after 2024", "as of January 2026".
static RE_TIME_SENSITIVE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)\b(before|after|until|since|as of|by)\s+\w*\s*(january|february|march|april|may|june|july|august|september|october|november|december)?\s*\d{4}\b",
    )
    .unwrap()
});

/// Keyword phrases that signal "when to use" context in a description.
/// The checklist requires descriptions to include both what a Skill does AND
/// when to invoke it so Claude can select the right Skill from many.
///
/// Covers both terse forms ("use when") and natural prose forms
/// ("should be used when", "when users want to…") to avoid false
/// positives on well-written descriptions.
const TRIGGER_PHRASES: &[&str] = &[
    "use when",
    "when the user",
    "when working with",
    "when asked",
    "when you need",
    "trigger",
    "invoke when",
    // Natural prose variants found in real skill descriptions
    "should be used when",
    "when users",
    "when a user",
    "use it when",
    "useful when",
];

// ---------------------------------------------------------------------------
// Lightweight YAML frontmatter parser
// ---------------------------------------------------------------------------
// We intentionally avoid a full YAML crate dependency.  SKILL.md frontmatter
// uses a tiny subset of YAML: scalar key/value pairs and simple sequences
// (block style `- item` or flow style `[item, item]`).  This covers everything
// the Claude Skills specification requires.

struct FrontmatterData {
    /// `name` field value and its 1-indexed line number.
    name: Option<(String, usize)>,
    /// `description` field value and its 1-indexed line number.
    description: Option<(String, usize)>,
    /// Each `allowed-tools` entry with its 1-indexed line number.
    allowed_tools: Vec<(String, usize)>,
}

/// Split a flow-sequence inner string on commas that are not inside parentheses.
///
/// `[Bash(find,ls), Write]` → `["Bash(find,ls)", "Write"]`
///
/// Plain `inner.split(',')` would produce `["Bash(find", "ls)", "Write"]`,
/// mangling the tool name and causing false-negative bare-bash-tool results.
fn split_flow_sequence(inner: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                items.push(inner[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = inner[start..].trim();
    if !last.is_empty() {
        items.push(last);
    }
    items
}

/// Parse the YAML frontmatter block from `content`.
///
/// Returns `None` if the file does not begin with `---`.  The parser reads
/// until the closing `---` line (or end-of-file) and extracts the three
/// fields the FrontmatterScanner cares about.
fn parse_frontmatter(content: &str) -> Option<FrontmatterData> {
    let mut lines = content.lines().enumerate();

    // First line must be the opening delimiter.
    let (_, first) = lines.next()?;
    if first.trim() != "---" {
        return None;
    }

    let mut name: Option<(String, usize)> = None;
    let mut description: Option<(String, usize)> = None;
    let mut allowed_tools: Vec<(String, usize)> = Vec::new();
    // The key whose block-sequence items we are currently collecting.
    let mut current_key: Option<String> = None;

    for (idx, line) in lines {
        let line_num = idx + 1; // lines().enumerate() is 0-indexed; add 1 for display

        // Closing delimiter ends the frontmatter block.
        if line.trim() == "---" {
            break;
        }

        // Block-sequence item: `  - value` (indented) or `- value` (unindented).
        let is_list_item = line.starts_with("  - ")
            || line.starts_with("\t- ")
            || (line.starts_with("- ") && current_key.is_some());
        if is_list_item {
            let item_raw = line
                .trim_start_matches(|c: char| c.is_whitespace())
                .strip_prefix("- ")
                .unwrap_or("")
                .trim();
            if let Some(ref key) = current_key {
                if key == "allowed-tools" && !item_raw.is_empty() {
                    allowed_tools.push((item_raw.to_string(), line_num));
                }
            }
            continue;
        }

        // Key: value line.
        if let Some((key, val)) = parse_kv(line) {
            current_key = Some(key.clone());
            let val = val.trim();
            match key.as_str() {
                "name" if !val.is_empty() => {
                    name = Some((val.to_string(), line_num));
                }
                "description" if !val.is_empty() => {
                    description = Some((val.to_string(), line_num));
                }
                "allowed-tools" => {
                    if val.starts_with('[') && val.ends_with(']') {
                        // Flow sequence: `allowed-tools: [Bash, Write]`
                        let inner = &val[1..val.len() - 1];
                        for t in split_flow_sequence(inner) {
                            if !t.is_empty() {
                                allowed_tools.push((t.to_string(), line_num));
                            }
                        }
                    } else if !val.is_empty() {
                        // Single scalar value: `allowed-tools: Bash`
                        allowed_tools.push((val.to_string(), line_num));
                    }
                    // Empty value means a block sequence follows — handled above.
                }
                _ => {}
            }
        }
    }

    Some(FrontmatterData {
        name,
        description,
        allowed_tools,
    })
}

/// Split a YAML `key: value` line into `(key, value)`.
///
/// Keys may contain letters, digits, hyphens, and underscores.  The value
/// is everything after the first `: ` (or `:` at end-of-line).
fn parse_kv(line: &str) -> Option<(String, String)> {
    // Only recognise lines that start with a non-whitespace character
    // (top-level keys).
    if line.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let colon_pos = line.find(':')?;
    let key = line[..colon_pos].trim().to_string();
    if key.is_empty() {
        return None;
    }
    let after = &line[colon_pos + 1..];
    // Strip optional leading space after the colon.
    let value = after.strip_prefix(' ').unwrap_or(after);
    Some((key, value.to_string()))
}

// ---------------------------------------------------------------------------
// emit helper
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn emit_fm(
    findings: &mut Vec<Finding>,
    id: &str,
    severity: Severity,
    message: &str,
    remediation: &str,
    file: &Path,
    line: Option<usize>,
) {
    findings.push(Finding {
        rule_id: id.to_string(),
        message: message.to_string(),
        severity,
        file: Some(file.to_path_buf()),
        line,
        column: None,
        scanner: "frontmatter".to_string(),
        snippet: None,
        suppressed: false,
        suppression_reason: None,
        remediation: Some(remediation.to_string()),
    });
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Rules 3a, 4, 5, 6 — validate the `name` field.
fn validate_name(findings: &mut Vec<Finding>, name_val: &str, name_line: usize, skill_md: &Path) {
    // Rule 3a: XML/HTML angle brackets in name (literal or HTML-entity form).
    // Checks both `<`/`>` and common encoded variants like &lt; &#60; &#x3C;
    // so that entity-encoded injection vectors are not silently accepted.
    let name_has_xml = name_val.contains('<')
        || name_val.contains('>')
        || name_val.contains("&lt;")
        || name_val.contains("&gt;")
        || name_val.contains("&#");
    if name_has_xml {
        emit_fm(
            findings,
            "frontmatter/xml-in-frontmatter",
            Severity::Error,
            "XML/HTML angle brackets in 'name' field — potential prompt injection vector",
            "Remove angle brackets from the name field",
            skill_md,
            Some(name_line),
        );
    }

    // Rule 4: Reserved brand words.
    let name_lower = name_val.to_lowercase();
    if name_lower.contains("claude") || name_lower.contains("anthropic") {
        emit_fm(
            findings,
            "frontmatter/name-reserved-word",
            Severity::Error,
            "Skill name contains reserved word 'claude' or 'anthropic'",
            "Choose a name that does not reference Claude or Anthropic brand names",
            skill_md,
            Some(name_line),
        );
    }

    // Rule 5: Must be lowercase-kebab-case.
    let has_uppercase = name_val.chars().any(|c| c.is_uppercase());
    let has_space = name_val.contains(' ');
    let has_underscore = name_val.contains('_');
    if has_uppercase || has_space || has_underscore {
        emit_fm(
            findings,
            "frontmatter/invalid-name-format",
            Severity::Warning,
            "Skill name contains uppercase letters, spaces, or underscores — use lowercase-kebab-case",
            "Rename to lowercase-kebab-case (e.g. 'my-skill' not 'My_Skill')",
            skill_md,
            Some(name_line),
        );
    }

    // Rule 6: Name length.
    if name_val.len() > 64 {
        emit_fm(
            findings,
            "frontmatter/name-too-long",
            Severity::Warning,
            &format!("Skill name is {} chars — maximum is 64", name_val.len()),
            "Shorten the skill name to 64 characters or fewer",
            skill_md,
            Some(name_line),
        );
    }

    // Rule 10: Vague generic name segment.
    // Split the kebab-case name into tokens and check each against the list of
    // terms that provide no meaningful signal about what a skill does.
    let name_lower = name_val.to_lowercase();
    let has_vague = name_lower
        .split('-')
        .any(|seg| VAGUE_NAME_TERMS.contains(&seg));
    if has_vague {
        emit_fm(
            findings,
            "frontmatter/name-too-vague",
            Severity::Warning,
            "Skill name uses a vague generic term — choose a descriptive name",
            "Rename to something specific (e.g. 'github-pr-creator' not 'tools')",
            skill_md,
            Some(name_line),
        );
    }
}

/// Rules 3b, 7, 8 — validate the `description` field.
fn validate_description(
    findings: &mut Vec<Finding>,
    description: Option<&(String, usize)>,
    skill_md: &Path,
) {
    // Rule 7: Unpack to a non-empty value, or emit missing and return.
    // The guard pattern handles both the absent (`None`) and empty-string
    // (`Some(("", _))`) cases in one branch, extracting the line hint when
    // available so the finding points at the actual `description:` line.
    let (desc_val, desc_line) = match description {
        Some((v, l)) if !v.trim().is_empty() => (v.as_str(), *l),
        other => {
            emit_fm(
                findings,
                "frontmatter/description-missing",
                Severity::Warning,
                "Skill description is missing or empty",
                "Add a meaningful description field to SKILL.md frontmatter",
                skill_md,
                other.map(|(_, l)| *l),
            );
            return;
        }
    };

    // Rule 3b: XML/HTML angle brackets in description (literal or HTML-entity form).
    let desc_has_xml = desc_val.contains('<')
        || desc_val.contains('>')
        || desc_val.contains("&lt;")
        || desc_val.contains("&gt;")
        || desc_val.contains("&#");
    if desc_has_xml {
        emit_fm(
            findings,
            "frontmatter/xml-in-frontmatter",
            Severity::Error,
            "XML/HTML angle brackets in 'description' field — potential prompt injection vector",
            "Remove angle brackets from the description field",
            skill_md,
            Some(desc_line),
        );
    }

    // Rule 8: Description too long.
    if desc_val.len() > 1024 {
        emit_fm(
            findings,
            "frontmatter/description-too-long",
            Severity::Warning,
            &format!("Description is {} chars — maximum is 1024", desc_val.len()),
            "Shorten the description to 1024 characters or fewer",
            skill_md,
            Some(desc_line),
        );
    }

    // Rule 11: Description must be written in third person.
    // The Claude agent skills best-practices guide explicitly warns against using
    // first/second person ("I can", "you can", etc.).
    if RE_FIRST_PERSON.is_match(desc_val) {
        emit_fm(
            findings,
            "frontmatter/description-not-third-person",
            Severity::Warning,
            "Description uses first or second person — use third person (e.g. 'This skill...')",
            "Rewrite the description in third person",
            skill_md,
            Some(desc_line),
        );
    }

    // Rule 14: Description should include "when to use" context.
    // The checklist requires descriptions to say both *what* the Skill does and
    // *when* to invoke it.  Claude selects from potentially 100+ Skills using
    // the description alone, so trigger context is critical for discovery.
    let desc_lower = desc_val.to_lowercase();
    let has_trigger = TRIGGER_PHRASES.iter().any(|p| desc_lower.contains(p));
    if !has_trigger {
        emit_fm(
            findings,
            "frontmatter/description-no-trigger",
            Severity::Info,
            "Description doesn't include 'when to use' context — add trigger phrases (e.g. 'Use when...')",
            "Append: 'Use when <specific trigger condition>.' to the description",
            skill_md,
            Some(desc_line),
        );
    }
}

/// Rule 9 — validate `allowed-tools` entries.
fn validate_allowed_tools(
    findings: &mut Vec<Finding>,
    allowed_tools: &[(String, usize)],
    skill_md: &Path,
) {
    for (tool, tool_line) in allowed_tools {
        let trimmed = tool.trim();
        // Bare `Bash` without a scope parenthesis grants unrestricted shell access.
        if trimmed.eq_ignore_ascii_case("bash") && !trimmed.contains('(') {
            emit_fm(
                findings,
                "frontmatter/bare-bash-tool",
                Severity::Warning,
                "Unscoped 'Bash' in allowed-tools grants unrestricted shell access",
                "Scope Bash to specific commands: e.g., Bash(find,ls,cat,grep)",
                skill_md,
                Some(*tool_line),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Built-in scanner for `SKILL.md` frontmatter and metadata validation.
///
/// Checks for the existence of `SKILL.md`, parses its YAML frontmatter,
/// and validates the `name`, `description`, and `allowed-tools` fields
/// against 15 rules derived from the Claude agent skills best-practices
/// guide.  Also inspects the body for excessive length, Windows-style
/// paths, and time-sensitive language.
///
/// See the [module-level documentation](self) for the full rule table.
pub struct FrontmatterScanner;

impl Scanner for FrontmatterScanner {
    fn name(&self) -> &'static str {
        "frontmatter"
    }

    fn description(&self) -> &'static str {
        "SKILL.md frontmatter and allowed-tools audit"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn scan(&self, path: &Path, _config: &Config) -> ScanResult {
        let start = Instant::now();
        let skill_md = path.join("SKILL.md");
        let mut findings = Vec::new();

        // Rule 1: SKILL.md must exist.
        if !skill_md.exists() {
            emit_fm(
                &mut findings,
                "frontmatter/missing-skill-md",
                Severity::Error,
                "SKILL.md not found in skill root",
                "Create a SKILL.md file in the skill root with required frontmatter fields",
                &skill_md,
                None,
            );
            return ScanResult {
                scanner_name: self.name().to_string(),
                findings,
                files_scanned: 0,
                skipped: false,
                skip_reason: None,
                error: None,
                duration_ms: start.elapsed().as_millis() as u64,
                scanner_score: None,
                scanner_grade: None,
            };
        }

        // Rule 2: README.md should not be present inside the skill folder.
        let readme = path.join("README.md");
        if readme.exists() {
            emit_fm(
                &mut findings,
                "frontmatter/readme-in-skill",
                Severity::Warning,
                "README.md found in skill folder — use the description field in SKILL.md instead",
                "Remove README.md and move documentation into the SKILL.md description field; README.md is not used by the agent runtime",
                &readme,
                None,
            );
        }

        // Read SKILL.md.
        let content = match std::fs::read_to_string(&skill_md) {
            Ok(c) => c,
            Err(e) => {
                return ScanResult {
                    scanner_name: self.name().to_string(),
                    findings,
                    files_scanned: 1,
                    skipped: false,
                    skip_reason: None,
                    error: Some(format!("Failed to read SKILL.md: {e}")),
                    duration_ms: start.elapsed().as_millis() as u64,
                    scanner_score: None,
                    scanner_grade: None,
                };
            }
        };

        // Parse frontmatter (may be absent if SKILL.md has no `---` block).
        let fm = parse_frontmatter(&content);

        // Name and allowed-tools only exist when frontmatter is present.
        if let Some(ref fm) = fm {
            if let Some((ref name_val, name_line)) = fm.name {
                validate_name(&mut findings, name_val, name_line, &skill_md);

                // Rule 16: name must match the containing directory name.
                // The Claude skill spec requires the `name` field to match the
                // directory so registries and runtimes can locate the skill by name.
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if name_val != dir_name {
                        emit_fm(
                            &mut findings,
                            "frontmatter/name-directory-mismatch",
                            Severity::Warning,
                            &format!(
                                "Skill name '{}' does not match directory name '{}'",
                                name_val, dir_name
                            ),
                            "Rename the skill directory to match the 'name' field, or update 'name' to match the directory",
                            &skill_md,
                            Some(name_line),
                        );
                    }
                }
            }
            validate_allowed_tools(&mut findings, &fm.allowed_tools, &skill_md);
        }

        // Description validation runs unconditionally — it covers both the
        // no-frontmatter case and the frontmatter-but-no-description case.
        validate_description(
            &mut findings,
            fm.as_ref().and_then(|f| f.description.as_ref()),
            &skill_md,
        );

        // Rule 12: SKILL.md body length.
        // The best-practices guide recommends keeping SKILL.md under 500 lines to
        // stay within context window budgets and keep skills focused.
        let line_count = content.lines().count();
        if line_count > 500 {
            emit_fm(
                &mut findings,
                "frontmatter/skill-body-too-long",
                Severity::Warning,
                &format!("SKILL.md is {line_count} lines — maximum is 500"),
                "Trim SKILL.md to 500 lines or fewer",
                &skill_md,
                None,
            );
        }

        // Rule 13: Windows-style backslash paths.
        // Forward slashes should be used in SKILL.md for cross-platform compatibility.
        // Report only the first occurrence to keep output concise.
        if let Some((idx, _)) = content
            .lines()
            .enumerate()
            .find(|(_, line)| RE_WINDOWS_PATH.is_match(line))
        {
            emit_fm(
                &mut findings,
                "frontmatter/windows-path",
                Severity::Warning,
                "Windows-style backslash path in SKILL.md — use forward slashes",
                "Replace backslash paths with forward slashes (e.g. path/to/file)",
                &skill_md,
                Some(idx + 1),
            );
        }

        // Rule 15: Time-sensitive content.
        // Date-based conditionals like "before August 2025" become stale and can
        // cause Claude to follow outdated instructions.  The best-practices guide
        // recommends using an "old patterns" section instead.
        if let Some((idx, _)) = content
            .lines()
            .enumerate()
            .find(|(_, line)| RE_TIME_SENSITIVE.is_match(line))
        {
            emit_fm(
                &mut findings,
                "frontmatter/time-sensitive-content",
                Severity::Warning,
                "SKILL.md contains time-sensitive date condition — this will become stale",
                "Move dated content into an 'Old patterns' collapsible section instead",
                &skill_md,
                Some(idx + 1),
            );
        }

        ScanResult {
            scanner_name: self.name().to_string(),
            findings,
            files_scanned: 1,
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

/// Returns the [`RuleInfo`] catalogue for every frontmatter validation rule.
///
/// Used by the `list-rules` and `explain` CLI commands to display rule
/// metadata without running a scan.
pub fn rules() -> Vec<RuleInfo> {
    vec![
        RuleInfo {
            id: "frontmatter/missing-skill-md",
            severity: "error",
            scanner: "frontmatter",
            message: "SKILL.md not found in skill root",
            remediation:
                "Create a SKILL.md file in the skill root with required frontmatter fields",
        },
        RuleInfo {
            id: "frontmatter/readme-in-skill",
            severity: "warning",
            scanner: "frontmatter",
            message: "README.md found in skill folder — use the description field instead",
            remediation:
                "Remove README.md and move documentation into the SKILL.md description field",
        },
        RuleInfo {
            id: "frontmatter/xml-in-frontmatter",
            severity: "error",
            scanner: "frontmatter",
            message:
                "XML/HTML angle brackets in frontmatter field — potential prompt injection vector",
            remediation: "Remove angle brackets from the name or description fields",
        },
        RuleInfo {
            id: "frontmatter/name-reserved-word",
            severity: "error",
            scanner: "frontmatter",
            message: "Skill name contains reserved word 'claude' or 'anthropic'",
            remediation: "Choose a name that does not reference Claude or Anthropic brand names",
        },
        RuleInfo {
            id: "frontmatter/invalid-name-format",
            severity: "warning",
            scanner: "frontmatter",
            message: "Skill name must be lowercase-kebab-case",
            remediation: "Rename to lowercase-kebab-case (e.g. 'my-skill' not 'My_Skill')",
        },
        RuleInfo {
            id: "frontmatter/name-too-long",
            severity: "warning",
            scanner: "frontmatter",
            message: "Skill name exceeds 64 characters",
            remediation: "Shorten the skill name to 64 characters or fewer",
        },
        RuleInfo {
            id: "frontmatter/description-missing",
            severity: "warning",
            scanner: "frontmatter",
            message: "Skill description is missing or empty",
            remediation: "Add a meaningful description field to SKILL.md frontmatter",
        },
        RuleInfo {
            id: "frontmatter/description-too-long",
            severity: "warning",
            scanner: "frontmatter",
            message: "Description exceeds 1024 characters",
            remediation: "Shorten the description to 1024 characters or fewer",
        },
        RuleInfo {
            id: "frontmatter/bare-bash-tool",
            severity: "warning",
            scanner: "frontmatter",
            message: "Unscoped 'Bash' in allowed-tools grants unrestricted shell access",
            remediation: "Scope Bash to specific commands: e.g., Bash(find,ls,cat,grep)",
        },
        RuleInfo {
            id: "frontmatter/name-too-vague",
            severity: "warning",
            scanner: "frontmatter",
            message: "Skill name uses a vague generic term",
            remediation: "Choose a descriptive name (e.g. 'github-pr-creator' not 'tools')",
        },
        RuleInfo {
            id: "frontmatter/description-not-third-person",
            severity: "warning",
            scanner: "frontmatter",
            message: "Description uses first or second person instead of third person",
            remediation: "Rewrite the description in third person (e.g. 'This skill creates...')",
        },
        RuleInfo {
            id: "frontmatter/skill-body-too-long",
            severity: "warning",
            scanner: "frontmatter",
            message: "SKILL.md exceeds 500 lines",
            remediation: "Trim SKILL.md to 500 lines or fewer",
        },
        RuleInfo {
            id: "frontmatter/windows-path",
            severity: "warning",
            scanner: "frontmatter",
            message: "Windows-style backslash path in SKILL.md — use forward slashes",
            remediation: "Replace backslash paths with forward slashes (e.g. path/to/file)",
        },
        RuleInfo {
            id: "frontmatter/description-no-trigger",
            severity: "info",
            scanner: "frontmatter",
            message: "Description doesn't include 'when to use' context",
            remediation: "Append 'Use when <specific trigger condition>.' to the description",
        },
        RuleInfo {
            id: "frontmatter/time-sensitive-content",
            severity: "warning",
            scanner: "frontmatter",
            message: "SKILL.md contains a time-sensitive date condition that will become stale",
            remediation: "Move dated content into an 'Old patterns' collapsible section",
        },
        RuleInfo {
            id: "frontmatter/name-directory-mismatch",
            severity: "warning",
            scanner: "frontmatter",
            message: "Skill name does not match the containing directory name",
            remediation: "Rename the skill directory to match the 'name' field, or update 'name' to match the directory",
        },
    ]
}
