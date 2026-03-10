//! AGENT.md frontmatter and metadata validator.
//!
//! Validates that every agent directory contains a well-formed `AGENT.md`
//! file with correct YAML frontmatter.  This is a built-in scanner — no
//! external tool is required.
//!
//! # Rules
//!
//! | ID | Sev | What it checks |
//! |----|-----|----------------|
//! | `agent/missing-agent-md`            | Error   | `AGENT.md` must exist |
//! | `agent/xml-in-frontmatter`          | Error   | No `<`/`>` in name, description, or system-prompt |
//! | `agent/name-reserved-word`          | Error   | Name must not contain "claude"/"anthropic" |
//! | `agent/system-prompt-injection`     | Error   | No prompt-injection patterns in system-prompt |
//! | `agent/invalid-name-format`         | Warning | Name must be lowercase-kebab-case |
//! | `agent/name-too-long`               | Warning | Name must be ≤ 64 characters |
//! | `agent/name-too-vague`              | Warning | Name must not be a generic term |
//! | `agent/description-missing`         | Warning | Description must exist and be non-empty |
//! | `agent/description-too-long`        | Warning | Description must be ≤ 1024 characters |
//! | `agent/description-not-third-person`| Warning | Must use third person voice |
//! | `agent/model-not-specified`         | Warning | `model` field should be explicit |
//! | `agent/bare-tool`                   | Warning | `Bash` in tools must be scoped |
//! | `agent/system-prompt-too-long`      | Warning | `system-prompt` must be ≤ 8000 characters |
//! | `agent/unconstrained-mcp-server`    | Warning | MCP servers should have an explicit tool allowlist |
//! | `agent/agent-body-too-long`         | Warning | AGENT.md must be ≤ 500 lines |
//! | `agent/windows-path`                | Warning | No backslash paths |
//! | `agent/time-sensitive-content`      | Warning | No date-conditional language |
//! | `agent/name-directory-mismatch`     | Warning | `name` must match the directory name |
//! | `agent/description-no-trigger`      | Info    | Should include "when to use" context |
//! | `agent/name-leading-trailing-hyphen`| Warning | Name must not start or end with `-` |
//! | `agent/name-consecutive-hyphens`    | Warning | Name must not contain `--` |

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::shared::{
    RE_FIRST_PERSON, RE_TIME_SENSITIVE, RE_WINDOWS_PATH, TRIGGER_PHRASES, VAGUE_NAME_TERMS,
};
use crate::scanners::{read_file_limited, RuleInfo, Scanner};
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Prompt-injection patterns specific to system-prompt fields
// ---------------------------------------------------------------------------

/// Patterns commonly used to hijack an agent's system prompt.
/// Matches literal injection commands case-insensitively.
static RE_PROMPT_INJECTION: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)\b(ignore\s+(all\s+)?previous\s+instructions?|disregard\s+(all\s+)?instructions?|override\s+all|jailbreak|you\s+are\s+now\s+a\s+different)\b",
    )
    .unwrap()
});

// ---------------------------------------------------------------------------
// Lightweight YAML frontmatter parser for AGENT.md
// ---------------------------------------------------------------------------

struct AgentFrontmatterData {
    /// `name` field value and its 1-indexed line number.
    name: Option<(String, usize)>,
    /// `description` field value and its 1-indexed line number.
    description: Option<(String, usize)>,
    /// `model` field value and its 1-indexed line number.
    model: Option<(String, usize)>,
    /// `system-prompt` collected text and the line where the key appears.
    system_prompt: Option<(String, usize)>,
    /// Each `tools` entry with its 1-indexed line number.
    tools: Vec<(String, usize)>,
    /// Each `mcp-servers` entry with its 1-indexed line number.
    mcp_servers: Vec<(String, usize)>,
}

/// Split a flow-sequence inner string on commas that are not inside parentheses.
///
/// `[Bash(find,ls), Write]` → `["Bash(find,ls)", "Write"]`
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

/// Split a YAML `key: value` line into `(key, value)`.
fn parse_kv(line: &str) -> Option<(String, String)> {
    if line.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let colon_pos = line.find(':')?;
    let key = line[..colon_pos].trim().to_string();
    if key.is_empty() {
        return None;
    }
    let after = &line[colon_pos + 1..];
    let value = after.strip_prefix(' ').unwrap_or(after);
    Some((key, value.to_string()))
}

/// Returns `true` if `line` looks like a YAML block-scalar indicator
/// (the value is `|`, `>`, `|-`, `>-`, `|+`, `>+`, or empty after stripping).
fn is_block_scalar_start(val: &str) -> bool {
    matches!(val.trim(), "" | "|" | ">" | "|-" | ">-" | "|+" | ">+")
}

/// Parse the YAML frontmatter block from `content` for AGENT.md.
///
/// Reads until the closing `---` (or end-of-file) and extracts the six
/// fields the AgentFrontmatterScanner cares about.
fn parse_frontmatter(content: &str) -> Option<AgentFrontmatterData> {
    let mut lines = content.lines().enumerate();

    // First line must be the opening delimiter.
    let (_, first) = lines.next()?;
    if first.trim() != "---" {
        return None;
    }

    let mut name: Option<(String, usize)> = None;
    let mut description: Option<(String, usize)> = None;
    let mut model: Option<(String, usize)> = None;
    let mut system_prompt: Option<(String, usize)> = None;
    let mut tools: Vec<(String, usize)> = Vec::new();
    let mut mcp_servers: Vec<(String, usize)> = Vec::new();

    // Track which top-level key we are currently collecting values for.
    #[derive(PartialEq)]
    enum CurrentKey {
        None,
        Tools,
        McpServers,
        SystemPrompt,
        Other,
    }

    let mut current_key = CurrentKey::None;
    // Whether the system-prompt value started with a block-scalar indicator.
    let mut system_prompt_is_block = false;

    // Collect lines (owned) to avoid borrow-checker issues.
    let remaining: Vec<(usize, String)> = lines.map(|(i, l)| (i, l.to_string())).collect();

    let iter = remaining.iter();

    for (idx, line) in iter {
        let line_num = idx + 1;

        if line.trim() == "---" {
            break;
        }

        if line.trim_start().starts_with('#') {
            continue;
        }

        // Block-sequence item under a known key.
        let is_list_item = line.starts_with("  - ")
            || line.starts_with("\t- ")
            || (line.starts_with("- ") && current_key != CurrentKey::None);

        // Indented continuation for block-scalar system-prompt.
        let is_indented = line.starts_with("  ") || line.starts_with('\t');

        if system_prompt_is_block
            && current_key == CurrentKey::SystemPrompt
            && is_indented
            && !is_list_item
        {
            // Append this line to the accumulated system-prompt text.
            let text_line = line
                .trim_start_matches(|c: char| c.is_whitespace())
                .to_string();
            if let Some((ref mut text, _)) = system_prompt {
                text.push('\n');
                text.push_str(&text_line);
            }
            continue;
        }

        if is_list_item {
            let item_raw = line
                .trim_start_matches(|c: char| c.is_whitespace())
                .strip_prefix("- ")
                .unwrap_or("")
                .trim();
            match current_key {
                CurrentKey::Tools if !item_raw.is_empty() => {
                    tools.push((item_raw.to_string(), line_num));
                }
                CurrentKey::McpServers if !item_raw.is_empty() => {
                    mcp_servers.push((item_raw.to_string(), line_num));
                }
                _ => {}
            }
            continue;
        }

        // Key: value line (must be at column 0 — parse_kv enforces that).
        if let Some((key, val)) = parse_kv(line) {
            // A non-indented key resets the current sequence/block context.
            system_prompt_is_block = false;

            let val_trimmed = val.trim();
            match key.as_str() {
                "name" => {
                    current_key = CurrentKey::Other;
                    if !val_trimmed.is_empty() {
                        name = Some((val_trimmed.to_string(), line_num));
                    }
                }
                "description" => {
                    current_key = CurrentKey::Other;
                    if !val_trimmed.is_empty() {
                        description = Some((val_trimmed.to_string(), line_num));
                    }
                }
                "model" => {
                    current_key = CurrentKey::Other;
                    if !val_trimmed.is_empty() {
                        model = Some((val_trimmed.to_string(), line_num));
                    }
                }
                "system-prompt" => {
                    current_key = CurrentKey::SystemPrompt;
                    if is_block_scalar_start(val_trimmed) {
                        // Block scalar: subsequent indented lines are the value.
                        system_prompt_is_block = true;
                        system_prompt = Some((String::new(), line_num));
                    } else if !val_trimmed.is_empty() {
                        system_prompt = Some((val_trimmed.to_string(), line_num));
                    }
                }
                "tools" => {
                    current_key = CurrentKey::Tools;
                    // Handle inline flow sequence: `tools: [Bash, Write]`
                    if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                        let inner = &val_trimmed[1..val_trimmed.len() - 1];
                        for t in split_flow_sequence(inner) {
                            if !t.is_empty() {
                                tools.push((t.to_string(), line_num));
                            }
                        }
                    } else if !val_trimmed.is_empty() && !is_block_scalar_start(val_trimmed) {
                        // Single inline value.
                        tools.push((val_trimmed.to_string(), line_num));
                    }
                }
                "mcp-servers" => {
                    current_key = CurrentKey::McpServers;
                    if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                        let inner = &val_trimmed[1..val_trimmed.len() - 1];
                        for t in split_flow_sequence(inner) {
                            if !t.is_empty() {
                                mcp_servers.push((t.to_string(), line_num));
                            }
                        }
                    } else if !val_trimmed.is_empty() && !is_block_scalar_start(val_trimmed) {
                        mcp_servers.push((val_trimmed.to_string(), line_num));
                    }
                }
                _ => {
                    current_key = CurrentKey::Other;
                }
            }
        }
    }

    Some(AgentFrontmatterData {
        name,
        description,
        model,
        system_prompt,
        tools,
        mcp_servers,
    })
}

// ---------------------------------------------------------------------------
// Emit helper
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn emit(
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
        scanner: "agent_frontmatter".to_string(),
        snippet: None,
        suppressed: false,
        suppression_reason: None,
        remediation: Some(remediation.to_string()),
    });
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_name(findings: &mut Vec<Finding>, name_val: &str, name_line: usize, agent_md: &Path) {
    // XML/HTML angle brackets in name.
    let has_xml = name_val.contains('<')
        || name_val.contains('>')
        || name_val.contains("&lt;")
        || name_val.contains("&gt;")
        || name_val.contains("&#");
    if has_xml {
        emit(
            findings,
            "agent/xml-in-frontmatter",
            Severity::Error,
            "XML/HTML angle brackets in 'name' field — potential prompt injection vector",
            "Remove angle brackets from the name field",
            agent_md,
            Some(name_line),
        );
    }

    let name_lower = name_val.to_lowercase();

    // Reserved brand words.
    if name_lower.contains("claude") || name_lower.contains("anthropic") {
        emit(
            findings,
            "agent/name-reserved-word",
            Severity::Error,
            "Agent name contains reserved word 'claude' or 'anthropic'",
            "Choose a name that does not reference Claude or Anthropic brand names",
            agent_md,
            Some(name_line),
        );
    }

    // Must be lowercase-kebab-case.
    let has_uppercase = name_val.chars().any(|c| c.is_uppercase());
    let has_space = name_val.contains(' ');
    let has_underscore = name_val.contains('_');
    if has_uppercase || has_space || has_underscore {
        emit(
            findings,
            "agent/invalid-name-format",
            Severity::Warning,
            "Agent name contains uppercase letters, spaces, or underscores — use lowercase-kebab-case",
            "Rename to lowercase-kebab-case (e.g. 'my-agent' not 'My_Agent')",
            agent_md,
            Some(name_line),
        );
    }

    // Name length.
    let name_char_count = name_val.chars().count();
    if name_char_count > 64 {
        emit(
            findings,
            "agent/name-too-long",
            Severity::Warning,
            &format!("Agent name is {} chars — maximum is 64", name_char_count),
            "Shorten the agent name to 64 characters or fewer",
            agent_md,
            Some(name_line),
        );
    }

    // Name must not start or end with a hyphen.
    if name_val.starts_with('-') || name_val.ends_with('-') {
        emit(
            findings,
            "agent/name-leading-trailing-hyphen",
            Severity::Warning,
            "Agent name starts or ends with a hyphen",
            "Remove the leading/trailing hyphen from the agent name (e.g. 'my-agent' not '-my-agent')",
            agent_md,
            Some(name_line),
        );
    }

    // Name must not contain consecutive hyphens.
    if name_val.contains("--") {
        emit(
            findings,
            "agent/name-consecutive-hyphens",
            Severity::Warning,
            "Agent name contains consecutive hyphens (--)",
            "Replace consecutive hyphens with a single hyphen (e.g. 'my-agent' not 'my--agent')",
            agent_md,
            Some(name_line),
        );
    }

    // Vague generic name segment.
    let has_vague = name_lower
        .split('-')
        .any(|seg| VAGUE_NAME_TERMS.contains(&seg));
    if has_vague {
        emit(
            findings,
            "agent/name-too-vague",
            Severity::Warning,
            "Agent name uses a vague generic term — choose a descriptive name",
            "Rename to something specific (e.g. 'github-pr-reviewer' not 'tools')",
            agent_md,
            Some(name_line),
        );
    }
}

fn validate_description(
    findings: &mut Vec<Finding>,
    description: Option<&(String, usize)>,
    agent_md: &Path,
) {
    let (desc_val, desc_line) = match description {
        Some((v, l)) if !v.trim().is_empty() => (v.as_str(), *l),
        other => {
            emit(
                findings,
                "agent/description-missing",
                Severity::Warning,
                "Agent description is missing or empty",
                "Add a meaningful description field to AGENT.md frontmatter",
                agent_md,
                other.map(|(_, l)| *l),
            );
            return;
        }
    };

    // XML/HTML angle brackets in description.
    let desc_has_xml = desc_val.contains('<')
        || desc_val.contains('>')
        || desc_val.contains("&lt;")
        || desc_val.contains("&gt;")
        || desc_val.contains("&#");
    if desc_has_xml {
        emit(
            findings,
            "agent/xml-in-frontmatter",
            Severity::Error,
            "XML/HTML angle brackets in 'description' field — potential prompt injection vector",
            "Remove angle brackets from the description field",
            agent_md,
            Some(desc_line),
        );
    }

    let desc_char_count = desc_val.chars().count();
    if desc_char_count > 1024 {
        emit(
            findings,
            "agent/description-too-long",
            Severity::Warning,
            &format!("Description is {} chars — maximum is 1024", desc_char_count),
            "Shorten the description to 1024 characters or fewer",
            agent_md,
            Some(desc_line),
        );
    }

    if RE_FIRST_PERSON.is_match(desc_val) {
        emit(
            findings,
            "agent/description-not-third-person",
            Severity::Warning,
            "Description uses first or second person — use third person (e.g. 'This agent...')",
            "Rewrite the description in third person",
            agent_md,
            Some(desc_line),
        );
    }

    let desc_lower = desc_val.to_lowercase();
    let has_trigger = TRIGGER_PHRASES.iter().any(|p| desc_lower.contains(p));
    if !has_trigger {
        emit(
            findings,
            "agent/description-no-trigger",
            Severity::Info,
            "Description doesn't include 'when to use' context — add trigger phrases (e.g. 'Use when...')",
            "Append: 'Use when <specific trigger condition>.' to the description",
            agent_md,
            Some(desc_line),
        );
    }
}

fn validate_tools(findings: &mut Vec<Finding>, tools: &[(String, usize)], agent_md: &Path) {
    for (tool, tool_line) in tools {
        let trimmed = tool.trim();
        if trimmed.eq_ignore_ascii_case("bash") && !trimmed.contains('(') {
            emit(
                findings,
                "agent/bare-tool",
                Severity::Warning,
                "Unscoped 'Bash' in tools grants unrestricted shell access",
                "Scope Bash to specific commands: e.g., Bash(find,ls,cat,grep)",
                agent_md,
                Some(*tool_line),
            );
        }
    }
}

fn validate_mcp_servers(
    findings: &mut Vec<Finding>,
    mcp_servers: &[(String, usize)],
    agent_md: &Path,
) {
    for (server, server_line) in mcp_servers {
        let trimmed = server.trim();
        // A plain server name without a parenthesised tool allowlist is unconstrained.
        if !trimmed.contains('(') {
            emit(
                findings,
                "agent/unconstrained-mcp-server",
                Severity::Warning,
                &format!(
                    "MCP server '{}' has no tool allowlist — grants access to all server tools",
                    trimmed
                ),
                "Add an explicit tool allowlist: e.g., github(list-issues,create-pr)",
                agent_md,
                Some(*server_line),
            );
        }
    }
}

fn validate_system_prompt(
    findings: &mut Vec<Finding>,
    system_prompt: Option<&(String, usize)>,
    agent_md: &Path,
) {
    let (sp_val, sp_line) = match system_prompt {
        Some((v, l)) => (v.as_str(), *l),
        None => return, // system-prompt is optional; absence is handled elsewhere
    };

    // XML/HTML angle brackets in system-prompt.
    let has_xml = sp_val.contains('<')
        || sp_val.contains('>')
        || sp_val.contains("&lt;")
        || sp_val.contains("&gt;")
        || sp_val.contains("&#");
    if has_xml {
        emit(
            findings,
            "agent/xml-in-frontmatter",
            Severity::Error,
            "XML/HTML angle brackets in 'system-prompt' field — potential prompt injection vector",
            "Remove angle brackets from the system-prompt field",
            agent_md,
            Some(sp_line),
        );
    }

    // Prompt injection patterns.
    if RE_PROMPT_INJECTION.is_match(sp_val) {
        emit(
            findings,
            "agent/system-prompt-injection",
            Severity::Error,
            "system-prompt contains prompt injection pattern (e.g. 'ignore previous instructions')",
            "Remove prompt injection phrases from the system-prompt field",
            agent_md,
            Some(sp_line),
        );
    }

    // System prompt length guard.
    let sp_char_count = sp_val.chars().count();
    if sp_char_count > 8000 {
        emit(
            findings,
            "agent/system-prompt-too-long",
            Severity::Warning,
            &format!("system-prompt is {} chars — maximum is 8000", sp_char_count),
            "Trim the system-prompt to 8000 characters or fewer",
            agent_md,
            Some(sp_line),
        );
    }
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Built-in scanner for `AGENT.md` frontmatter and metadata validation.
///
/// Checks for the existence of `AGENT.md`, parses its YAML frontmatter,
/// and validates the `name`, `description`, `model`, `system-prompt`,
/// `tools`, and `mcp-servers` fields against 19 rules derived from the
/// Claude agent skills best-practices guide.  Also inspects the body for
/// excessive length, Windows-style paths, and time-sensitive language.
///
/// See the [module-level documentation](self) for the full rule table.
pub struct AgentFrontmatterScanner;

impl Scanner for AgentFrontmatterScanner {
    fn name(&self) -> &'static str {
        "agent_frontmatter"
    }

    fn description(&self) -> &'static str {
        "AGENT.md frontmatter and tools audit"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn scan(&self, path: &Path, _config: &Config) -> ScanResult {
        let start = Instant::now();
        let agent_md = path.join("AGENT.md");
        let mut findings = Vec::new();

        // Rule: AGENT.md must exist.
        if !agent_md.exists() {
            emit(
                &mut findings,
                "agent/missing-agent-md",
                Severity::Error,
                "AGENT.md not found in agent root",
                "Create an AGENT.md file in the agent root with required frontmatter fields",
                &agent_md,
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

        // Read AGENT.md (size-limited to prevent DoS via oversized files).
        let content = match read_file_limited(&agent_md) {
            Ok(c) => c,
            Err(e) => {
                return ScanResult {
                    scanner_name: self.name().to_string(),
                    findings,
                    files_scanned: 1,
                    skipped: false,
                    skip_reason: None,
                    error: Some(format!("Failed to read AGENT.md: {e}")),
                    duration_ms: start.elapsed().as_millis() as u64,
                    scanner_score: None,
                    scanner_grade: None,
                };
            }
        };

        // Parse frontmatter.
        let fm = parse_frontmatter(&content);

        if let Some(ref fm) = fm {
            // Validate name.
            if let Some((ref name_val, name_line)) = fm.name {
                validate_name(&mut findings, name_val, name_line, &agent_md);

                // name must match directory name.
                let name_format_invalid = findings
                    .iter()
                    .any(|f| f.rule_id == "agent/invalid-name-format");
                if !name_format_invalid {
                    if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                        if name_val != dir_name {
                            emit(
                                &mut findings,
                                "agent/name-directory-mismatch",
                                Severity::Warning,
                                &format!(
                                    "Agent name '{}' does not match directory name '{}'",
                                    name_val, dir_name
                                ),
                                "Rename the agent directory to match the 'name' field, or update 'name' to match the directory",
                                &agent_md,
                                Some(name_line),
                            );
                        }
                    }
                }
            }

            // model field should be explicit.
            if fm.model.is_none() {
                emit(
                    &mut findings,
                    "agent/model-not-specified",
                    Severity::Warning,
                    "No 'model' field in AGENT.md — implicit default may drift with platform updates",
                    "Add an explicit 'model' field (e.g. model: claude-sonnet-4-6-thinking)",
                    &agent_md,
                    None,
                );
            }

            validate_tools(&mut findings, &fm.tools, &agent_md);
            validate_mcp_servers(&mut findings, &fm.mcp_servers, &agent_md);
            validate_system_prompt(&mut findings, fm.system_prompt.as_ref(), &agent_md);
        }

        // Description validation runs unconditionally.
        validate_description(
            &mut findings,
            fm.as_ref().and_then(|f| f.description.as_ref()),
            &agent_md,
        );

        // Single pass over AGENT.md body lines:
        // - body too long (> 500 lines)
        // - first Windows-style backslash path
        // - first time-sensitive date condition
        let mut line_count = 0usize;
        let mut windows_path_line: Option<usize> = None;
        let mut time_sensitive_line: Option<usize> = None;

        for (idx, line) in content.lines().enumerate() {
            line_count += 1;
            if windows_path_line.is_none() && RE_WINDOWS_PATH.is_match(line) {
                windows_path_line = Some(idx + 1);
            }
            if time_sensitive_line.is_none() && RE_TIME_SENSITIVE.is_match(line) {
                time_sensitive_line = Some(idx + 1);
            }
        }

        if line_count > 500 {
            emit(
                &mut findings,
                "agent/agent-body-too-long",
                Severity::Warning,
                &format!("AGENT.md is {line_count} lines — maximum is 500"),
                "Trim AGENT.md to 500 lines or fewer",
                &agent_md,
                None,
            );
        }

        if let Some(line_num) = windows_path_line {
            emit(
                &mut findings,
                "agent/windows-path",
                Severity::Warning,
                "Windows-style backslash path in AGENT.md — use forward slashes",
                "Replace backslash paths with forward slashes (e.g. path/to/file)",
                &agent_md,
                Some(line_num),
            );
        }

        if let Some(line_num) = time_sensitive_line {
            emit(
                &mut findings,
                "agent/time-sensitive-content",
                Severity::Warning,
                "AGENT.md contains time-sensitive date condition — this will become stale",
                "Move dated content into an 'Old patterns' collapsible section instead",
                &agent_md,
                Some(line_num),
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

/// Returns the [`RuleInfo`] catalogue for every agent frontmatter validation rule.
pub fn rules() -> Vec<RuleInfo> {
    vec![
        RuleInfo {
            id: "agent/missing-agent-md",
            severity: "error",
            scanner: "agent_frontmatter",
            message: "AGENT.md not found in agent root",
            remediation: "Create an AGENT.md file in the agent root with required frontmatter fields",
        },
        RuleInfo {
            id: "agent/xml-in-frontmatter",
            severity: "error",
            scanner: "agent_frontmatter",
            message: "XML/HTML angle brackets in frontmatter field — potential prompt injection vector",
            remediation: "Remove angle brackets from the name, description, or system-prompt fields",
        },
        RuleInfo {
            id: "agent/name-reserved-word",
            severity: "error",
            scanner: "agent_frontmatter",
            message: "Agent name contains reserved word 'claude' or 'anthropic'",
            remediation: "Choose a name that does not reference Claude or Anthropic brand names",
        },
        RuleInfo {
            id: "agent/system-prompt-injection",
            severity: "error",
            scanner: "agent_frontmatter",
            message: "system-prompt contains prompt injection pattern",
            remediation: "Remove prompt injection phrases from the system-prompt field",
        },
        RuleInfo {
            id: "agent/invalid-name-format",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Agent name must be lowercase-kebab-case",
            remediation: "Rename to lowercase-kebab-case (e.g. 'my-agent' not 'My_Agent')",
        },
        RuleInfo {
            id: "agent/name-too-long",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Agent name exceeds 64 characters",
            remediation: "Shorten the agent name to 64 characters or fewer",
        },
        RuleInfo {
            id: "agent/name-too-vague",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Agent name uses a vague generic term",
            remediation: "Choose a descriptive name (e.g. 'github-pr-reviewer' not 'tools')",
        },
        RuleInfo {
            id: "agent/description-missing",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Agent description is missing or empty",
            remediation: "Add a meaningful description field to AGENT.md frontmatter",
        },
        RuleInfo {
            id: "agent/description-too-long",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Description exceeds 1024 characters",
            remediation: "Shorten the description to 1024 characters or fewer",
        },
        RuleInfo {
            id: "agent/description-not-third-person",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Description uses first or second person instead of third person",
            remediation: "Rewrite the description in third person (e.g. 'This agent creates...')",
        },
        RuleInfo {
            id: "agent/model-not-specified",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "No 'model' field in AGENT.md — implicit default may drift",
            remediation: "Add an explicit 'model' field (e.g. model: claude-sonnet-4-6-thinking)",
        },
        RuleInfo {
            id: "agent/bare-tool",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Unscoped 'Bash' in tools grants unrestricted shell access",
            remediation: "Scope Bash to specific commands: e.g., Bash(find,ls,cat,grep)",
        },
        RuleInfo {
            id: "agent/system-prompt-too-long",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "system-prompt exceeds 8000 characters",
            remediation: "Trim the system-prompt to 8000 characters or fewer",
        },
        RuleInfo {
            id: "agent/unconstrained-mcp-server",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "MCP server has no tool allowlist — grants access to all server tools",
            remediation: "Add an explicit tool allowlist: e.g., github(list-issues,create-pr)",
        },
        RuleInfo {
            id: "agent/agent-body-too-long",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "AGENT.md exceeds 500 lines",
            remediation: "Trim AGENT.md to 500 lines or fewer",
        },
        RuleInfo {
            id: "agent/windows-path",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Windows-style backslash path in AGENT.md — use forward slashes",
            remediation: "Replace backslash paths with forward slashes (e.g. path/to/file)",
        },
        RuleInfo {
            id: "agent/time-sensitive-content",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "AGENT.md contains a time-sensitive date condition that will become stale",
            remediation: "Move dated content into an 'Old patterns' collapsible section",
        },
        RuleInfo {
            id: "agent/name-directory-mismatch",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Agent name does not match the containing directory name",
            remediation: "Rename the agent directory to match the 'name' field, or update 'name' to match the directory",
        },
        RuleInfo {
            id: "agent/description-no-trigger",
            severity: "info",
            scanner: "agent_frontmatter",
            message: "Description doesn't include 'when to use' context",
            remediation: "Append 'Use when <specific trigger condition>.' to the description",
        },
        RuleInfo {
            id: "agent/name-leading-trailing-hyphen",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Agent name starts or ends with a hyphen",
            remediation: "Remove the leading/trailing hyphen from the agent name",
        },
        RuleInfo {
            id: "agent/name-consecutive-hyphens",
            severity: "warning",
            scanner: "agent_frontmatter",
            message: "Agent name contains consecutive hyphens (--)",
            remediation: "Replace consecutive hyphens with a single hyphen",
        },
    ]
}
