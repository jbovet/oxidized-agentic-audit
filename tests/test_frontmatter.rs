use std::path::Path;

use oxidized_skills::config::Config;
use oxidized_skills::finding::Severity;
use oxidized_skills::scanners::frontmatter::FrontmatterScanner;
use oxidized_skills::scanners::Scanner;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn scan_dir(dir: &Path) -> oxidized_skills::finding::ScanResult {
    let config = Config::default();
    FrontmatterScanner.scan(dir, &config)
}

fn scan_fixture(fixture: &str) -> oxidized_skills::finding::ScanResult {
    let config = Config::default();
    let path = Path::new("tests/fixtures").join(fixture);
    FrontmatterScanner.scan(&path, &config)
}

fn write_skill_md(dir: &std::path::Path, content: &str) {
    std::fs::write(dir.join("SKILL.md"), content).unwrap();
}

fn minimal_skill(name: &str, description: &str, allowed_tools_line: &str) -> String {
    format!(
        "---\nname: {name}\ndescription: {description}\nallowed-tools:\n  - {allowed_tools_line}\n---\n\n# Skill\n"
    )
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/missing-skill-md
// ---------------------------------------------------------------------------

#[test]
fn missing_skill_md_fires_error() {
    let dir = tempfile::tempdir().unwrap();
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/missing-skill-md");
    assert!(found, "Expected frontmatter/missing-skill-md finding");
    assert_eq!(result.files_scanned, 0);
}

#[test]
fn missing_skill_md_is_error_severity() {
    let dir = tempfile::tempdir().unwrap();
    let result = scan_dir(dir.path());
    let f = result
        .findings
        .iter()
        .find(|f| f.rule_id == "frontmatter/missing-skill-md")
        .unwrap();
    assert_eq!(f.severity, Severity::Error);
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/readme-in-skill
// ---------------------------------------------------------------------------

#[test]
fn readme_in_skill_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("my-skill", "A safe skill", "Bash(find)"),
    );
    std::fs::write(dir.path().join("README.md"), "# Readme").unwrap();

    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/readme-in-skill");
    assert!(found, "Expected frontmatter/readme-in-skill finding");
}

#[test]
fn no_readme_no_finding() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("my-skill", "A safe skill", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/readme-in-skill");
    assert!(!found, "No readme-in-skill finding expected");
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/xml-in-frontmatter
// ---------------------------------------------------------------------------

#[test]
fn xml_in_name_fires_error() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: <bad-skill>\ndescription: A skill\nallowed-tools:\n  - Bash(find)\n---\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/xml-in-frontmatter" && f.severity == Severity::Error);
    assert!(found, "Expected xml-in-frontmatter Error for name");
}

#[test]
fn xml_in_description_fires_error() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: safe-skill\ndescription: <script>alert(1)</script>\nallowed-tools:\n  - Bash(find)\n---\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/xml-in-frontmatter" && f.severity == Severity::Error);
    assert!(found, "Expected xml-in-frontmatter Error for description");
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/name-reserved-word
// ---------------------------------------------------------------------------

#[test]
fn name_reserved_word_claude_fires_error() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("claude-helper", "A skill", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-reserved-word");
    assert!(found, "Expected name-reserved-word for 'claude-helper'");
}

#[test]
fn name_reserved_word_anthropic_fires_error() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("anthropic-tool", "A skill", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-reserved-word");
    assert!(found, "Expected name-reserved-word for 'anthropic-tool'");
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/invalid-name-format
// ---------------------------------------------------------------------------

#[test]
fn name_invalid_format_uppercase_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("MySkill", "A skill", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/invalid-name-format");
    assert!(found, "Expected invalid-name-format for 'MySkill'");
}

#[test]
fn name_invalid_format_underscore_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("my_skill", "A skill", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/invalid-name-format");
    assert!(found, "Expected invalid-name-format for 'my_skill'");
}

#[test]
fn name_valid_kebab_no_format_finding() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("my-skill", "A skill", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/invalid-name-format");
    assert!(!found, "Valid kebab-case name should not fire");
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/name-too-long
// ---------------------------------------------------------------------------

#[test]
fn name_too_long_fires_warning() {
    let long_name = "a".repeat(65);
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(&long_name, "A skill", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-too-long");
    assert!(found, "Expected name-too-long for 65-char name");
}

#[test]
fn name_exactly_64_chars_no_finding() {
    let name_64 = "a".repeat(64);
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(&name_64, "A skill", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-too-long");
    assert!(!found, "64-char name is exactly at limit — should not fire");
}

// ---------------------------------------------------------------------------
// Bug 3 regression: char count vs byte count for name length
// ---------------------------------------------------------------------------

#[test]
fn name_64_multibyte_chars_at_limit_no_finding() {
    // "é" is 2 bytes in UTF-8 but 1 character.
    // A 64-character name made of "é" has 128 bytes — the old .len() check
    // would have incorrectly fired name-too-long (128 > 64).
    // With .chars().count() it is exactly at the 64-char limit.
    let name = "é".repeat(64);
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &format!("---\nname: {name}\ndescription: A skill. Use when needed.\nallowed-tools:\n  - Bash(find)\n---\n"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-too-long");
    assert!(
        !found,
        "64 multi-byte characters must not fire name-too-long (byte count != char count)"
    );
}

#[test]
fn name_65_multibyte_chars_over_limit_fires_warning() {
    let name = "é".repeat(65);
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &format!("---\nname: {name}\ndescription: A skill. Use when needed.\nallowed-tools:\n  - Bash(find)\n---\n"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-too-long");
    assert!(
        found,
        "65 multi-byte characters (one over limit) must fire name-too-long"
    );
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/description-missing
// ---------------------------------------------------------------------------

#[test]
fn description_missing_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\nallowed-tools:\n  - Bash(find)\n---\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-missing");
    assert!(found, "Expected description-missing when field absent");
}

#[test]
fn description_present_no_missing_finding() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("my-skill", "This skill does something useful", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-missing");
    assert!(
        !found,
        "description-missing should not fire when description is set"
    );
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/description-too-long
// ---------------------------------------------------------------------------

#[test]
fn description_too_long_fires_warning() {
    let long_desc = "x".repeat(1025);
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &format!(
            "---\nname: my-skill\ndescription: {long_desc}\nallowed-tools:\n  - Bash(find)\n---\n"
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-too-long");
    assert!(
        found,
        "Expected description-too-long for 1025-char description"
    );
}

#[test]
fn description_exactly_1024_chars_no_finding() {
    let desc_1024 = "x".repeat(1024);
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &format!(
            "---\nname: my-skill\ndescription: {desc_1024}\nallowed-tools:\n  - Bash(find)\n---\n"
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-too-long");
    assert!(
        !found,
        "1024-char description is at limit — should not fire"
    );
}

#[test]
fn description_1024_multibyte_chars_at_limit_no_finding() {
    // "é" is 2 bytes but 1 char — 1024 × "é" = 2048 bytes, 1024 chars.
    // Old .len() check would fire (2048 > 1024); .chars().count() correctly does not.
    let desc = "é".repeat(1024);
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &format!("---\nname: my-skill\ndescription: {desc}\nallowed-tools:\n  - Bash(find)\n---\n"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-too-long");
    assert!(
        !found,
        "1024-multibyte-char description is at limit — should not fire"
    );
}

#[test]
fn description_1025_multibyte_chars_over_limit_fires_warning() {
    // "é" is 2 bytes but 1 char — 1025 chars is one over the limit.
    let desc = "é".repeat(1025);
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &format!("---\nname: my-skill\ndescription: {desc}\nallowed-tools:\n  - Bash(find)\n---\n"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-too-long");
    assert!(
        found,
        "Expected description-too-long for 1025-multibyte-char description"
    );
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/bare-bash-tool
// ---------------------------------------------------------------------------

#[test]
fn bare_bash_tool_block_seq_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: A skill\nallowed-tools:\n  - Bash\n---\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/bare-bash-tool");
    assert!(
        found,
        "Expected bare-bash-tool for unscoped 'Bash' in block seq"
    );
}

#[test]
fn bare_bash_tool_flow_seq_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: A skill\nallowed-tools: [Bash]\n---\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/bare-bash-tool");
    assert!(
        found,
        "Expected bare-bash-tool for unscoped 'Bash' in flow seq"
    );
}

#[test]
fn scoped_bash_tool_no_finding() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: A skill\nallowed-tools:\n  - Bash(find,ls)\n---\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/bare-bash-tool");
    assert!(
        !found,
        "Scoped Bash(find,ls) should NOT fire bare-bash-tool"
    );
}

#[test]
fn multiple_tools_only_bash_fires() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: A skill\nallowed-tools:\n  - Bash\n  - Write\n---\n",
    );
    let result = scan_dir(dir.path());
    let bare_bash_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "frontmatter/bare-bash-tool")
        .collect();
    assert_eq!(
        bare_bash_findings.len(),
        1,
        "Only Bash should fire, not Write"
    );
}

// ---------------------------------------------------------------------------
// Fixture integration
// ---------------------------------------------------------------------------

#[test]
fn clean_skill_fixture_no_frontmatter_findings() {
    let result = scan_fixture("clean-skill");
    assert!(
        result.findings.is_empty(),
        "clean-skill fixture should produce no frontmatter findings, got: {:?}",
        result.findings
    );
    assert!(!result.skipped);
}

#[test]
fn dirty_skill_fixture_detects_bare_bash() {
    let result = scan_fixture("dirty-skill");
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/bare-bash-tool");
    assert!(
        found,
        "dirty-skill has bare 'Bash' — expected frontmatter/bare-bash-tool"
    );
}

// ---------------------------------------------------------------------------
// Fix #9: flow sequence must not split on commas inside parentheses
// ---------------------------------------------------------------------------

#[test]
fn flow_seq_scoped_bash_with_comma_args_no_false_positive() {
    // `[Bash(find,ls)]` must be parsed as a single entry "Bash(find,ls)",
    // not split into "Bash(find" and "ls)".  The latter would mangle the tool
    // name and could cause false-negatives for bare-bash-tool detection.
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: A skill\nallowed-tools: [Bash(find,ls)]\n---\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/bare-bash-tool");
    assert!(
        !found,
        "Scoped Bash(find,ls) in flow sequence must NOT fire bare-bash-tool"
    );
}

#[test]
fn flow_seq_bare_bash_with_other_tools_fires() {
    // `[Bash, Write]` — bare Bash must still be detected even alongside other tools.
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: A skill\nallowed-tools: [Bash, Write]\n---\n",
    );
    let result = scan_dir(dir.path());
    let bare_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "frontmatter/bare-bash-tool")
        .collect();
    assert_eq!(
        bare_findings.len(),
        1,
        "Bare Bash in [Bash, Write] should fire exactly once"
    );
}

#[test]
fn flow_seq_multiple_scoped_tools_no_finding() {
    // `[Bash(find,ls,cat), Write, Read]` — all scoped, no bare-bash-tool expected.
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: A skill\nallowed-tools: [Bash(find,ls,cat), Write, Read]\n---\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/bare-bash-tool");
    assert!(
        !found,
        "Multiple scoped tools in flow sequence must not fire bare-bash-tool"
    );
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/name-too-vague
// ---------------------------------------------------------------------------

#[test]
fn name_too_vague_exact_match_fires_warning() {
    for vague in &["tools", "helper", "utils", "data", "files", "documents"] {
        let dir = tempfile::tempdir().unwrap();
        write_skill_md(
            dir.path(),
            &minimal_skill(vague, "Does something useful", "Bash(find)"),
        );
        let result = scan_dir(dir.path());
        let found = result
            .findings
            .iter()
            .any(|f| f.rule_id == "frontmatter/name-too-vague");
        assert!(found, "Expected name-too-vague for '{vague}'");
    }
}

#[test]
fn name_too_vague_segment_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("my-tools", "Does something useful", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-too-vague");
    assert!(
        found,
        "Expected name-too-vague for 'my-tools' (segment 'tools')"
    );
}

#[test]
fn name_specific_no_vague_finding() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(
            "github-pr-creator",
            "Creates GitHub pull requests",
            "Bash(find)",
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-too-vague");
    assert!(
        !found,
        "Specific name 'github-pr-creator' must not fire name-too-vague"
    );
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/description-not-third-person
// ---------------------------------------------------------------------------

#[test]
fn description_first_person_i_can_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("my-skill", "I can create pull requests", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-not-third-person");
    assert!(
        found,
        "Expected description-not-third-person for 'I can ...'"
    );
}

#[test]
fn description_second_person_you_can_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("my-skill", "you can use this to deploy code", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-not-third-person");
    assert!(
        found,
        "Expected description-not-third-person for 'you can ...'"
    );
}

#[test]
fn description_third_person_no_finding() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(
            "my-skill",
            "This skill creates pull requests on GitHub",
            "Bash(find)",
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-not-third-person");
    assert!(!found, "Third-person description must not fire");
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/skill-body-too-long
// ---------------------------------------------------------------------------

#[test]
fn skill_body_too_long_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    // Build a SKILL.md that exceeds 500 lines total.
    let body_lines = "# line\n".repeat(510);
    let content = format!(
        "---\nname: my-skill\ndescription: Does useful things\nallowed-tools:\n  - Bash(find)\n---\n{body_lines}"
    );
    write_skill_md(dir.path(), &content);
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/skill-body-too-long");
    assert!(found, "Expected skill-body-too-long for 510-line SKILL.md");
}

#[test]
fn skill_body_exactly_500_lines_no_finding() {
    let dir = tempfile::tempdir().unwrap();
    // 6 lines of frontmatter + 494 body lines = 500 total.
    let body_lines = "# line\n".repeat(494);
    let content = format!(
        "---\nname: my-skill\ndescription: Does useful things\nallowed-tools:\n  - Bash(find)\n---\n{body_lines}"
    );
    write_skill_md(dir.path(), &content);
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/skill-body-too-long");
    assert!(
        !found,
        "500-line SKILL.md must not fire skill-body-too-long"
    );
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/windows-path
// ---------------------------------------------------------------------------

#[test]
fn windows_absolute_path_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: Does useful things\nallowed-tools:\n  - Bash(find)\n---\n\nRun the script at C:\\scripts\\deploy.bat\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/windows-path");
    assert!(found, "Expected windows-path for 'C:\\scripts\\deploy.bat'");
}

#[test]
fn windows_relative_path_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: Does useful things\nallowed-tools:\n  - Bash(find)\n---\n\nSee scripts\\install.sh for details\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/windows-path");
    assert!(found, "Expected windows-path for 'scripts\\install.sh'");
}

#[test]
fn forward_slash_paths_no_finding() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: Does useful things\nallowed-tools:\n  - Bash(find)\n---\n\nRun scripts/install.sh to get started.\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/windows-path");
    assert!(!found, "Forward-slash paths must not fire windows-path");
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/description-no-trigger
// ---------------------------------------------------------------------------

#[test]
fn description_without_trigger_fires_info() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill("my-skill", "Processes Excel spreadsheets", "Bash(find)"),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-no-trigger");
    assert!(
        found,
        "Expected description-no-trigger when description has no 'when to use' context"
    );
}

#[test]
fn description_with_use_when_no_trigger_finding() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(
            "my-skill",
            "Processes Excel spreadsheets. Use when the user asks to analyze a spreadsheet.",
            "Bash(find)",
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-no-trigger");
    assert!(
        !found,
        "description-no-trigger must not fire when 'use when' is present"
    );
}

#[test]
fn description_with_when_the_user_no_trigger_finding() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(
            "my-skill",
            "Processes PDFs. Use when the user mentions a PDF file.",
            "Bash(find)",
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-no-trigger");
    assert!(
        !found,
        "description-no-trigger must not fire when 'when the user' is present"
    );
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/time-sensitive-content
// ---------------------------------------------------------------------------

#[test]
fn time_sensitive_before_year_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: Does useful things. Use when needed.\nallowed-tools:\n  - Bash(find)\n---\n\nIf you're doing this before 2025, use the old API.\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/time-sensitive-content");
    assert!(found, "Expected time-sensitive-content for 'before 2025'");
}

#[test]
fn time_sensitive_after_month_year_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: Does useful things. Use when needed.\nallowed-tools:\n  - Bash(find)\n---\n\nAfter August 2025, use the new endpoint.\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/time-sensitive-content");
    assert!(
        found,
        "Expected time-sensitive-content for 'After August 2025'"
    );
}

#[test]
fn time_sensitive_as_of_fires_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: Does useful things. Use when needed.\nallowed-tools:\n  - Bash(find)\n---\n\nAs of January 2026, the v2 API is required.\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/time-sensitive-content");
    assert!(
        found,
        "Expected time-sensitive-content for 'As of January 2026'"
    );
}

#[test]
fn no_date_conditions_no_time_sensitive_finding() {
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        "---\nname: my-skill\ndescription: Does useful things. Use when needed.\nallowed-tools:\n  - Bash(find)\n---\n\n## Old patterns\nSee the legacy section for deprecated usage.\n",
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/time-sensitive-content");
    assert!(
        !found,
        "No date conditions should not fire time-sensitive-content"
    );
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/description-no-trigger — extended phrase coverage
// ---------------------------------------------------------------------------

#[test]
fn description_should_be_used_when_no_trigger_finding() {
    // "should be used when" is a natural prose trigger phrase — must NOT fire.
    // Matches the real skill-creator description pattern.
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(
            "my-skill",
            "Guides users through a workflow. This skill should be used when a developer needs step-by-step help.",
            "Bash(find)",
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-no-trigger");
    assert!(
        !found,
        "description-no-trigger must not fire for 'should be used when'"
    );
}

#[test]
fn description_when_users_no_trigger_finding() {
    // "when users" (plural) is a valid trigger phrase — must NOT fire.
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(
            "my-skill",
            "Automates release notes. Use when users want to publish a new version.",
            "Bash(find)",
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-no-trigger");
    assert!(
        !found,
        "description-no-trigger must not fire for 'when users'"
    );
}

#[test]
fn description_when_a_user_no_trigger_finding() {
    // "when a user" is a valid trigger phrase — must NOT fire.
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(
            "my-skill",
            "Sends Slack notifications. Invoke when a user requests a status update.",
            "Bash(find)",
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-no-trigger");
    assert!(
        !found,
        "description-no-trigger must not fire for 'when a user'"
    );
}

#[test]
fn description_use_it_when_no_trigger_finding() {
    // "use it when" is a valid trigger phrase — must NOT fire.
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(
            "my-skill",
            "Validates JSON schemas. Use it when processing API responses.",
            "Bash(find)",
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-no-trigger");
    assert!(
        !found,
        "description-no-trigger must not fire for 'use it when'"
    );
}

#[test]
fn description_useful_when_no_trigger_finding() {
    // "useful when" is a valid trigger phrase — must NOT fire.
    let dir = tempfile::tempdir().unwrap();
    write_skill_md(
        dir.path(),
        &minimal_skill(
            "my-skill",
            "Parses log files into structured data. Useful when diagnosing production incidents.",
            "Bash(find)",
        ),
    );
    let result = scan_dir(dir.path());
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/description-no-trigger");
    assert!(
        !found,
        "description-no-trigger must not fire for 'useful when'"
    );
}

// ---------------------------------------------------------------------------
// Rule: frontmatter/name-directory-mismatch
// ---------------------------------------------------------------------------

#[test]
fn name_matches_directory_no_mismatch_finding() {
    // skill name == directory name → no finding.
    let base = tempfile::tempdir().unwrap();
    let skill_dir = base.path().join("my-skill");
    std::fs::create_dir_all(&skill_dir).unwrap();
    write_skill_md(
        &skill_dir,
        "---\nname: my-skill\ndescription: A skill. Use when needed.\nallowed-tools:\n  - Bash(find)\n---\n",
    );
    let result = scan_dir(&skill_dir);
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-directory-mismatch");
    assert!(
        !found,
        "name-directory-mismatch must not fire when name matches directory"
    );
}

#[test]
fn name_mismatch_directory_fires_warning() {
    // name: other-name inside directory my-skill → should fire.
    let base = tempfile::tempdir().unwrap();
    let skill_dir = base.path().join("my-skill");
    std::fs::create_dir_all(&skill_dir).unwrap();
    write_skill_md(
        &skill_dir,
        "---\nname: other-name\ndescription: A skill. Use when needed.\nallowed-tools:\n  - Bash(find)\n---\n",
    );
    let result = scan_dir(&skill_dir);
    let found = result.findings.iter().any(|f| {
        f.rule_id == "frontmatter/name-directory-mismatch" && f.severity == Severity::Warning
    });
    assert!(
        found,
        "name-directory-mismatch (Warning) must fire when name != directory name"
    );
}

#[test]
fn name_mismatch_fixture_fires() {
    // The name-mismatch-skill fixture has name: wrong-name but lives in name-mismatch-skill/
    let result = scan_fixture("name-mismatch-skill");
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-directory-mismatch");
    assert!(
        found,
        "name-mismatch-skill fixture should trigger frontmatter/name-directory-mismatch"
    );
}

// Bug regression: name-directory-mismatch must not fire when invalid-name-format already did
#[test]
fn invalid_name_format_suppresses_directory_mismatch_finding() {
    // 'My_Skill' is malformed (uppercase + underscore) → invalid-name-format fires.
    // It also differs from the directory 'my-skill', but name-directory-mismatch
    // should be suppressed to avoid noisy double-reporting.
    let base = tempfile::tempdir().unwrap();
    let skill_dir = base.path().join("my-skill");
    std::fs::create_dir_all(&skill_dir).unwrap();
    write_skill_md(
        &skill_dir,
        "---\nname: My_Skill\ndescription: A skill. Use when needed.\nallowed-tools:\n  - Bash(find)\n---\n",
    );
    let result = scan_dir(&skill_dir);
    let has_format = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/invalid-name-format");
    let has_mismatch = result
        .findings
        .iter()
        .any(|f| f.rule_id == "frontmatter/name-directory-mismatch");
    assert!(
        has_format,
        "invalid-name-format must still fire for 'My_Skill'"
    );
    assert!(
        !has_mismatch,
        "name-directory-mismatch must be suppressed when invalid-name-format already fired"
    );
}

// ---------------------------------------------------------------------------
// Bug regression: comment with colon inside block sequence must not drop items
// ---------------------------------------------------------------------------

#[test]
fn comment_with_colon_inside_allowed_tools_sequence_does_not_drop_items() {
    // A YAML comment like `# See https://docs.example.com` contains a colon.
    // Before the fix, parse_kv would parse the comment as key="# See https"
    // and overwrite current_key, causing the next list item to be dropped.
    // After the fix, comment lines are skipped entirely before parse_kv is called.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("my-skill")).unwrap();
    // Write a SKILL.md with an unscoped Bash followed by a comment containing a colon
    // and then a Write entry.  Before the fix, parse_kv would parse the comment as
    // key="# See https" and overwrite current_key, causing Write to be silently dropped.
    write_skill_md(
        &dir.path().join("my-skill"),
        "---\nname: my-skill\ndescription: A skill. Use when needed.\nallowed-tools:\n  - Bash\n# See https://docs.example.com for more info\n  - Write\n---\n",
    );
    let skill_dir = dir.path().join("my-skill");
    let result = scan_dir(&skill_dir);
    // bare-bash-tool MUST fire because Bash (unscoped) is present — if the comment
    // had corrupted current_key and dropped Write, the parser would still see Bash.
    // More importantly, the allowed_tools list must contain 2 entries: Bash + Write.
    let bare_bash: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "frontmatter/bare-bash-tool")
        .collect();
    assert!(
        bare_bash.len() == 1,
        "bare-bash-tool must fire exactly once for unscoped Bash; comment must not corrupt parsing"
    );
    // The key assertion: scan must not emit a missing-skill-md error.
    let missing: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "frontmatter/missing-skill-md")
        .collect();
    assert!(
        missing.is_empty(),
        "Comment with colon must not corrupt frontmatter parsing"
    );
}

#[test]
fn comment_without_colon_inside_block_sequence_does_not_drop_items() {
    // Plain comments (no colon) were always handled, but verify they still work.
    let base = tempfile::tempdir().unwrap();
    let skill_dir = base.path().join("my-skill");
    std::fs::create_dir_all(&skill_dir).unwrap();
    write_skill_md(
        &skill_dir,
        "---\nname: my-skill\ndescription: A skill. Use when needed.\nallowed-tools:\n  - Bash(find)\n# plain comment no colon\n  - Write\n---\n",
    );
    let result = scan_dir(&skill_dir);
    let bare_bash: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "frontmatter/bare-bash-tool")
        .collect();
    assert!(
        bare_bash.is_empty(),
        "Scoped Bash(find) with a plain comment must not fire bare-bash-tool"
    );
}
