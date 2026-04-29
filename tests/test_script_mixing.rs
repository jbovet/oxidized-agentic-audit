use std::path::Path;

use oxidized_agentic_audit::config::Config;
use oxidized_agentic_audit::finding::Severity;
use oxidized_agentic_audit::scanners::script_mixing::ScriptMixingScanner;
use oxidized_agentic_audit::scanners::Scanner;

fn scan_fixture(fixture: &str) -> oxidized_agentic_audit::finding::ScanResult {
    let config = Config::default();
    let path = Path::new("tests/fixtures").join(fixture);
    ScriptMixingScanner.scan(&path, &config)
}

#[test]
fn script_mixing_fixture_runs_without_skip_or_error() {
    let result = scan_fixture("script-mixing-skill");
    assert!(!result.skipped, "scanner must not skip");
    assert!(
        result.error.is_none(),
        "scanner must not error: {:?}",
        result.error
    );
    assert!(
        result.files_scanned >= 1,
        "fixture has SKILL.md, got {}",
        result.files_scanned
    );
}

#[test]
fn script_mixing_detects_mixed_scripts_in_frontmatter() {
    let result = scan_fixture("script-mixing-skill");
    let mixed_scripts: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "script/SM3-mixed-scripts")
        .collect();

    // The name field contains Cyrillic 'а' mixed with Latin characters
    assert!(
        mixed_scripts.len() >= 1,
        "should detect mixed scripts in frontmatter, got {}",
        mixed_scripts.len()
    );
}

#[test]
fn script_mixing_detects_homoglyphs() {
    let result = scan_fixture("script-mixing-skill");
    let homoglyphs: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "script/SM1-homoglyph")
        .collect();

    // The body contains Greek 'ο' (looks like 'o')
    assert!(
        homoglyphs.len() >= 1,
        "should detect homoglyphs (Greek ο), got {} findings",
        homoglyphs.len()
    );

    if let Some(finding) = homoglyphs.first() {
        assert_eq!(finding.severity, Severity::Warning);
        assert!(finding.message.contains("Homoglyph") || finding.message.contains("Greek"));
    }
}

#[test]
fn script_mixing_detects_bidi_overrides() {
    let result = scan_fixture("script-mixing-skill");
    let bidi: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "script/SM2-bidi-override")
        .collect();

    // The body contains RTL override marks (U+202E)
    assert!(
        bidi.len() >= 1,
        "should detect bidirectional override marks, got {}",
        bidi.len()
    );

    if let Some(finding) = bidi.first() {
        assert_eq!(
            finding.severity,
            Severity::Error,
            "bidi override should be Error severity"
        );
    }
}
