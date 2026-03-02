use oxidized_skills::config::Config;
use oxidized_skills::output;
use oxidized_skills::output::OutputFormat;
use std::path::Path;

fn get_dirty_report() -> oxidized_skills::finding::AuditReport {
    let config = Config::default();
    oxidized_skills::audit::run_audit(Path::new("tests/fixtures/dirty-skill"), &config)
}

fn get_clean_report() -> oxidized_skills::finding::AuditReport {
    let config = Config::default();
    oxidized_skills::audit::run_audit(Path::new("tests/fixtures/clean-skill"), &config)
}

#[test]
fn json_output_is_valid() {
    let report = get_dirty_report();
    let json = output::format_report(&report, &OutputFormat::Json);

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");
    assert!(parsed["skill"].is_string());
    assert!(parsed["findings"].is_array());
    assert!(parsed["summary"]["errors"].is_number());
    assert!(!parsed["passed"].as_bool().unwrap());
}

#[test]
fn json_clean_skill_passes() {
    let report = get_clean_report();
    let json = output::format_report(&report, &OutputFormat::Json);

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");
    assert!(parsed["passed"].as_bool().unwrap());
}

#[test]
fn sarif_output_is_valid() {
    let report = get_dirty_report();
    let sarif = output::format_report(&report, &OutputFormat::Sarif);

    let parsed: serde_json::Value =
        serde_json::from_str(&sarif).expect("SARIF JSON should be valid");
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"].is_array());
    assert!(parsed["runs"][0]["tool"]["driver"]["name"] == "oxidized-skills");
    assert!(parsed["runs"][0]["results"].is_array());
}

#[test]
fn sarif_run_properties_contains_security_score_and_grade() {
    let report = get_dirty_report();
    let sarif = output::format_report(&report, &OutputFormat::Sarif);

    let parsed: serde_json::Value =
        serde_json::from_str(&sarif).expect("SARIF JSON should be valid");

    let props = &parsed["runs"][0]["properties"];
    assert!(
        props["security_score"].is_number(),
        "SARIF run.properties should contain a numeric security_score"
    );
    assert!(
        props["security_grade"].is_string(),
        "SARIF run.properties should contain a string security_grade"
    );
    let score = props["security_score"].as_u64().unwrap();
    assert!(score < 100, "Dirty skill SARIF security_score should be below 100");
}

#[test]
fn sarif_clean_skill_shows_perfect_score() {
    let report = get_clean_report();
    let sarif = output::format_report(&report, &OutputFormat::Sarif);

    let parsed: serde_json::Value =
        serde_json::from_str(&sarif).expect("SARIF JSON should be valid");

    let props = &parsed["runs"][0]["properties"];
    assert_eq!(
        props["security_score"].as_u64().unwrap(),
        100,
        "Clean skill SARIF security_score should be 100"
    );
    assert_eq!(
        props["security_grade"].as_str().unwrap(),
        "A",
        "Clean skill SARIF security_grade should be A"
    );
}

#[test]
fn pretty_output_contains_findings() {
    let report = get_dirty_report();
    let pretty = output::format_report(&report, &OutputFormat::Pretty);

    assert!(pretty.contains("dirty-skill"));
    assert!(pretty.contains("FAIL") || pretty.contains("ERROR"));
}

#[test]
fn pretty_output_clean_passes() {
    let report = get_clean_report();
    let pretty = output::format_report(&report, &OutputFormat::Pretty);

    assert!(pretty.contains("clean-skill"));
    assert!(pretty.contains("PASS"));
}

#[test]
fn json_contains_severity_levels() {
    let report = get_dirty_report();
    let json = output::format_report(&report, &OutputFormat::Json);

    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let findings = parsed["findings"].as_array().unwrap();

    let has_error = findings.iter().any(|f| f["severity"] == "error");
    let has_warning = findings.iter().any(|f| f["severity"] == "warning");

    assert!(has_error, "Should have at least one error finding");
    assert!(has_warning, "Should have at least one warning finding");
}

#[test]
fn clean_skill_pretty_output_shows_perfect_score() {
    let report = get_clean_report();
    let pretty = output::format_report(&report, &OutputFormat::Pretty);

    // Strip ANSI codes for assertion (colored adds escape sequences in tests)
    let stripped = strip_ansi(&pretty);
    assert!(
        stripped.contains("Score: 100/100 (A)"),
        "Clean skill should show Score: 100/100 (A), got: {stripped}"
    );
}

#[test]
fn dirty_skill_pretty_output_shows_degraded_score() {
    let report = get_dirty_report();
    let pretty = output::format_report(&report, &OutputFormat::Pretty);

    let stripped = strip_ansi(&pretty);
    // Score must appear and be below 100
    assert!(
        stripped.contains("Score:"),
        "Pretty output should always contain a Score field"
    );
    assert!(
        !stripped.contains("Score: 100/100"),
        "Dirty skill must not show a perfect score"
    );
}

#[test]
fn json_output_contains_security_score_and_grade() {
    let report = get_dirty_report();
    let json = output::format_report(&report, &OutputFormat::Json);

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");
    assert!(
        parsed["security_score"].is_number(),
        "JSON should contain a numeric security_score field"
    );
    assert!(
        parsed["security_grade"].is_string(),
        "JSON should contain a string security_grade field"
    );
    let score = parsed["security_score"].as_u64().unwrap();
    assert!(score < 100, "Dirty skill security_score should be below 100");
}

#[test]
fn clean_skill_json_shows_perfect_score() {
    let report = get_clean_report();
    let json = output::format_report(&report, &OutputFormat::Json);

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");
    assert_eq!(
        parsed["security_score"].as_u64().unwrap(),
        100,
        "Clean skill should have security_score of 100"
    );
    assert_eq!(
        parsed["security_grade"].as_str().unwrap(),
        "A",
        "Clean skill should have security_grade of A"
    );
}

/// Removes ANSI escape sequences so assertions on colored strings work reliably.
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Consume everything up to and including the final byte of the escape sequence.
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                for ch in chars.by_ref() {
                    // CSI sequences end with a byte in 0x40–0x7E
                    if ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}
