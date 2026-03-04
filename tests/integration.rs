use assert_cmd::Command;
use predicates::prelude::*;

fn oxidized_skills() -> Command {
    assert_cmd::cargo::cargo_bin_cmd!("oxidized-skills")
}

#[test]
fn audit_clean_skill_passes() {
    oxidized_skills()
        .args(["audit", "tests/fixtures/clean-skill"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"));
}

#[test]
fn audit_dirty_skill_fails() {
    oxidized_skills()
        .args(["audit", "tests/fixtures/dirty-skill"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("FAIL"));
}

#[test]
fn audit_dirty_skill_json_format() {
    oxidized_skills()
        .args(["audit", "tests/fixtures/dirty-skill", "--format", "json"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"passed\": false"));
}

#[test]
fn audit_dirty_skill_sarif_format() {
    oxidized_skills()
        .args(["audit", "tests/fixtures/dirty-skill", "--format", "sarif"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"version\": \"2.1.0\""));
}

#[test]
fn audit_suppressed_skill() {
    oxidized_skills()
        .args(["audit", "tests/fixtures/suppressed-skill"])
        .assert()
        .success();
}

#[test]
fn audit_nonexistent_path_exits_2() {
    oxidized_skills()
        .args(["audit", "tests/fixtures/does-not-exist"])
        .assert()
        .code(2);
}

#[test]
fn check_tools_succeeds() {
    oxidized_skills()
        .args(["check-tools"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Scanner Availability"));
}

#[test]
fn list_rules_shows_rules() {
    oxidized_skills()
        .args(["list-rules"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bash/CAT-A1"))
        .stdout(predicate::str::contains("prompt/override-ignore"))
        .stdout(predicate::str::contains("pkg/F1-npm"));
}

#[test]
fn explain_known_rule() {
    oxidized_skills()
        .args(["explain", "bash/CAT-A1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bash/CAT-A1"))
        .stdout(predicate::str::contains("Remediation"));
}

#[test]
fn explain_unknown_rule_exits_2() {
    oxidized_skills()
        .args(["explain", "nonexistent/rule"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Unknown rule"));
}

#[test]
fn strict_mode_fails_on_warnings() {
    // dirty-skill has warnings (e.g., CAT-E1 sudo bash = warning)
    // Without strict, it fails anyway due to errors. Let's create a fixture with only warnings.
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(scripts_dir.join("test.sh"), "#!/bin/bash\nsudo bash\n").unwrap();

    oxidized_skills()
        .args(["audit", dir.path().to_str().unwrap(), "--strict"])
        .assert()
        .code(1);
}

#[test]
fn output_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let output_file = dir.path().join("report.json");

    oxidized_skills()
        .args([
            "audit",
            "tests/fixtures/dirty-skill",
            "--format",
            "json",
            "--output",
            output_file.to_str().unwrap(),
        ])
        .assert()
        .code(1);

    let content = std::fs::read_to_string(&output_file).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("Output file should contain valid JSON");
    assert!(!parsed["passed"].as_bool().unwrap());
}

// ── audit-all & collection-dir detection ─────────────────────────────────────

#[test]
fn audit_collection_dir_shows_hint_and_exits_2() {
    // tests/fixtures/ has subdirs with SKILL.md but no top-level SKILL.md —
    // exactly the collection-directory pattern we want to detect.
    oxidized_skills()
        .args(["audit", "tests/fixtures"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "looks like a skills collection directory",
        ))
        .stderr(predicate::str::contains("audit-all"));
}

#[test]
fn audit_all_discovers_skills_and_prints_summary() {
    oxidized_skills()
        .args(["audit-all", "tests/fixtures"])
        .assert()
        // At least one fixture skill fails — exit 1
        .code(1)
        .stdout(predicate::str::contains("Collection Summary"))
        .stdout(predicate::str::contains("Total:"));
}

#[test]
fn audit_all_exits_0_when_all_pass() {
    let dir = tempfile::tempdir().unwrap();
    // Populate two minimal passing skills (name matches directory to satisfy name-directory-mismatch rule)
    for name in &["alpha", "beta"] {
        let skill_dir = dir.path().join(name);
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: A test skill. Use when testing.\nallowed-tools:\n  - Read\n---\n# Test\n"),
        )
        .unwrap();
    }

    oxidized_skills()
        .args(["audit-all", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Collection Summary"))
        .stdout(predicate::str::contains("2 skills"));
}

#[test]
fn audit_all_empty_dir_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    oxidized_skills()
        .args(["audit-all", dir.path().to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no skill directories found"));
}

#[test]
fn audit_all_nonexistent_path_exits_2() {
    oxidized_skills()
        .args(["audit-all", "tests/fixtures/does-not-exist"])
        .assert()
        .code(2);
}

// ── --min-score ───────────────────────────────────────────────────────────────

#[test]
fn min_score_passes_when_clean_skill_meets_threshold() {
    // clean-skill scores 100 — any reasonable min-score should pass.
    oxidized_skills()
        .args(["audit", "tests/fixtures/clean-skill", "--min-score", "80"])
        .assert()
        .success();
}

#[test]
fn min_score_fails_when_score_below_threshold() {
    // dirty-skill scores 0 — threshold of 1 should fail.
    oxidized_skills()
        .args(["audit", "tests/fixtures/dirty-skill", "--min-score", "1"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("below the required minimum"));
}

#[test]
fn min_score_error_message_shows_score_and_threshold() {
    oxidized_skills()
        .args(["audit", "tests/fixtures/dirty-skill", "--min-score", "50"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("50"));
}

#[test]
fn min_score_zero_always_passes_clean_skill() {
    // --min-score 0 is a no-op; clean skill passes.
    oxidized_skills()
        .args(["audit", "tests/fixtures/clean-skill", "--min-score", "0"])
        .assert()
        .success();
}

#[test]
fn min_score_audit_all_fails_when_any_skill_below_threshold() {
    // fixtures/ contains dirty-skill (score 0) — threshold of 50 must fail.
    oxidized_skills()
        .args(["audit-all", "tests/fixtures", "--min-score", "50"])
        .assert()
        .code(1);
}

#[test]
fn min_score_audit_all_shows_marker_in_summary() {
    // The collection summary should annotate skills below the threshold with [< N].
    oxidized_skills()
        .args(["audit-all", "tests/fixtures", "--min-score", "50"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[< 50]"));
}

#[test]
fn min_score_audit_all_shows_below_min_count_in_footer() {
    oxidized_skills()
        .args(["audit-all", "tests/fixtures", "--min-score", "50"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("below min-score"));
}

#[test]
fn min_score_audit_all_passes_when_all_above_threshold() {
    let dir = tempfile::tempdir().unwrap();
    // name matches directory to satisfy name-directory-mismatch rule
    for name in &["alpha", "beta"] {
        let skill_dir = dir.path().join(name);
        std::fs::create_dir_all(&skill_dir).unwrap();
        let skill_md = format!("---\nname: {name}\ndescription: A test skill. Use when testing.\nallowed-tools:\n  - Read\n---\n# Test\n");
        std::fs::write(skill_dir.join("SKILL.md"), skill_md).unwrap();
    }

    // Both skills are clean (score 100) — min-score 80 must succeed.
    oxidized_skills()
        .args([
            "audit-all",
            dir.path().to_str().unwrap(),
            "--min-score",
            "80",
        ])
        .assert()
        .success();
}

// ── shellcheck fixture ────────────────────────────────────────────────────────

#[test]
fn audit_shellcheck_skill_has_findings_when_tool_available() {
    // Only run assertions if shellcheck is installed
    let sc_available = std::process::Command::new("which")
        .arg("shellcheck")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !sc_available {
        // Just verify the audit runs cleanly when tool is missing (skipped)
        oxidized_skills()
            .args([
                "audit",
                "tests/fixtures/shellcheck-skill",
                "--format",
                "json",
            ])
            .assert()
            .success();
        return;
    }

    // shellcheck is present — the fixture has intentional SC2086 violations
    let output = oxidized_skills()
        .args([
            "audit",
            "tests/fixtures/shellcheck-skill",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Should produce valid JSON");

    // Verify at least one shellcheck finding appears
    let findings = parsed["findings"].as_array().unwrap();
    let sc_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f["rule_id"]
                .as_str()
                .map(|id| id.starts_with("shellcheck/SC"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !sc_findings.is_empty(),
        "Expected at least one shellcheck/SC finding in shellcheck-skill audit"
    );
}

// ── secrets fixture ───────────────────────────────────────────────────────────

#[test]
fn audit_secrets_skill_detects_leaked_key_when_gitleaks_available() {
    let gitleaks_available = std::process::Command::new("which")
        .arg("gitleaks")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !gitleaks_available {
        // Just verify the audit runs (secrets scanner is skipped)
        oxidized_skills()
            .args(["audit", "tests/fixtures/secrets-skill", "--format", "json"])
            .assert()
            .success();
        return;
    }

    // gitleaks present — fixture has fake AWS keys
    let output = oxidized_skills()
        .args(["audit", "tests/fixtures/secrets-skill", "--format", "json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Should produce valid JSON");

    let findings = parsed["findings"].as_array().unwrap();
    let secret_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f["rule_id"]
                .as_str()
                .map(|id| id.starts_with("secrets/"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !secret_findings.is_empty(),
        "Expected gitleaks to detect the fake AWS key in secrets-skill fixture"
    );
}
