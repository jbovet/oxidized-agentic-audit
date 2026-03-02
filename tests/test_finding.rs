use std::path::PathBuf;

use oxidized_skills::config::Suppression;
use oxidized_skills::finding::{AuditReport, Finding, ScanResult, SecurityGrade, Severity};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_finding(file: &str) -> Finding {
    Finding {
        rule_id: "bash/CAT-H1".to_string(),
        message: "outbound HTTP".to_string(),
        severity: Severity::Warning,
        file: Some(PathBuf::from(file)),
        line: Some(5),
        column: None,
        scanner: "bash_patterns".to_string(),
        snippet: None,
        suppressed: false,
        suppression_reason: None,
        remediation: None,
    }
}

fn make_suppression(file: &str) -> Suppression {
    Suppression {
        rule: "bash/CAT-H1".to_string(),
        file: file.to_string(),
        lines: None,
        reason: "approved".to_string(),
        ticket: None,
    }
}

fn build_report(finding: Finding, suppression: Suppression) -> AuditReport {
    let result = ScanResult {
        scanner_name: "bash_patterns".to_string(),
        findings: vec![finding],
        files_scanned: 1,
        skipped: false,
        skip_reason: None,
        error: None,
        duration_ms: 0,
    };
    AuditReport::from_results("test-skill", vec![result], &[suppression], false)
}

// --- Positive cases: suppression SHOULD match ---

#[test]
fn suppression_matches_exact_filename() {
    let report = build_report(
        make_finding("/path/to/scripts/test.sh"),
        make_suppression("test.sh"),
    );
    assert!(
        report.findings.is_empty(),
        "Suppression for 'test.sh' should match finding in '/path/to/scripts/test.sh'"
    );
    assert_eq!(report.suppressed.len(), 1);
}

#[test]
fn suppression_matches_multicomponent_suffix() {
    let report = build_report(
        make_finding("/path/to/scripts/test.sh"),
        make_suppression("scripts/test.sh"),
    );
    assert!(
        report.findings.is_empty(),
        "Suppression for 'scripts/test.sh' should match the full path"
    );
}

// --- Negative cases: suppression must NOT match ---

#[test]
fn suppression_does_not_match_filename_with_same_suffix() {
    // Old string ends_with bug: "maltest.sh".ends_with("test.sh") == true.
    // Path::ends_with checks component boundaries, so this must NOT match.
    let report = build_report(
        make_finding("/path/to/scripts/maltest.sh"),
        make_suppression("test.sh"),
    );
    assert!(
        !report.findings.is_empty(),
        "Suppression for 'test.sh' must NOT match 'maltest.sh'"
    );
    assert!(report.suppressed.is_empty());
}

#[test]
fn suppression_does_not_match_different_directory() {
    let report = build_report(
        make_finding("/path/to/other/test.sh"),
        make_suppression("scripts/test.sh"),
    );
    assert!(
        !report.findings.is_empty(),
        "Suppression for 'scripts/test.sh' must NOT match 'other/test.sh'"
    );
}

// ---------------------------------------------------------------------------
// Fix #6: inverted line ranges must not silently suppress nothing
// ---------------------------------------------------------------------------

fn make_finding_at_line(file: &str, line: usize) -> Finding {
    Finding {
        rule_id: "bash/CAT-H1".to_string(),
        message: "outbound HTTP".to_string(),
        severity: Severity::Warning,
        file: Some(PathBuf::from(file)),
        line: Some(line),
        column: None,
        scanner: "bash_patterns".to_string(),
        snippet: None,
        suppressed: false,
        suppression_reason: None,
        remediation: None,
    }
}

#[test]
fn inverted_line_range_does_not_suppress_finding() {
    // Suppression with "100-50" is an inverted range — should be rejected, not match everything.
    let suppression = Suppression {
        rule: "bash/CAT-H1".to_string(),
        file: "test.sh".to_string(),
        lines: Some("100-50".to_string()),
        reason: "test".to_string(),
        ticket: None,
    };
    let result = ScanResult {
        scanner_name: "bash_patterns".to_string(),
        findings: vec![make_finding_at_line("/path/to/test.sh", 75)],
        files_scanned: 1,
        skipped: false,
        skip_reason: None,
        error: None,
        duration_ms: 0,
    };
    let report = AuditReport::from_results("test-skill", vec![result], &[suppression], false);
    assert!(
        !report.findings.is_empty(),
        "Inverted line range '100-50' must not suppress finding at line 75"
    );
    assert!(report.suppressed.is_empty());
}

#[test]
fn valid_line_range_suppresses_finding_within_range() {
    let suppression = Suppression {
        rule: "bash/CAT-H1".to_string(),
        file: "test.sh".to_string(),
        lines: Some("50-100".to_string()),
        reason: "approved".to_string(),
        ticket: None,
    };
    let result = ScanResult {
        scanner_name: "bash_patterns".to_string(),
        findings: vec![make_finding_at_line("/path/to/test.sh", 75)],
        files_scanned: 1,
        skipped: false,
        skip_reason: None,
        error: None,
        duration_ms: 0,
    };
    let report = AuditReport::from_results("test-skill", vec![result], &[suppression], false);
    assert!(
        report.findings.is_empty(),
        "Valid range '50-100' should suppress finding at line 75"
    );
    assert_eq!(report.suppressed.len(), 1);
}

// ---------------------------------------------------------------------------
// Security score tests
// ---------------------------------------------------------------------------

fn make_report_from_findings(findings: Vec<Finding>) -> AuditReport {
    let result = ScanResult {
        scanner_name: "test".to_string(),
        findings,
        files_scanned: 1,
        skipped: false,
        skip_reason: None,
        error: None,
        duration_ms: 0,
    };
    AuditReport::from_results("score-test", vec![result], &[], false)
}

fn error_finding(rule_id: &str) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        message: "test".to_string(),
        severity: Severity::Error,
        file: None,
        line: None,
        column: None,
        scanner: "test".to_string(),
        snippet: None,
        suppressed: false,
        suppression_reason: None,
        remediation: None,
    }
}

fn warning_finding() -> Finding {
    Finding {
        rule_id: "bash/CAT-H1".to_string(),
        message: "test".to_string(),
        severity: Severity::Warning,
        file: None,
        line: None,
        column: None,
        scanner: "test".to_string(),
        snippet: None,
        suppressed: false,
        suppression_reason: None,
        remediation: None,
    }
}

fn info_finding() -> Finding {
    Finding {
        rule_id: "bash/CAT-H1".to_string(),
        message: "test".to_string(),
        severity: Severity::Info,
        file: None,
        line: None,
        column: None,
        scanner: "test".to_string(),
        snippet: None,
        suppressed: false,
        suppression_reason: None,
        remediation: None,
    }
}

#[test]
fn clean_skill_scores_100_grade_a() {
    let report = make_report_from_findings(vec![]);
    assert_eq!(report.security_score, 100);
    assert_eq!(report.security_grade, SecurityGrade::A);
}

#[test]
fn single_warning_deducts_5_points() {
    // 100 - 5 = 95 → grade A
    let report = make_report_from_findings(vec![warning_finding()]);
    assert_eq!(report.security_score, 95);
    assert_eq!(report.security_grade, SecurityGrade::A);
}

#[test]
fn single_info_deducts_1_point() {
    // 100 - 1 = 99 → grade A
    let report = make_report_from_findings(vec![info_finding()]);
    assert_eq!(report.security_score, 99);
    assert_eq!(report.security_grade, SecurityGrade::A);
}

#[test]
fn regular_error_deducts_15_points() {
    // 100 - 15 = 85 → grade B
    let report = make_report_from_findings(vec![error_finding("bash/CAT-G1")]);
    assert_eq!(report.security_score, 85);
    assert_eq!(report.security_grade, SecurityGrade::B);
}

#[test]
fn critical_rce_error_deducts_30_points() {
    // bash/CAT-A is an RCE category → 100 - 30 = 70 → grade C
    let report = make_report_from_findings(vec![error_finding("bash/CAT-A-001")]);
    assert_eq!(report.security_score, 70);
    assert_eq!(report.security_grade, SecurityGrade::C);
}

#[test]
fn critical_prompt_injection_error_deducts_30_points() {
    // prompt/ prefix is critical → 100 - 30 = 70 → grade C
    let report = make_report_from_findings(vec![error_finding("prompt/P01")]);
    assert_eq!(report.security_score, 70);
    assert_eq!(report.security_grade, SecurityGrade::C);
}

#[test]
fn multiple_findings_accumulate_deductions() {
    // 1 critical error (-30) + 1 warning (-5) + 1 info (-1) = -36 → score 64 → grade C
    let findings = vec![
        error_finding("bash/CAT-D-001"),
        warning_finding(),
        info_finding(),
    ];
    let report = make_report_from_findings(findings);
    assert_eq!(report.security_score, 64);
    assert_eq!(report.security_grade, SecurityGrade::C);
}

#[test]
fn score_floors_at_zero() {
    // 4 critical errors → -120 → clamped to 0 → grade F
    let findings = vec![
        error_finding("bash/CAT-A-001"),
        error_finding("bash/CAT-A-002"),
        error_finding("bash/CAT-A-003"),
        error_finding("bash/CAT-A-004"),
    ];
    let report = make_report_from_findings(findings);
    assert_eq!(report.security_score, 0);
    assert_eq!(report.security_grade, SecurityGrade::F);
}

#[test]
fn grade_d_boundary_at_40() {
    // 4 regular errors → -60 → score 40 → grade D (lower bound of D)
    let findings = vec![
        error_finding("bash/CAT-G1"),
        error_finding("bash/CAT-G1"),
        error_finding("bash/CAT-G1"),
        error_finding("bash/CAT-G1"),
    ];
    let report = make_report_from_findings(findings);
    assert_eq!(report.security_score, 40);
    assert_eq!(report.security_grade, SecurityGrade::D);
}
