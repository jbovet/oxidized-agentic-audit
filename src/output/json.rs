//! JSON output formatter.
//!
//! Produces a pretty-printed JSON document containing skill metadata, a
//! severity summary, active findings, and suppressed findings.

use crate::finding::AuditReport;

#[derive(serde::Serialize)]
struct JsonOutput<'a> {
    skill: &'a str,
    version: &'a Option<String>,
    audit_timestamp: &'a str,
    status: &'a crate::finding::AuditStatus,
    risk_level: &'a crate::finding::RiskLevel,
    security_score: u8,
    security_grade: &'a crate::finding::SecurityGrade,
    passed: bool,
    summary: Summary,
    findings: &'a [crate::finding::Finding],
    suppressed: &'a [crate::finding::Finding],
}

#[derive(serde::Serialize)]
struct Summary {
    errors: usize,
    warnings: usize,
    info: usize,
    suppressed: usize,
}

/// Formats an [`AuditReport`] as pretty-printed JSON.
///
/// The output includes skill metadata, a severity summary object, and the
/// full list of active and suppressed findings.
///
/// # Panics
///
/// Panics if the report cannot be serialized (should not happen with valid data).
pub fn format(report: &AuditReport) -> String {
    let output = JsonOutput {
        skill: &report.skill,
        version: &report.version,
        audit_timestamp: &report.audit_timestamp,
        status: &report.status,
        risk_level: &report.risk_level,
        security_score: report.security_score,
        security_grade: &report.security_grade,
        passed: report.passed,
        summary: {
            // Single pass over findings instead of three separate iterations.
            let (errors, warnings, info) = report.count_by_severity();
            Summary {
                errors,
                warnings,
                info,
                suppressed: report.suppressed.len(),
            }
        },
        findings: &report.findings,
        suppressed: &report.suppressed,
    };

    serde_json::to_string_pretty(&output).expect("JSON serialization failed")
}
