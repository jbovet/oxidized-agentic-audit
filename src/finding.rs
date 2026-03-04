//! Core data types for audit findings and reports.
//!
//! This module contains the primary output types of the audit pipeline:
//!
//! - [`Finding`] — a single security issue detected by a scanner.
//! - [`ScanResult`] — aggregated output from one scanner run.
//! - [`AuditReport`] — the final report combining all scanners.
//! - [`Severity`], [`AuditStatus`], [`RiskLevel`], [`SecurityGrade`] — classification enums.

use std::fmt;
use std::path::PathBuf;

/// Severity level for a security finding.
///
/// Variants are ordered from most to least critical and implement [`Ord`],
/// so collections of findings can be sorted by severity.
///
/// Serializes to lowercase strings (`"error"`, `"warning"`, `"info"`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Critical issue that must be resolved before the skill can be trusted.
    Error,
    /// Potential issue that should be reviewed but may be acceptable.
    Warning,
    /// Informational observation that does not affect the audit outcome.
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
            Severity::Info => write!(f, "info"),
        }
    }
}

/// A single security finding detected by a scanner.
///
/// Each finding carries the rule it violates, a human-readable message,
/// optional source location, and remediation guidance.
///
/// # Suppression
///
/// Findings can be suppressed either by inline comments (`# audit:ignore`) or
/// by entries in a [`.oxidized-skills-ignore`](crate::config::Suppression) file.
/// When suppressed, [`suppressed`](Finding::suppressed) is `true` and the
/// finding is moved to [`AuditReport::suppressed`] instead of
/// [`AuditReport::findings`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Unique rule identifier (e.g., `"bash/CAT-A-001"`, `"prompt/P01"`).
    pub rule_id: String,
    /// Human-readable description of the issue.
    pub message: String,
    /// Severity level.
    pub severity: Severity,
    /// Path to the source file, relative to the skill root.
    pub file: Option<PathBuf>,
    /// 1-based line number inside the source file.
    pub line: Option<usize>,
    /// 1-based column number inside the source file.
    pub column: Option<usize>,
    /// Name of the scanner that produced this finding.
    pub scanner: String,
    /// Code snippet showing the offending line.
    pub snippet: Option<String>,
    /// Whether this finding has been suppressed.
    pub suppressed: bool,
    /// Reason for suppression (from a suppression rule or inline marker).
    pub suppression_reason: Option<String>,
    /// Guidance on how to resolve the issue.
    pub remediation: Option<String>,
}

/// Results from running a single [`Scanner`](crate::scanners::Scanner).
///
/// Scanners that are not installed on the host are represented as skipped
/// results (see [`ScanResult::skipped`]).
#[derive(Debug, serde::Serialize)]
pub struct ScanResult {
    /// Scanner identifier (matches [`Scanner::name`](crate::scanners::Scanner::name)).
    pub scanner_name: String,
    /// Findings produced by this scan.
    pub findings: Vec<Finding>,
    /// Number of files examined.
    pub files_scanned: usize,
    /// `true` when the scanner did not run (e.g., external tool missing).
    pub skipped: bool,
    /// Human-readable reason when `skipped` is `true`.
    pub skip_reason: Option<String>,
    /// Error message if the scanner encountered a fatal error.
    pub error: Option<String>,
    /// Wall-clock time for this scanner, in milliseconds.
    pub duration_ms: u64,
    /// Security score (0–100) for this scanner's raw findings.
    ///
    /// Computed from the scanner's own findings before suppressions are applied.
    /// `None` when the scanner was skipped, disabled, or encountered an error.
    pub scanner_score: Option<u8>,
    /// Letter grade derived from [`scanner_score`](Self::scanner_score).
    /// `None` when `scanner_score` is `None`.
    pub scanner_grade: Option<SecurityGrade>,
}

impl ScanResult {
    /// Creates a [`ScanResult`] representing a skipped scanner.
    ///
    /// Use this when a scanner cannot run — for example because its external
    /// tool is not installed.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxidized_skills::finding::ScanResult;
    ///
    /// let result = ScanResult::skipped("semgrep", "semgrep not found on PATH");
    /// assert!(result.skipped);
    /// assert_eq!(result.findings.len(), 0);
    /// ```
    pub fn skipped(name: &str, reason: &str) -> Self {
        ScanResult {
            scanner_name: name.to_string(),
            findings: vec![],
            files_scanned: 0,
            skipped: true,
            skip_reason: Some(reason.to_string()),
            error: None,
            duration_ms: 0,
            scanner_score: None,
            scanner_grade: None,
        }
    }

    /// Creates a [`ScanResult`] representing a scanner that encountered an error.
    ///
    /// Use this when a scanner fails to run — for example because the external
    /// tool exited with an unexpected error code.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxidized_skills::finding::ScanResult;
    ///
    /// let result = ScanResult::error("shellcheck", "Failed to run shellcheck".to_string(), 42);
    /// assert!(result.error.is_some());
    /// assert!(!result.skipped);
    /// ```
    pub fn error(name: &str, error: String, duration_ms: u64) -> Self {
        ScanResult {
            scanner_name: name.to_string(),
            findings: vec![],
            files_scanned: 0,
            skipped: false,
            skip_reason: None,
            error: Some(error),
            duration_ms,
            scanner_score: None,
            scanner_grade: None,
        }
    }
}

/// Complete audit report for a single skill.
///
/// Created by [`AuditReport::from_results`] after all scanners have run.
/// This is the main output of [`audit::run_audit`](crate::audit::run_audit)
/// and is consumed by the [`output`](crate::output) formatters.
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::Path;
/// use oxidized_skills::{audit, config::Config};
///
/// let config = Config::load(None).unwrap();
/// let report = audit::run_audit(Path::new("./my-skill"), &config);
///
/// println!("status: {:?}, errors: {}", report.status, report.error_count());
/// ```
#[derive(Debug, serde::Serialize)]
pub struct AuditReport {
    /// Name of the audited skill (derived from the directory name).
    pub skill: String,
    /// Optional skill version (reserved for future use).
    pub version: Option<String>,
    /// RFC 3339 timestamp of when the audit ran.
    pub audit_timestamp: String,
    /// Overall audit outcome.
    pub status: AuditStatus,
    /// Overall risk assessment.
    pub risk_level: RiskLevel,
    /// Numeric security score from 0 (worst) to 100 (best).
    ///
    /// Computed by deducting points per active finding:
    /// - Critical error (RCE/backdoor/prompt): −30
    /// - Regular error: −15
    /// - Warning: −5
    /// - Info: −1
    ///
    /// The score is clamped to [0, 100].
    pub security_score: u8,
    /// Letter grade derived from [`security_score`](Self::security_score).
    pub security_grade: SecurityGrade,
    /// Total number of files examined across all scanners.
    pub files_scanned: usize,
    /// Per-scanner results (including skipped scanners).
    pub scanner_results: Vec<ScanResult>,
    /// Active (non-suppressed) findings.
    pub findings: Vec<Finding>,
    /// Suppressed findings (kept for transparency in reports).
    pub suppressed: Vec<Finding>,
    /// Convenience flag: `true` when `status` is [`AuditStatus::Passed`].
    pub passed: bool,
}

impl AuditReport {
    /// Builds an [`AuditReport`] from raw scanner results.
    ///
    /// This constructor:
    /// 1. Separates suppressed findings from active ones.
    /// 2. Applies file-level suppression rules.
    /// 3. Computes [`AuditStatus`] and [`RiskLevel`].
    ///
    /// # Arguments
    ///
    /// * `skill`        — skill name (usually the directory basename).
    /// * `results`      — scanner results to aggregate.
    /// * `suppressions` — rules loaded from `.oxidized-skills-ignore`.
    /// * `strict`       — when `true`, warnings are treated as failures.
    pub fn from_results(
        skill: &str,
        results: Vec<ScanResult>,
        suppressions: &[crate::config::Suppression],
        strict: bool,
    ) -> Self {
        let files_scanned: usize = results.iter().map(|r| r.files_scanned).sum();

        // Pre-pass: annotate each scanner result with its own score, computed
        // on the raw (pre-suppression) findings.  Skipped / errored scanners
        // receive `None` because there are no meaningful findings to score.
        let results: Vec<ScanResult> = results
            .into_iter()
            .map(|mut r| {
                if !r.skipped && r.error.is_none() {
                    let (score, grade) = compute_security_score(&r.findings);
                    r.scanner_score = Some(score);
                    r.scanner_grade = Some(grade);
                }
                r
            })
            .collect();

        let mut active = Vec::new();
        let mut suppressed = Vec::new();

        for result in &results {
            for finding in &result.findings {
                if finding.suppressed {
                    suppressed.push(finding.clone());
                } else if let Some(s) = find_suppression(finding, suppressions) {
                    // Single call — avoids traversing the suppression list twice
                    // (once for the boolean check, once to retrieve the reason).
                    let mut f = finding.clone();
                    f.suppressed = true;
                    f.suppression_reason = Some(s.reason.clone());
                    suppressed.push(f);
                } else {
                    active.push(finding.clone());
                }
            }
        }

        let (status, risk_level, security_score, security_grade) =
            compute_audit_metrics(&active, strict);
        let passed = matches!(status, AuditStatus::Passed);

        AuditReport {
            skill: skill.to_string(),
            version: None,
            audit_timestamp: chrono::Utc::now().to_rfc3339(),
            status,
            risk_level,
            security_score,
            security_grade,
            files_scanned,
            scanner_results: results,
            findings: active,
            suppressed,
            passed,
        }
    }

    /// Returns the number of active findings with [`Severity::Error`].
    pub fn error_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count()
    }

    /// Returns the number of active findings with [`Severity::Warning`].
    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count()
    }

    /// Returns the number of active findings with [`Severity::Info`].
    pub fn info_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count()
    }

    /// Counts errors, warnings, and info findings in a single pass.
    ///
    /// Returns `(errors, warnings, info)`. Prefer this over calling
    /// [`error_count`](Self::error_count), [`warning_count`](Self::warning_count),
    /// and [`info_count`](Self::info_count) separately when all three values are
    /// needed (avoids three iterations).
    pub fn count_by_severity(&self) -> (usize, usize, usize) {
        self.findings
            .iter()
            .fold((0, 0, 0), |(e, w, i), f| match f.severity {
                Severity::Error => (e + 1, w, i),
                Severity::Warning => (e, w + 1, i),
                Severity::Info => (e, w, i + 1),
            })
    }
}

/// Overall outcome of an audit.
///
/// The status is derived from the active (non-suppressed) findings and the
/// [`StrictConfig`](crate::config::StrictConfig) setting.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditStatus {
    /// No errors or warnings (or all were suppressed).
    Passed,
    /// Warnings present, but no errors (and strict mode is off).
    Warning,
    /// Errors present, or warnings in strict mode.
    Failed,
}

/// Risk level derived from the nature of the findings.
///
/// The classification considers whether critical patterns (RCE, backdoors,
/// prompt injection) are present, not just the count of errors.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// No active findings.
    Low,
    /// Only warnings, no errors.
    Medium,
    /// Errors present but none in critical categories.
    High,
    /// Findings in critical categories (RCE, backdoor, prompt injection).
    Critical,
}

/// Letter-grade summary of a skill's security posture.
///
/// Derived from [`AuditReport::security_score`]:
///
/// | Score   | Grade |
/// |---------|-------|
/// | 90–100  | `A`   |
/// | 75–89   | `B`   |
/// | 60–74   | `C`   |
/// | 40–59   | `D`   |
/// | 0–39    | `F`   |
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecurityGrade {
    A,
    B,
    C,
    D,
    F,
}

impl fmt::Display for SecurityGrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityGrade::A => write!(f, "A"),
            SecurityGrade::B => write!(f, "B"),
            SecurityGrade::C => write!(f, "C"),
            SecurityGrade::D => write!(f, "D"),
            SecurityGrade::F => write!(f, "F"),
        }
    }
}

/// Computes status, risk level, security score, and grade in a single pass.
///
/// Used by [`AuditReport::from_results`] to derive all aggregate metrics
/// without iterating the findings list three times.
fn compute_audit_metrics(
    findings: &[Finding],
    strict: bool,
) -> (AuditStatus, RiskLevel, u8, SecurityGrade) {
    let mut has_errors = false;
    let mut has_warnings = false;
    let mut has_rce_or_backdoor = false;
    let mut deduction: u32 = 0;

    for f in findings {
        let is_critical = f.rule_id.starts_with("bash/CAT-A")
            || f.rule_id.starts_with("bash/CAT-D")
            || f.rule_id.starts_with("typescript/CAT-A")
            || f.rule_id.starts_with("typescript/CAT-D")
            || f.rule_id.starts_with("prompt/");

        match f.severity {
            Severity::Error => {
                has_errors = true;
                if is_critical {
                    has_rce_or_backdoor = true;
                    deduction += 30;
                } else {
                    deduction += 15;
                }
            }
            Severity::Warning => {
                has_warnings = true;
                deduction += 5;
            }
            Severity::Info => {
                deduction += 1;
            }
        }
    }

    let status = if has_errors {
        AuditStatus::Failed
    } else if has_warnings {
        if strict {
            AuditStatus::Failed
        } else {
            AuditStatus::Warning
        }
    } else {
        AuditStatus::Passed
    };

    let risk_level = if has_rce_or_backdoor {
        RiskLevel::Critical
    } else if has_errors {
        RiskLevel::High
    } else if has_warnings {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };

    let score = (100u32.saturating_sub(deduction)).min(100) as u8;
    let grade = match score {
        90..=100 => SecurityGrade::A,
        75..=89 => SecurityGrade::B,
        60..=74 => SecurityGrade::C,
        40..=59 => SecurityGrade::D,
        _ => SecurityGrade::F,
    };

    (status, risk_level, score, grade)
}

/// Computes the security score and grade for a set of findings.
///
/// Kept as a standalone function for per-scanner scoring in
/// [`AuditReport::from_results`].
fn compute_security_score(findings: &[Finding]) -> (u8, SecurityGrade) {
    let deduction: u32 = findings.iter().fold(0u32, |acc, f| {
        let pts: u32 = match f.severity {
            Severity::Error => {
                let is_critical = f.rule_id.starts_with("bash/CAT-A")
                    || f.rule_id.starts_with("bash/CAT-D")
                    || f.rule_id.starts_with("typescript/CAT-A")
                    || f.rule_id.starts_with("typescript/CAT-D")
                    || f.rule_id.starts_with("prompt/");
                if is_critical {
                    30
                } else {
                    15
                }
            }
            Severity::Warning => 5,
            Severity::Info => 1,
        };
        acc + pts
    });

    let score = (100u32.saturating_sub(deduction)).min(100) as u8;
    let grade = match score {
        90..=100 => SecurityGrade::A,
        75..=89 => SecurityGrade::B,
        60..=74 => SecurityGrade::C,
        40..=59 => SecurityGrade::D,
        _ => SecurityGrade::F,
    };
    (score, grade)
}

fn find_suppression<'a>(
    finding: &Finding,
    suppressions: &'a [crate::config::Suppression],
) -> Option<&'a crate::config::Suppression> {
    suppressions.iter().find(|s| {
        if s.rule != finding.rule_id {
            return false;
        }
        // Use Path::ends_with so that a suppression for "test.sh" matches
        // "/path/to/test.sh" but NOT "/path/to/maltest.sh".  A raw string
        // ends_with check fails this: "maltest.sh".ends_with("test.sh") is true.
        //
        // When the finding has no file path, the file check cannot be satisfied
        // unless the suppression also has an empty file field (wildcard).
        // Falling through unconditionally when file is None would let any
        // rule-only suppression suppress across all file-less findings.
        match &finding.file {
            Some(file) => {
                if !file.ends_with(std::path::Path::new(&s.file)) {
                    return false;
                }
            }
            None => {
                // Only allow suppression when the suppression entry does not
                // target a specific file (empty string acts as a wildcard).
                if !s.file.is_empty() {
                    return false;
                }
            }
        }
        if let (Some(ref lines), Some(line)) = (&s.lines, finding.line) {
            match parse_line_range(lines) {
                Some((start, end)) if line >= start && line <= end => {}
                // Range is either invalid (None) or the line is outside the range —
                // either way the suppression does not apply.
                _ => return false,
            }
        }
        true
    })
}

fn parse_line_range(lines: &str) -> Option<(usize, usize)> {
    let parts: Vec<&str> = lines.split('-').collect();
    if parts.len() == 2 {
        let start = parts[0].parse().ok()?;
        let end = parts[1].parse().ok()?;
        if start > end {
            return None;
        }
        Some((start, end))
    } else if parts.len() == 1 {
        let line = parts[0].parse().ok()?;
        Some((line, line))
    } else {
        None
    }
}
