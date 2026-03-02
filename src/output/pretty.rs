//! Human-readable colored text formatter.
//!
//! Produces a terminal-friendly report with ANSI color codes, showing scanner
//! statuses, individual findings with source locations, suppressed items, and
//! a one-line summary.

use crate::finding::{AuditReport, AuditStatus, Severity};
use colored::Colorize;

/// Formats an [`AuditReport`] as human-readable, ANSI-colored text.
///
/// Sections rendered (in order):
/// 1. **Header** — skill name and timestamp.
/// 2. **Scanners** — per-scanner pass/fail/skip status.
/// 3. **Findings** — active findings with severity, rule, location, and snippet.
/// 4. **Suppressed** — suppressed findings with reasons.
/// 5. **Summary** — overall status and severity counts.
pub fn format(report: &AuditReport) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "\n{}\n",
        format!("  Skill Audit: {}  ", report.skill)
            .bold()
            .on_blue()
            .white()
    ));
    out.push_str(&format!("  Timestamp: {}\n\n", report.audit_timestamp));

    // Scanner results summary
    out.push_str(&format!("{}\n", "Scanners".bold().underline()));
    for result in &report.scanner_results {
        let disabled = result
            .skip_reason
            .as_deref()
            .map(|r| r == "disabled in config")
            .unwrap_or(false);
        let icon = if disabled {
            " OFF".dimmed().to_string()
        } else if result.skipped {
            "SKIP".dimmed().to_string()
        } else {
            // Single pass: determine both flags simultaneously instead of two
            // separate iter().any() calls over the same findings Vec.
            let (has_err, has_warn) =
                result
                    .findings
                    .iter()
                    .fold((false, false), |(e, w), f| match f.severity {
                        Severity::Error => (true, w),
                        Severity::Warning => (e, true),
                        Severity::Info => (e, w),
                    });
            if has_err {
                "FAIL".red().bold().to_string()
            } else if has_warn {
                "WARN".yellow().bold().to_string()
            } else {
                "PASS".green().bold().to_string()
            }
        };

        let detail = if disabled {
            "disabled in config".dimmed().to_string()
        } else if result.skipped {
            result
                .skip_reason
                .as_deref()
                .unwrap_or("skipped")
                .dimmed()
                .to_string()
        } else {
            let count = result.findings.len();
            let scanned = result.files_scanned;
            format!("{} findings, {} files scanned", count, scanned)
        };

        out.push_str(&format!(
            "  [{icon}] {name:<20} {detail}\n",
            name = result.scanner_name,
        ));
    }
    out.push('\n');

    // Active findings — use a peekable iterator to avoid allocating an
    // intermediate Vec just to check emptiness before the single iteration.
    let mut active_iter = report.findings.iter().filter(|f| !f.suppressed).peekable();
    if active_iter.peek().is_some() {
        out.push_str(&format!("{}\n", "Findings".bold().underline()));
        for finding in active_iter {
            let severity_str = match finding.severity {
                Severity::Error => "ERROR".red().bold().to_string(),
                Severity::Warning => " WARN".yellow().bold().to_string(),
                Severity::Info => " INFO".blue().to_string(),
            };

            let location = match (&finding.file, finding.line) {
                (Some(f), Some(l)) => format!("{}:{}", f.display(), l),
                (Some(f), None) => format!("{}", f.display()),
                _ => String::new(),
            };

            out.push_str(&format!(
                "  [{severity_str}] {rule_id:<25} {message}\n",
                rule_id = finding.rule_id.dimmed(),
                message = finding.message,
            ));
            if !location.is_empty() {
                out.push_str(&format!("         {}\n", location.dimmed()));
            }
            if let Some(ref snippet) = finding.snippet {
                out.push_str(&format!("         > {}\n", snippet.dimmed()));
            }
        }
        out.push('\n');
    }

    // Suppressed findings
    if !report.suppressed.is_empty() {
        out.push_str(&format!(
            "{} ({} suppressed)\n",
            "Suppressed".bold().underline(),
            report.suppressed.len()
        ));
        for finding in &report.suppressed {
            let reason = finding
                .suppression_reason
                .as_deref()
                .unwrap_or("no reason given");
            out.push_str(&format!(
                "  [SKIP] {:<25} {}\n",
                finding.rule_id.dimmed(),
                reason.dimmed(),
            ));
        }
        out.push('\n');
    }

    // Summary
    let status_str = match report.status {
        AuditStatus::Passed => "PASSED".green().bold().to_string(),
        AuditStatus::Warning => "WARNING".yellow().bold().to_string(),
        AuditStatus::Failed => "FAILED".red().bold().to_string(),
    };

    let score_str = {
        let s = format!(
            "Score: {}/100 ({})",
            report.security_score, report.security_grade
        );
        match report.security_score {
            90..=100 => s.green().bold().to_string(),
            60..=89 => s.yellow().bold().to_string(),
            _ => s.red().bold().to_string(),
        }
    };

    // Single pass for all three severity counts.
    let (errors, warnings, info) = report.count_by_severity();
    out.push_str(&format!(
        "Result: {status_str}  |  {score_str}  |  {} errors, {} warnings, {} info, {} suppressed\n",
        errors,
        warnings,
        info,
        report.suppressed.len(),
    ));

    out
}
