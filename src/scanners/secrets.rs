//! Secret scanning via [gitleaks](https://github.com/gitleaks/gitleaks).
//!
//! This is an **external** scanner — it requires the `gitleaks` binary to
//! be installed on `PATH`.  When `gitleaks` is not found the scanner is
//! automatically marked as *skipped* by the audit runner.
//!
//! # How it works
//!
//! 1. Spawns `gitleaks detect --source <path> --no-git --report-format json
//!    --report-path <tmpfile>`.
//! 2. Parses the JSON report into [`Finding`] structs.
//! 3. Maps every leak to severity [`Error`](crate::finding::Severity::Error).
//! 4. Cleans up the temporary report file.
//!
//! # Exit codes
//!
//! - **0** — no leaks found.
//! - **1** — leaks found (expected; findings are returned).
//! - **≥ 2** — gitleaks error (e.g. 126/127 = binary not runnable).
//!
//! # Representative rules
//!
//! The [`rules`] function lists a representative subset of gitleaks rules.
//! At runtime, findings are tagged dynamically as `secrets/<RuleID>` based
//! on whatever gitleaks reports.

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{which_exists, RuleInfo, Scanner};
use std::path::Path;
use std::time::Instant;

/// External scanner wrapper for [gitleaks](https://github.com/gitleaks/gitleaks).
///
/// Runs `gitleaks detect` in `--no-git` mode against the skill directory,
/// writing results to a temporary JSON file that is parsed and converted
/// into [`Finding`] structs.  Every detected secret is reported at
/// [`Severity::Error`].
///
/// Requires `gitleaks` on `PATH`; see [`is_available`](Scanner::is_available).
pub struct SecretsScanner;

impl Scanner for SecretsScanner {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn description(&self) -> &'static str {
        "Secret scanning via gitleaks (external tool)"
    }

    fn is_available(&self) -> bool {
        which_exists("gitleaks")
    }

    fn scan(&self, path: &Path, _config: &Config) -> ScanResult {
        let start = Instant::now();

        // Write gitleaks report to a temp file so we can parse it cleanly
        let report_file = match tempfile::NamedTempFile::new() {
            Ok(f) => f,
            Err(e) => {
                return ScanResult {
                    scanner_name: self.name().to_string(),
                    findings: vec![],
                    files_scanned: 0,
                    skipped: false,
                    skip_reason: None,
                    error: Some(format!("Failed to create temp file: {}", e)),
                    duration_ms: start.elapsed().as_millis() as u64,
                    scanner_score: None,
                    scanner_grade: None,
                };
            }
        };

        let report_path = report_file.path().to_path_buf();

        let output = std::process::Command::new("gitleaks")
            .arg("detect")
            .arg("--source")
            .arg(path)
            .arg("--no-git")
            .arg("--report-format")
            .arg("json")
            .arg("--report-path")
            .arg(&report_path)
            .output();

        let output = match output {
            Ok(o) => o,
            Err(e) => {
                return ScanResult {
                    scanner_name: self.name().to_string(),
                    findings: vec![],
                    files_scanned: 0,
                    skipped: false,
                    skip_reason: None,
                    error: Some(format!("Failed to run gitleaks: {}", e)),
                    duration_ms: start.elapsed().as_millis() as u64,
                    scanner_score: None,
                    scanner_grade: None,
                };
            }
        };

        // gitleaks exits 1 when leaks are found, 0 when clean.
        // Exit code 126/127 indicates it couldn't run.
        if let Some(code) = output.status.code() {
            if code > 1 {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return ScanResult {
                    scanner_name: self.name().to_string(),
                    findings: vec![],
                    files_scanned: 0,
                    skipped: false,
                    skip_reason: None,
                    error: Some(format!("gitleaks error (exit {}): {}", code, stderr.trim())),
                    duration_ms: start.elapsed().as_millis() as u64,
                    scanner_score: None,
                    scanner_grade: None,
                };
            }
        }

        // Parse report JSON
        let content = match std::fs::read_to_string(&report_path) {
            Ok(c) => c,
            Err(e) => {
                return ScanResult {
                    scanner_name: self.name().to_string(),
                    findings: vec![],
                    files_scanned: 0,
                    skipped: false,
                    skip_reason: None,
                    error: Some(format!("Failed to read gitleaks report: {e}")),
                    duration_ms: start.elapsed().as_millis() as u64,
                    scanner_score: None,
                    scanner_grade: None,
                };
            }
        };

        let items: Vec<serde_json::Value> = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                return ScanResult {
                    scanner_name: self.name().to_string(),
                    findings: vec![],
                    files_scanned: 1,
                    skipped: false,
                    skip_reason: None,
                    error: Some(format!("Failed to parse gitleaks report: {}", e)),
                    duration_ms: start.elapsed().as_millis() as u64,
                    scanner_score: None,
                    scanner_grade: None,
                };
            }
        };

        let mut findings = Vec::new();

        for item in &items {
            let rule = item["RuleID"]
                .as_str()
                .or_else(|| item["ruleId"].as_str())
                .unwrap_or("unknown");
            let rule_id = format!("secrets/{}", rule);

            let description = item["Description"]
                .as_str()
                .or_else(|| item["description"].as_str())
                .unwrap_or("Secret detected")
                .to_string();

            let file_path = item["File"]
                .as_str()
                .or_else(|| item["file"].as_str())
                .map(std::path::PathBuf::from);

            let line = item["StartLine"]
                .as_u64()
                .or_else(|| item["startLine"].as_u64())
                .map(|l| l as usize);

            let snippet = item["Match"]
                .as_str()
                .or_else(|| item["match"].as_str())
                .map(|s| s.to_string());

            findings.push(Finding {
                rule_id,
                message: description,
                severity: Severity::Error,
                file: file_path,
                line,
                column: None,
                scanner: self.name().to_string(),
                snippet,
                suppressed: false,
                suppression_reason: None,
                remediation: Some(
                    "Rotate the leaked secret immediately and remove it from the codebase"
                        .to_string(),
                ),
            });
        }

        // Clean up temp report file
        let _ = std::fs::remove_file(&report_path);

        // Count distinct files referenced in findings; fall back to 1 (the
        // scanned directory counts as one scan unit) when no findings exist.
        let files_scanned = {
            use std::collections::HashSet;
            let unique: HashSet<_> = findings.iter().filter_map(|f| f.file.as_ref()).collect();
            if unique.is_empty() {
                1
            } else {
                unique.len()
            }
        };

        ScanResult {
            scanner_name: self.name().to_string(),
            findings,
            files_scanned,
            skipped: false,
            skip_reason: None,
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
            scanner_score: None,
            scanner_grade: None,
        }
    }
}

/// Returns a representative [`RuleInfo`] catalogue for the secrets scanner.
///
/// Because gitleaks ships with 100+ built-in rules that are updated
/// independently of this crate, only the most common rule IDs are listed
/// here.  At runtime, findings use the actual `RuleID` from the gitleaks
/// report (e.g. `secrets/aws-access-key`).
pub fn rules() -> Vec<RuleInfo> {
    vec![
        RuleInfo {
            id: "secrets/generic-api-key",
            severity: "error",
            scanner: "secrets",
            message: "Detected a Generic API Key",
            remediation: "Rotate the leaked secret immediately and remove it from the codebase",
        },
        RuleInfo {
            id: "secrets/aws-access-key",
            severity: "error",
            scanner: "secrets",
            message: "Detected an AWS Access Key",
            remediation: "Revoke the key immediately in AWS console",
        },
        RuleInfo {
            id: "secrets/github-pat",
            severity: "error",
            scanner: "secrets",
            message: "Detected a GitHub Personal Access Token",
            remediation: "Revoke the token in GitHub settings",
        },
        RuleInfo {
            id: "secrets/private-key",
            severity: "error",
            scanner: "secrets",
            message: "Detected a Private Key (SSH, RSA, etc.)",
            remediation: "Remove the key and rotate any credentials it protected",
        },
    ]
}
