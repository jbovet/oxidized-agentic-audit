//! Static analysis via [semgrep](https://semgrep.dev/).
//!
//! This is an **external** scanner — it requires the `semgrep` binary to
//! be installed on `PATH`.  When `semgrep` is not found the scanner is
//! automatically marked as *skipped* by the audit runner.
//!
//! # How it works
//!
//! 1. Spawns `semgrep scan --json --quiet <path>`.
//! 2. Polls the subprocess with a configurable timeout (default 3 s) to
//!    avoid hanging when semgrep tries to phone home on restricted networks.
//! 3. Parses the JSON `results` array into [`Finding`] structs, mapping
//!    the semgrep `severity` field to our [`Severity`] enum.
//!
//! # Timeout behaviour
//!
//! Semgrep can stall for many seconds when it tries to reach `semgrep.dev`
//! for rule updates and the network is blocked (e.g. corporate proxy).
//! The `SEMGREP_TIMEOUT` constant caps the wait at 3 seconds; if the
//! process has not exited by then it is killed and the scan is marked as
//! *skipped*.
//!
//! # Representative rules
//!
//! The [`rules`] function lists a representative subset.  At runtime,
//! findings are tagged dynamically as `semgrep/<check_id>` based on
//! whatever semgrep reports.

use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{which_exists, RuleInfo, Scanner};
use std::path::Path;
use std::time::{Duration, Instant};

/// Maximum time to wait for semgrep before giving up.
///
/// Semgrep can stall for many seconds when it tries to reach semgrep.dev for
/// rule updates and the network is blocked (e.g. corporate proxy).  A 30-second
/// ceiling keeps CI pipelines from hanging indefinitely while still allowing
/// legitimate slow runs to complete.
const SEMGREP_TIMEOUT: Duration = Duration::from_secs(30);

/// External scanner wrapper for [semgrep](https://semgrep.dev/).
///
/// Runs `semgrep scan --json --quiet <path>` and maps results to
/// [`Finding`] structs.  Severity is derived from the semgrep `severity`
/// JSON field (`ERROR` → [`Error`](Severity::Error), `WARNING` →
/// [`Warning`](Severity::Warning), anything else → [`Info`](Severity::Info)).
///
/// The subprocess is killed and the scan is marked *skipped* if it does
/// not complete within `SEMGREP_TIMEOUT` (30 seconds).
///
/// Requires `semgrep` on `PATH`; see [`is_available`](Scanner::is_available).
pub struct SemgrepScanner;

impl Scanner for SemgrepScanner {
    fn name(&self) -> &'static str {
        "semgrep"
    }

    fn description(&self) -> &'static str {
        "Static analysis via semgrep (external tool)"
    }

    fn is_available(&self) -> bool {
        which_exists("semgrep")
    }

    fn scan(&self, path: &Path, config: &Config) -> ScanResult {
        let start = Instant::now();

        let mut cmd = std::process::Command::new("semgrep");
        cmd.arg("scan").arg("--json").arg("--quiet");

        // 1. Rule configuration resolution:
        //    - Use explicit path from oxidized-skills.toml if provided.
        //    - Fall back to local semgrep.yml or .semgrep.yml if they exist.
        //    - Otherwise semgrep will use its default (usually 'auto' registry rules).
        if let Some(ref custom_config) = config.semgrep.config {
            // Validate the config value before passing to semgrep.
            // Accepted forms:
            //   - Registry shorthands:  p/<ruleset>, r/<rules>, auto
            //   - URLs:                 https://... or http://...
            //   - Local path:           must be an existing file or directory
            //
            // This prevents argument-confusion where a crafted config value like
            // "--flag" could alter semgrep's behaviour in unexpected ways.
            let is_registry = custom_config.starts_with("p/")
                || custom_config.starts_with("r/")
                || custom_config == "auto";
            let is_url = custom_config.contains("://");
            let is_local_path = Path::new(custom_config.as_str()).exists();

            if is_registry || is_url || is_local_path {
                cmd.arg("--config").arg(custom_config);
            } else {
                eprintln!(
                    "Warning: semgrep config '{}' is not a registry shorthand, URL, or existing \
                     path — skipping custom config",
                    custom_config
                );
            }
        } else if Path::new("semgrep.yml").exists() {
            cmd.arg("--config").arg("semgrep.yml");
        } else if Path::new(".semgrep.yml").exists() {
            cmd.arg("--config").arg(".semgrep.yml");
        }

        // 2. Performance optimizations:
        //    - Disable metrics unless explicitly enabled.
        //    - Disable version check unless explicitly enabled.
        if !config.semgrep.metrics {
            cmd.arg("--metrics=off");
        }

        if !config.semgrep.version_check {
            cmd.env("SEMGREP_ENABLE_VERSION_CHECK", "0");
        }

        cmd.arg(path);

        let output =
            match crate::scanners::run_with_timeout(cmd, SEMGREP_TIMEOUT, self.name(), start) {
                Ok(o) => o,
                Err(scan_result) => return scan_result,
            };

        // semgrep exits non-zero when findings are present or on error
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return ScanResult {
                scanner_name: self.name().to_string(),
                findings: vec![],
                files_scanned: 0,
                skipped: false,
                skip_reason: None,
                error: None,
                duration_ms: start.elapsed().as_millis() as u64,
                scanner_score: None,
                scanner_grade: None,
            };
        }

        let root: serde_json::Value = match serde_json::from_str(&stdout) {
            Ok(v) => v,
            Err(e) => {
                return ScanResult::error(
                    self.name(),
                    format!("Failed to parse semgrep JSON: {}", e),
                    start.elapsed().as_millis() as u64,
                );
            }
        };

        let results = match root["results"].as_array() {
            Some(r) => r,
            None => {
                return ScanResult {
                    scanner_name: self.name().to_string(),
                    findings: vec![],
                    files_scanned: 0,
                    skipped: false,
                    skip_reason: None,
                    error: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                    scanner_score: None,
                    scanner_grade: None,
                };
            }
        };

        // Prefer the authoritative total from semgrep's own stats; fall back
        // to unique file paths in findings after the loop is complete.
        let total_files_stat = root["stats"]["total_files"].as_u64().map(|n| n as usize);

        let mut findings = Vec::new();

        for item in results {
            let check_id = item["check_id"].as_str().unwrap_or("unknown").to_string();
            let rule_id = format!("semgrep/{}", check_id);

            // Use eq_ignore_ascii_case to avoid allocating an uppercase String
            // that is only used for a transient comparison.
            let sev_str = item["extra"]["severity"].as_str().unwrap_or("WARNING");
            let severity = if sev_str.eq_ignore_ascii_case("ERROR") {
                Severity::Error
            } else if sev_str.eq_ignore_ascii_case("WARNING") {
                Severity::Warning
            } else {
                Severity::Info
            };

            let message = item["extra"]["message"]
                .as_str()
                .unwrap_or("semgrep finding")
                .to_string();

            let file_path = item["path"].as_str().map(std::path::PathBuf::from);

            let line = item["start"]["line"].as_u64().map(|l| l as usize);

            let column = item["start"]["col"].as_u64().map(|c| c as usize);

            let snippet = item["extra"]["lines"]
                .as_str()
                .map(|s| s.trim().to_string());

            let remediation = item["extra"]["metadata"]["fix"]
                .as_str()
                .or_else(|| item["extra"]["fix"].as_str())
                .map(|s| s.to_string());

            findings.push(Finding {
                rule_id,
                message,
                severity,
                file: file_path,
                line,
                column,
                scanner: self.name().to_string(),
                snippet,
                suppressed: false,
                suppression_reason: None,
                remediation,
            });
        }

        let files_scanned = total_files_stat.unwrap_or_else(|| {
            // semgrep didn't report total_files; count unique paths from findings
            // so the metric is meaningful rather than always showing 0.
            use std::collections::HashSet;
            findings
                .iter()
                .filter_map(|f| f.file.as_ref())
                .collect::<HashSet<_>>()
                .len()
        });

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

/// Returns a representative [`RuleInfo`] catalogue for the semgrep scanner.
///
/// Semgrep ships thousands of community and pro rules that are updated
/// independently of this crate.  Only a few common examples are listed
/// here.  At runtime, findings use the actual `check_id` from the semgrep
/// JSON output (e.g. `semgrep/python.lang.security.audit.…`).
pub fn rules() -> Vec<RuleInfo> {
    vec![
        RuleInfo {
            id: "semgrep/javascript.express.security.audit.xss.direct-response-write.direct-response-write",
            severity: "error",
            scanner: "semgrep",
            message: "Direct response write (XSS vulnerability)",
            remediation: "Escape output or use a templating engine",
        },
        RuleInfo {
            id: "semgrep/python.lang.security.audit.dangerous-spawn-process.dangerous-spawn-process",
            severity: "error",
            scanner: "semgrep",
            message: "Dangerous process spawn (Command Injection)",
            remediation: "Use subprocess with a list of arguments instead of shell=True",
        },
        RuleInfo {
            id: "semgrep/bash.curl.security.curl-pipe-bash.curl-pipe-bash",
            severity: "error",
            scanner: "semgrep",
            message: "Curl piped to bash",
            remediation: "Download, verify, then execute",
        },
    ]
}
