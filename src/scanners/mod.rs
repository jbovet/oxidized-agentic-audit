//! Pluggable security scanners.
//!
//! Every scanner implements the [`Scanner`] trait. Scanners fall into two
//! categories:
//!
//! - **Built-in** (no external dependencies): [`prompt`], [`bash_patterns`],
//!   [`typescript`], [`package_install`], [`frontmatter`].
//! - **External** (require a tool on `PATH`): [`shellcheck`], [`secrets`]
//!   (gitleaks), [`semgrep`].
//!
//! Use [`all_scanners`] to obtain all registered scanners and [`all_rules`]
//! to list every rule they define.

pub mod bash_patterns;
pub mod frontmatter;
pub mod package_install;
pub mod prompt;
pub mod secrets;
pub mod semgrep;
pub mod shellcheck;
pub mod typescript;

use crate::config::Config;
use crate::finding::ScanResult;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// Default timeout for external tool invocations (60 seconds).
pub const EXTERNAL_TOOL_TIMEOUT: Duration = Duration::from_secs(60);

/// A pluggable security scanner.
///
/// Implementers **must** be [`Send`] + [`Sync`] because
/// [`audit::run_audit`](crate::audit::run_audit) executes scanners in parallel
/// via [rayon].
///
/// # Implementing a custom scanner
///
/// ```rust,ignore
/// use oxidized_skills::scanners::Scanner;
///
/// pub struct MyScanner;
///
/// impl Scanner for MyScanner {
///     fn name(&self) -> &'static str { "my_scanner" }
///     fn description(&self) -> &'static str { "My custom scanner" }
///     fn is_available(&self) -> bool { true }
///     fn scan(&self, path: &Path, config: &Config) -> ScanResult {
///         // ... scanning logic ...
///         # todo!()
///     }
/// }
/// ```
pub trait Scanner: Send + Sync {
    /// Returns the scanner's unique identifier (e.g., `"prompt"`, `"shellcheck"`).
    fn name(&self) -> &'static str;

    /// Returns a short, human-readable description of the scanner.
    fn description(&self) -> &'static str;

    /// Returns `true` if the scanner's external dependencies are installed.
    ///
    /// Built-in scanners always return `true`. External scanners check
    /// whether their tool binary exists on `PATH` via [`which_exists`].
    fn is_available(&self) -> bool;

    /// Executes the scanner against the given skill directory.
    ///
    /// Returns a [`ScanResult`] containing any findings and scan metadata.
    fn scan(&self, path: &Path, config: &Config) -> ScanResult;
}

/// Returns every registered [`Scanner`] implementation.
///
/// The returned order is the default execution order; the audit runner
/// does not depend on this ordering because scanners run in parallel.
pub fn all_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(prompt::PromptScanner),
        Box::new(bash_patterns::BashPatternScanner),
        Box::new(typescript::TypeScriptScanner),
        Box::new(package_install::PackageInstallScanner),
        Box::new(frontmatter::FrontmatterScanner),
        Box::new(shellcheck::ShellCheckScanner),
        Box::new(secrets::SecretsScanner),
        Box::new(semgrep::SemgrepScanner),
    ]
}

/// Recursively collects files matching the given extensions.
///
/// Walks the directory tree under `path` and returns every regular file whose
/// extension (case-insensitive) appears in `extensions`.
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::Path;
/// use oxidized_skills::scanners::collect_files;
///
/// let shell_files = collect_files(Path::new("./my-skill"), &["sh", "bash"]);
/// ```
pub fn collect_files(path: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in WalkDir::new(path)
        // Explicitly disable symlink following to prevent directory-escape attacks
        // via symlinks that point outside the skill root.  With follow_links(false),
        // DirEntry::file_type().is_file() returns false for symlinks, so the filter
        // below naturally excludes them.
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let entry_path = entry.path();
        // Containment check: defence-in-depth to ensure every collected path
        // remains inside the scan root even if WalkDir behaviour changes.
        if !entry_path.starts_with(path) {
            continue;
        }
        if let Some(ext) = entry_path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if extensions.contains(&ext_str.as_str()) {
                files.push(entry_path.to_path_buf());
            }
        }
    }
    // Sort for deterministic finding order across runs and platforms.
    files.sort();
    files
}

/// Returns `true` if an executable named `cmd` exists on `PATH`.
///
/// On Unix the file must also have an executable permission bit set.
/// Used by external scanners to implement [`Scanner::is_available`].
pub fn which_exists(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path).any(|dir| {
                let candidate = dir.join(cmd);
                if !candidate.is_file() {
                    return false;
                }
                // Also verify the file is executable; a non-executable binary on
                // PATH would appear available but fail at runtime.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::metadata(&candidate)
                        .map(|m| m.permissions().mode() & 0o111 != 0)
                        .unwrap_or(false)
                }
                #[cfg(not(unix))]
                {
                    true
                }
            })
        })
        .unwrap_or(false)
}

/// Runs an external tool with a timeout, killing the process if it exceeds the limit.
///
/// Returns `Ok(Output)` on success, or `Err(ScanResult)` if the tool timed out,
/// failed to spawn, or encountered an I/O error. The error variant contains a
/// pre-built [`ScanResult`] with appropriate `skipped` or `error` fields set.
///
/// Used by the external scanners ([`shellcheck`], [`secrets`], [`semgrep`]) to
/// prevent indefinite hangs when a tool stalls.
pub fn run_with_timeout(
    mut cmd: Command,
    timeout: Duration,
    scanner_name: &str,
    start: Instant,
) -> Result<Output, ScanResult> {
    let mut child = match cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return Err(ScanResult::error(
                scanner_name,
                format!("Failed to run {}: {}", scanner_name, e),
                start.elapsed().as_millis() as u64,
            ));
        }
    };

    let poll_interval = Duration::from_millis(100);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ScanResult {
                        scanner_name: scanner_name.to_string(),
                        findings: vec![],
                        files_scanned: 0,
                        skipped: true,
                        skip_reason: Some(format!(
                            "{} timed out after {}s",
                            scanner_name,
                            timeout.as_secs()
                        )),
                        error: None,
                        duration_ms: start.elapsed().as_millis() as u64,
                        scanner_score: None,
                        scanner_grade: None,
                    });
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(ScanResult::error(
                    scanner_name,
                    format!("Failed to wait for {}: {}", scanner_name, e),
                    start.elapsed().as_millis() as u64,
                ));
            }
        }
    }

    child.wait_with_output().map_err(|e| {
        ScanResult::error(
            scanner_name,
            format!("Failed to read {} output: {}", scanner_name, e),
            start.elapsed().as_millis() as u64,
        )
    })
}

/// Returns `true` if `line` ends with an inline suppression marker.
///
/// Recognized markers (case-insensitive):
/// - `# audit:ignore`
/// - `# oxidized-skills:ignore`
///
/// The marker must appear as a trailing shell comment — it is **not**
/// recognized when embedded inside a string literal.
///
/// # Examples
///
/// ```
/// use oxidized_skills::scanners::is_suppressed_inline;
///
/// assert!(is_suppressed_inline("curl http://example.com # audit:ignore"));
/// assert!(!is_suppressed_inline("echo '# audit:ignore' | bash"));
/// ```
pub fn is_suppressed_inline(line: &str) -> bool {
    // Only treat a suppression marker as valid when it appears as a trailing
    // shell comment (at or near end-of-line), not when it is embedded inside a
    // string literal such as: echo "# audit:ignore" | bash
    // The regex requires the marker to be preceded by optional whitespace and
    // to end at the line boundary (after optional trailing whitespace).
    static RE_INLINE_SUPPRESS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)\s*#\s*(audit|oxidized-skills):ignore\s*$").unwrap()
    });
    RE_INLINE_SUPPRESS.is_match(line)
}

/// Metadata for a single audit rule.
///
/// Returned by [`all_rules`] and used by the `list-rules` and `explain`
/// CLI commands. Each scanner module exposes a `rules()` function that
/// returns a `Vec<RuleInfo>`.
pub struct RuleInfo {
    /// Unique rule identifier (e.g., `"bash/CAT-A-001"`).
    pub id: &'static str,
    /// Severity as a string (`"error"`, `"warning"`, `"info"`).
    pub severity: &'static str,
    /// Scanner that detects this rule.
    pub scanner: &'static str,
    /// Short description of what the rule checks.
    pub message: &'static str,
    /// Guidance on how to fix a violation.
    pub remediation: &'static str,
}

/// Aggregates [`RuleInfo`] from every scanner module.
///
/// Useful for building rule-listing and rule-explanation UIs.
pub fn all_rules() -> Vec<RuleInfo> {
    let mut rules = Vec::new();
    rules.extend(bash_patterns::rules());
    rules.extend(typescript::rules());
    rules.extend(prompt::rules());
    rules.extend(package_install::rules());
    rules.extend(frontmatter::rules());
    rules.extend(shellcheck::rules());
    rules.extend(secrets::rules());
    rules.extend(semgrep::rules());
    rules
}
