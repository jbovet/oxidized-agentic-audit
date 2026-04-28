//! Pluggable security scanners.
//!
//! Every scanner implements the [`Scanner`] trait. Scanners fall into two
//! categories:
//!
//! - **Built-in** (no external dependencies): [`prompt`], [`bash_patterns`],
//!   [`typescript`], [`package_install`], [`frontmatter`], [`agent_frontmatter`].
//! - **External** (require a tool on `PATH`): [`shellcheck`], [`secrets`]
//!   (gitleaks), [`semgrep`].
//!
//! Use [`skill_scanners`] / [`agent_scanners`] to obtain the scanner set for
//! the appropriate scan mode, and [`all_rules`] / [`all_agent_rules`] /
//! [`all_unique_rules`] to list every rule they define.

pub mod agent_frontmatter;
pub mod bash_patterns;
pub mod frontmatter;
pub mod malicious_urls;
pub mod obfuscation;
pub mod package_install;
pub mod prompt;
pub mod secrets;
pub mod semgrep;
pub mod shared;
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
/// [`scan::run_scan`](crate::scan::run_scan) executes scanners in parallel
/// via [rayon].
///
/// # Implementing a custom scanner
///
/// ```rust,ignore
/// use oxidized_agentic_audit::scanners::Scanner;
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

/// Returns scanners for a **skill** directory scan (looks for `SKILL.md`).
///
/// The returned order is the default execution order; the scan runner
/// does not depend on this ordering because scanners run in parallel.
pub fn skill_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(prompt::PromptScanner),
        Box::new(bash_patterns::BashPatternScanner),
        Box::new(typescript::TypeScriptScanner),
        Box::new(package_install::PackageInstallScanner),
        Box::new(malicious_urls::MaliciousUrlsScanner),
        Box::new(obfuscation::ObfuscationScanner),
        Box::new(frontmatter::FrontmatterScanner),
        Box::new(shellcheck::ShellCheckScanner),
        Box::new(secrets::SecretsScanner),
        Box::new(semgrep::SemgrepScanner),
    ]
}

/// Returns scanners for an **agent** directory scan (looks for `AGENT.md`).
///
/// All file-type–agnostic scanners (prompt, bash patterns, secrets, etc.)
/// are reused unchanged; only the frontmatter scanner is swapped for the
/// agent-specific [`agent_frontmatter::AgentFrontmatterScanner`].
pub fn agent_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(prompt::PromptScanner),
        Box::new(bash_patterns::BashPatternScanner),
        Box::new(typescript::TypeScriptScanner),
        Box::new(package_install::PackageInstallScanner),
        Box::new(malicious_urls::MaliciousUrlsScanner),
        Box::new(obfuscation::ObfuscationScanner),
        Box::new(agent_frontmatter::AgentFrontmatterScanner),
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
/// use oxidized_agentic_audit::scanners::collect_files;
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

/// Maximum file size (in bytes) that any built-in scanner will read into memory.
///
/// Files exceeding this limit are skipped with a descriptive `Info` finding
/// so the audit report still shows that a file was not scanned, rather than
/// silently dropping it.  10 MB is far above any realistic skill file while
/// still preventing memory exhaustion from gigabyte-scale crafted inputs.
pub const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

/// Reads a file into a `String`, refusing files larger than [`MAX_FILE_SIZE_BYTES`].
///
/// Returns `Err(String)` with a human-readable message when:
/// - The file cannot be opened.
/// - The file metadata cannot be read from the open handle.
/// - The file is not a regular file (device, FIFO, socket) — these report
///   `size == 0` via `stat(2)` but can stream infinite data (e.g. `/dev/zero`).
/// - The file size exceeds the limit (DoS guard).
/// - The file cannot be read or contains invalid UTF-8.
///
/// ## Security properties
///
/// - **Special-file rejection**: `std::fs::metadata` (stat) checks
///   `FileType::is_file()` *before* `File::open`.  This is necessary because
///   opening a FIFO or socket with `O_RDONLY` blocks until a writer appears;
///   the type check prevents that blocking.  Character/block devices,
///   FIFOs, and sockets all report `st_size == 0` but can stream infinite
///   data — they are rejected without ever calling `open(2)`.
/// - **TOCTOU-free size guard**: after opening, [`std::fs::File::metadata`]
///   calls `fstat(fd)`.  The size check operates on the exact inode that was
///   opened; a symlink swap after `open(2)` cannot redirect it to a larger
///   file.  (The pre-open type check has a narrow TOCTOU window, but a
///   regular-file → special-file swap is not a realistic threat against a
///   static skill directory.)
/// - **Hard read cap**: [`std::io::Read::take`]`(MAX_FILE_SIZE_BYTES + 1)` limits the
///   actual kernel copy independently of the `fstat` result, providing
///   defence-in-depth for files that grow between the size check and the read
///   (appended logs, `/proc` pseudo-files on Linux, etc.).
///
/// All built-in scanners use this instead of `std::fs::read_to_string` so
/// that a single malicious oversized or special file cannot cause an OOM-kill
/// of the scan runner.
pub fn read_file_limited(path: &Path) -> Result<String, String> {
    use std::io::Read;

    // ── 1. Pre-open type check via stat(path) ──────────────────────────────────
    // Opening a FIFO or socket for reading with the default O_RDONLY flag
    // blocks the calling thread until a writer appears — we must reject
    // special files *before* calling File::open.  std::fs::metadata follows
    // symlinks, so a symlink-to-FIFO is also caught here.
    //
    // TOCTOU note: this stat and the open() below are two separate syscalls.
    // The window is negligible in practice (a static skill directory cannot
    // be atomically replaced mid-scan by an unprivileged user), and the size
    // guard in step 4 uses fstat(fd) — which *is* TOCTOU-free — for the
    // security-critical limit.
    let path_meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !path_meta.file_type().is_file() {
        return Err("not a regular file — skipping to prevent stream exhaustion".to_string());
    }

    // ── 2. Open ───────────────────────────────────────────────────────────────
    // Safe to open now that we confirmed it is a regular file.
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;

    // ── 3. Size check via fstat(fd) ───────────────────────────────────────────
    // file.metadata() calls fstat(fd) — it operates on the exact inode we
    // opened and cannot be redirected by a symlink swap that happens after
    // step 2.  Any error is surfaced explicitly; no unwrap_or(0) silencing.
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat open file: {e}"))?;

    let size = meta.len();
    if size > MAX_FILE_SIZE_BYTES {
        return Err(format!(
            "file too large ({size} bytes); maximum is {MAX_FILE_SIZE_BYTES} \
             bytes — skipping to prevent memory exhaustion"
        ));
    }

    // ── 4. Capped read — defence-in-depth ─────────────────────────────────────
    // take(MAX_FILE_SIZE_BYTES + 1) caps the kernel copy independently of the
    // fstat result, covering files that grow between steps 3 and 4 (e.g.
    // append-heavy logs, /proc pseudo-files on Linux).
    // We read into Vec<u8> first so that a UTF-8 decode error produces a clear
    // Err rather than a panic.
    let mut buf = Vec::with_capacity(size as usize);
    file.take(MAX_FILE_SIZE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;

    if buf.len() as u64 > MAX_FILE_SIZE_BYTES {
        return Err(format!(
            "file exceeded {MAX_FILE_SIZE_BYTES} bytes during read — skipping"
        ));
    }

    String::from_utf8(buf).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn read_file_limited_accepts_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("skill.md");
        std::fs::write(&path, "hello world\n").unwrap();
        let result = read_file_limited(&path);
        assert_eq!(result.unwrap(), "hello world\n");
    }

    // ── Error propagation (no unwrap_or silencing) ────────────────────────────

    #[test]
    fn read_file_limited_rejects_nonexistent_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.md");
        let result = read_file_limited(&path);
        assert!(
            result.is_err(),
            "must return Err for a path that does not exist"
        );
    }

    // ── Size guard ────────────────────────────────────────────────────────────

    #[test]
    fn read_file_limited_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.md");
        // Write MAX + 1 bytes so the pre-check fires.
        let oversized = vec![b'a'; (MAX_FILE_SIZE_BYTES + 1) as usize];
        std::fs::write(&path, &oversized).unwrap();
        let result = read_file_limited(&path);
        assert!(
            result.is_err(),
            "must return Err for a file exceeding MAX_FILE_SIZE_BYTES"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("file too large") || msg.contains("exceeded"),
            "error message should mention size limit, got: {msg}"
        );
    }

    // ── UTF-8 error ───────────────────────────────────────────────────────────

    #[test]
    fn read_file_limited_utf8_error_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary.bin");
        // Write bytes that are not valid UTF-8.
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[0xFF, 0xFE, 0x00, 0x01]).unwrap();
        let result = read_file_limited(&path);
        assert!(
            result.is_err(),
            "must return Err for non-UTF-8 file content"
        );
    }

    // ── Special-file rejection (Unix only) ───────────────────────────────────

    /// Creates a named pipe (FIFO) at `path` using the `mkfifo` system call.
    /// Returns `false` when the OS does not support FIFOs (non-Unix CI).
    #[cfg(unix)]
    fn make_fifo(path: &std::path::Path) -> bool {
        std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    #[cfg(unix)]
    fn read_file_limited_rejects_fifo_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.fifo");
        if !make_fifo(&path) {
            // mkfifo unavailable in this environment — skip gracefully.
            return;
        }
        // This must return Err immediately without blocking on the pipe read.
        let result = read_file_limited(&path);
        assert!(
            result.is_err(),
            "must return Err for a FIFO — not block waiting for a writer"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("not a regular file"),
            "error message should identify the special-file rejection, got: {msg}"
        );
    }
}

/// Returns `true` if `line` ends with an inline suppression marker.
///
/// Recognized markers (case-insensitive):
/// - `# scan:ignore`
/// - `# audit:ignore`
/// - `# oxidized-agentic-audit:ignore`
///
/// The marker must appear as a trailing shell comment — it is **not**
/// recognized when embedded inside a string literal.
///
/// # Examples
///
/// ```
/// use oxidized_agentic_audit::scanners::is_suppressed_inline;
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
        regex::Regex::new(r"(?i)\s*#\s*(scan|audit|oxidized-agentic-audit):ignore\s*$").unwrap()
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

/// Aggregates [`RuleInfo`] from every **skill** scanner module.
///
/// Useful for building rule-listing and rule-explanation UIs for skill audits.
pub fn all_rules() -> Vec<RuleInfo> {
    let mut rules = Vec::new();
    rules.extend(bash_patterns::rules());
    rules.extend(typescript::rules());
    rules.extend(prompt::rules());
    rules.extend(package_install::rules());
    rules.extend(malicious_urls::rules());
    rules.extend(obfuscation::rules());
    rules.extend(frontmatter::rules());
    rules.extend(shellcheck::rules());
    rules.extend(secrets::rules());
    rules.extend(semgrep::rules());
    rules
}

/// Aggregates all rules across both **skill** and **agent** scanner sets,
/// deduplicating shared scanners so each rule appears exactly once.
///
/// Includes skill-specific [`frontmatter`] rules plus agent-specific
/// [`agent_frontmatter`] rules, along with every shared scanner's rules.
/// Useful for `list-rules --mode all` and `explain --mode all`.
pub fn all_unique_rules() -> Vec<RuleInfo> {
    // Start from the full skill rule set, then append the agent-only
    // frontmatter rules (all other scanners are identical across both modes).
    let mut rules = all_rules();
    rules.extend(agent_frontmatter::rules());
    rules
}

/// Aggregates [`RuleInfo`] from every **agent** scanner module.
///
/// Useful for building rule-listing and rule-explanation UIs for agent scans.
pub fn all_agent_rules() -> Vec<RuleInfo> {
    let mut rules = Vec::new();
    rules.extend(bash_patterns::rules());
    rules.extend(typescript::rules());
    rules.extend(prompt::rules());
    rules.extend(package_install::rules());
    rules.extend(malicious_urls::rules());
    rules.extend(obfuscation::rules());
    rules.extend(agent_frontmatter::rules());
    rules.extend(shellcheck::rules());
    rules.extend(secrets::rules());
    rules.extend(semgrep::rules());
    rules
}
