//! Configuration loading and management.
//!
//! Provides types for the TOML-based configuration file and for finding-suppression
//! rules stored in `.oxidized-skills-ignore` files.
//!
//! # Configuration file
//!
//! The default configuration file is `oxidized-skills.toml` in the current
//! working directory. Use [`Config::load`] to read it:
//!
//! ```rust,no_run
//! use oxidized_skills::config::Config;
//!
//! let config = Config::load(None).expect("failed to load config");
//! assert!(config.is_scanner_enabled("prompt"));
//! ```
//!
//! # Suppression files
//!
//! Place a `.oxidized-skills-ignore` file inside a skill directory to suppress
//! specific findings. See [`Suppression`] for the format and [`load_suppressions`]
//! for loading.

use std::path::Path;

/// Main configuration for the audit system.
///
/// Loaded from a TOML file (typically `oxidized-skills.toml`). All fields
/// carry sensible defaults so the config file can be omitted entirely.
///
/// # Examples
///
/// ```rust,no_run
/// use oxidized_skills::config::Config;
///
/// // Load from the default location or fall back to built-in defaults.
/// let config = Config::load(None).unwrap();
/// ```
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct Config {
    /// Trusted registries and domains used by package-install and
    /// bash-pattern scanners.
    pub allowlist: AllowlistConfig,
    /// When strict mode is enabled, warnings are promoted to failures.
    pub strict: StrictConfig,
    /// Per-scanner on/off toggles.
    pub scanners: ScannersConfig,
    /// Configuration for the semgrep scanner.
    pub semgrep: SemgrepConfig,
}

/// Trusted package registries and domains.
///
/// Entries are automatically normalized to lowercase at load time via
/// [`AllowlistConfig::normalize`] so that scanners can perform
/// case-insensitive comparisons without per-line allocation.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct AllowlistConfig {
    /// Trusted package registries (e.g., `registry.npmjs.org`, `pypi.org`).
    pub registries: Vec<String>,
    /// Trusted domains for downloads (e.g., `github.com`).
    pub domains: Vec<String>,
}

/// Strict-mode configuration.
///
/// When [`enabled`](StrictConfig::enabled) is `true`, any finding with
/// [`Severity::Warning`](crate::finding::Severity::Warning) will cause the
/// audit to fail (status = [`AuditStatus::Failed`](crate::finding::AuditStatus::Failed)).
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct StrictConfig {
    /// Set to `true` to treat warnings as errors.
    pub enabled: bool,
}

/// Per-scanner on/off toggles.
///
/// Every scanner defaults to **enabled**. Set a field to `false` in the
/// TOML config file to skip that scanner during audits.
///
/// # Examples
///
/// ```toml
/// [scanners]
/// semgrep = false   # skip semgrep even if it is installed
/// ```
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct ScannersConfig {
    /// Shell script analysis via [shellcheck](https://www.shellcheck.net/).
    pub shellcheck: bool,
    /// Static analysis via [semgrep](https://semgrep.dev/).
    pub semgrep: bool,
    /// Secret detection via [gitleaks](https://github.com/gitleaks/gitleaks).
    pub secrets: bool,
    /// Prompt injection pattern detection (built-in, no external tool).
    pub prompt: bool,
    /// Dangerous bash anti-pattern detection (built-in).
    pub bash_patterns: bool,
    /// Dangerous TypeScript/JavaScript pattern detection (built-in).
    pub typescript_patterns: bool,
    /// Unsafe package installation detection (built-in).
    pub package_install: bool,
    /// SKILL.md frontmatter validation (built-in).
    pub frontmatter: bool,
}

/// Configuration for the [semgrep](https://semgrep.dev/) scanner.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct SemgrepConfig {
    /// Path to a local semgrep rules file (e.g., `semgrep.yml`).
    ///
    /// If specified, semgrep will be run with `--config <path>`. If not
    /// specified, the scanner looks for a `semgrep.yml` file in the project
    /// root. Using a local config file prevents semgrep from redownloading
    /// rules from the registry on every run.
    pub config: Option<String>,

    /// Whether to send anonymous performance metrics to semgrep.dev.
    ///
    /// Defaults to `false` for privacy and speed.
    pub metrics: bool,

    /// Whether to check for the latest semgrep version.
    ///
    /// Defaults to `false` for speed.
    pub version_check: bool,
}

impl AllowlistConfig {
    /// Normalizes all entries to lowercase in-place.
    ///
    /// Called once at config load time so that scanners can compare against
    /// pre-lowercased values without allocating on every line they scan.
    pub fn normalize(&mut self) {
        for s in &mut self.registries {
            *s = s.to_lowercase();
        }
        for s in &mut self.domains {
            *s = s.to_lowercase();
        }
    }
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        // Values are already lowercase; normalize() is a no-op for the default.
        AllowlistConfig {
            registries: vec![
                "registry.npmjs.org".to_string(),
                "pypi.org".to_string(),
                "files.pythonhosted.org".to_string(),
            ],
            domains: vec![
                "registry.npmjs.org".to_string(),
                "npmjs.org".to_string(),
                "github.com".to_string(),
                "githubusercontent.com".to_string(),
                "pypi.org".to_string(),
            ],
        }
    }
}

impl Default for ScannersConfig {
    fn default() -> Self {
        ScannersConfig {
            shellcheck: true,
            semgrep: true,
            secrets: true,
            prompt: true,
            bash_patterns: true,
            typescript_patterns: true,
            package_install: true,
            frontmatter: true,
        }
    }
}

impl Config {
    /// Loads configuration from a TOML file.
    ///
    /// Resolution order:
    /// 1. If `path` is `Some`, load from that file (error if missing).
    /// 2. If `path` is `None`, try `oxidized-skills.toml` in the current directory.
    /// 3. If that file does not exist either, return [`Config::default()`].
    ///
    /// The [`AllowlistConfig`] entries are normalized to lowercase after loading.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` when:
    /// - The explicit path does not exist.
    /// - The file cannot be read from disk.
    /// - The TOML content fails to parse.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::path::Path;
    /// use oxidized_skills::config::Config;
    ///
    /// // Explicit path
    /// let cfg = Config::load(Some(Path::new("my-config.toml")))?;
    ///
    /// // Auto-detect or default
    /// let cfg = Config::load(None)?;
    /// # Ok::<(), String>(())
    /// ```
    pub fn load(path: Option<&Path>) -> Result<Config, String> {
        let (config_path, is_explicit) = if let Some(p) = path {
            (p.to_path_buf(), true)
        } else {
            (Path::new("oxidized-skills.toml").to_path_buf(), false)
        };

        match std::fs::read_to_string(&config_path) {
            Ok(content) => {
                let mut config: Config = toml::from_str(&content).map_err(|e| {
                    format!("Failed to parse config {}: {}", config_path.display(), e)
                })?;
                // Normalize allowlist entries to lowercase once at load time so
                // scanners can skip per-call lowercasing in hot loops.
                config.allowlist.normalize();
                Ok(config)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !is_explicit => {
                Ok(Config::default())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(format!("Config file not found: {}", config_path.display()))
            }
            Err(e) => Err(format!(
                "Failed to read config {}: {}",
                config_path.display(),
                e
            )),
        }
    }

    /// Returns `true` if the named scanner is enabled.
    ///
    /// Unknown scanner names are considered enabled (returns `true`).
    ///
    /// # Examples
    ///
    /// ```
    /// use oxidized_skills::config::Config;
    ///
    /// let config = Config::default();
    /// assert!(config.is_scanner_enabled("prompt"));
    /// assert!(config.is_scanner_enabled("unknown_scanner"));
    /// ```
    pub fn is_scanner_enabled(&self, name: &str) -> bool {
        match name {
            "shellcheck" => self.scanners.shellcheck,
            "semgrep" => self.scanners.semgrep,
            "secrets" => self.scanners.secrets,
            "prompt" => self.scanners.prompt,
            "bash_patterns" => self.scanners.bash_patterns,
            "typescript_patterns" => self.scanners.typescript_patterns,
            "package_install" => self.scanners.package_install,
            "frontmatter" => self.scanners.frontmatter,
            _ => true,
        }
    }
}

/// Root structure of an `.oxidized-skills-ignore` TOML file.
///
/// # File format
///
/// ```toml
/// [[suppress]]
/// rule = "bash/CAT-A-001"
/// file = "setup.sh"
/// reason = "Accepted risk for bootstrapping"
/// ```
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SuppressionFile {
    /// One or more suppression entries.
    pub suppress: Vec<Suppression>,
}

/// A rule that silences a specific audit finding.
///
/// Suppressions live in `.oxidized-skills-ignore` files at the root of a skill
/// directory and are loaded by [`load_suppressions`].
///
/// # Matching
///
/// A suppression matches a [`Finding`](crate::finding::Finding) when:
/// - `rule` equals the finding's `rule_id`.
/// - `file` matches the finding's path (empty string acts as a wildcard).
/// - `lines` (if set) contains the finding's line number.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Suppression {
    /// Rule ID to suppress (e.g., `"bash/CAT-A-001"`).
    pub rule: String,
    /// Relative file path to match, or an empty string for all files.
    pub file: String,
    /// Optional line range (`"10-20"`) or single line (`"15"`).
    pub lines: Option<String>,
    /// Human-readable justification for the suppression.
    pub reason: String,
    /// Optional issue-tracker reference (e.g., `"JIRA-1234"`).
    pub ticket: Option<String>,
}

/// Loads suppression rules from a `.oxidized-skills-ignore` file.
///
/// Looks for the file in `skill_path` and parses it as TOML. Returns an empty
/// vector when the file is absent or cannot be parsed (a warning is printed to
/// stderr in the latter case).
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::Path;
/// use oxidized_skills::config::load_suppressions;
///
/// let suppressions = load_suppressions(Path::new("./my-skill"));
/// for s in &suppressions {
///     println!("suppressed: {} — {}", s.rule, s.reason);
/// }
/// ```
pub fn load_suppressions(skill_path: &Path) -> Vec<Suppression> {
    let ignore_path = skill_path.join(".oxidized-skills-ignore");
    if !ignore_path.exists() {
        return vec![];
    }

    let content = match std::fs::read_to_string(&ignore_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    match toml::from_str::<SuppressionFile>(&content) {
        Ok(file) => file
            .suppress
            .into_iter()
            .filter(|s| {
                let suppression_path = std::path::Path::new(&s.file);
                // Reject `..` components (relative traversal) AND absolute paths.
                // An absolute path like `/etc/passwd` would pass the ParentDir check
                // but references a file outside the skill directory.
                let has_parent_dir = suppression_path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir));
                let is_absolute = suppression_path.is_absolute();
                if has_parent_dir || is_absolute {
                    eprintln!(
                        "Warning: ignoring suppression with unsafe path in file field: {}",
                        s.file
                    );
                }
                !has_parent_dir && !is_absolute
            })
            .collect(),
        Err(e) => {
            eprintln!("Warning: failed to parse .oxidized-skills-ignore: {e}");
            vec![]
        }
    }
}
