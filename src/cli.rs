//! Command-line interface definition.
//!
//! Uses [clap] derive macros to parse arguments. This module is only used by
//! the binary crate (`src/main.rs`).

use clap::{Parser, Subcommand};
use oxidized_skills::output::OutputFormat;
use std::path::PathBuf;

/// Security auditing for AI agent skills.
#[derive(Parser)]
#[command(
    name = "oxidized-skills",
    version,
    about = "Security auditing for AI agent skills"
)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands.
#[derive(Subcommand)]
pub enum Commands {
    /// Audit a single skill directory for security issues.
    Audit {
        /// Path to the skill directory (must contain a SKILL.md).
        path: PathBuf,

        /// Output format (pretty, json, or sarif).
        #[arg(long, short, default_value = "pretty", value_enum)]
        format: OutputFormat,

        /// Write output to a file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Treat warnings as errors (exit code 1 on warnings).
        #[arg(long)]
        strict: bool,

        /// Path to a custom configuration file.
        #[arg(long)]
        config: Option<PathBuf>,

        /// Fail if the security score is below this threshold (0–100).
        /// Useful as a CI gate: `--min-score 80` rejects any skill scoring below 80.
        #[arg(long, value_name = "N")]
        min_score: Option<u8>,
    },

    /// Audit every skill directory inside a collection directory.
    #[command(name = "audit-all")]
    AuditAll {
        /// Path to a directory containing multiple skill subdirectories.
        path: PathBuf,

        /// Output format (pretty, json, or sarif).
        #[arg(long, short, default_value = "pretty", value_enum)]
        format: OutputFormat,

        /// Treat warnings as errors (exit code 1 on warnings).
        #[arg(long)]
        strict: bool,

        /// Path to a custom configuration file.
        #[arg(long)]
        config: Option<PathBuf>,

        /// Fail if any skill's security score is below this threshold (0–100).
        #[arg(long, value_name = "N")]
        min_score: Option<u8>,
    },

    /// Check which external scanner tools are installed and available.
    CheckTools,

    /// List every built-in rule with its severity and description.
    ListRules,

    /// Show the full explanation and remediation for a specific rule.
    Explain {
        /// Rule ID to look up (e.g., `"bash/CAT-A1"`, `"prompt/P01"`).
        rule_id: String,
    },
}
