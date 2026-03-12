mod cli;

use clap::Parser;
use cli::{AuditType, Cli, Commands, RuleMode};
use colored::Colorize;
use oxidized_agentic_audit::{
    audit::{self, AuditMode},
    config,
    finding::AuditReport,
    output, scanners,
};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            audit_type,
            format,
            output: output_path,
            strict,
            config: config_path,
            min_score,
        } => {
            let (mode, sentinel, entity, article) = audit_type_meta(audit_type);
            if !path.exists() {
                eprintln!("Error: path does not exist: {}", path.display());
                std::process::exit(2);
            }

            // Detect collection directories early to give a helpful error rather
            // than a confusing sentinel-file-not-found failure on every scanner.
            let children = find_artifact_dirs(&path, sentinel);
            if !path.join(sentinel).exists() && !children.is_empty() {
                eprintln!(
                    "Error: '{}' looks like {} {}s collection directory, not a single {}.",
                    path.display(),
                    article,
                    entity,
                    entity
                );
                eprintln!();
                eprintln!("To scan all {}s at once:", entity);
                eprintln!(
                    "  oxidized-agentic-audit scan-all --type {} {}",
                    entity,
                    path.display()
                );
                eprintln!();
                eprintln!("To scan a specific {}:", entity);
                for child in &children {
                    eprintln!(
                        "  oxidized-agentic-audit scan --type {} {}",
                        entity,
                        child.display()
                    );
                }
                std::process::exit(2);
            }

            let mut config = config::Config::load(config_path.as_deref()).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                std::process::exit(2);
            });

            if strict {
                config.strict.enabled = true;
            }

            let report = audit::run_audit(&path, &config, mode);
            let formatted = output::format_report(&report, &format);

            if let Some(out_path) = output_path {
                std::fs::write(&out_path, &formatted).unwrap_or_else(|e| {
                    eprintln!("Error writing output: {e}");
                    std::process::exit(2);
                });
                eprintln!("Output written to {}", out_path.display());
            } else {
                print!("{formatted}");
            }

            if let Some(min) = min_score {
                if report.security_score < min {
                    eprintln!(
                        "Error: security score {}/100 is below the required minimum of {}",
                        report.security_score, min
                    );
                    std::process::exit(1);
                }
            }

            std::process::exit(if report.passed { 0 } else { 1 });
        }

        Commands::ScanAll {
            path,
            audit_type,
            format,
            strict,
            config: config_path,
            min_score,
        } => {
            if !path.exists() {
                eprintln!("Error: path does not exist: {}", path.display());
                std::process::exit(2);
            }

            let (mode, sentinel, entity, _article) = audit_type_meta(audit_type);

            let dirs = find_artifact_dirs(&path, sentinel);
            if dirs.is_empty() {
                eprintln!(
                    "Error: no {} directories found in '{}' (no subdirectory contains a {})",
                    entity,
                    path.display(),
                    sentinel,
                );
                std::process::exit(2);
            }

            let mut config = config::Config::load(config_path.as_deref()).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                std::process::exit(2);
            });

            if strict {
                config.strict.enabled = true;
            }

            let mut reports: Vec<AuditReport> = Vec::new();
            for dir in &dirs {
                let report = audit::run_audit(dir, &config, mode);
                let formatted = output::format_report(&report, &format);
                print!("{formatted}");
                reports.push(report);
            }

            if matches!(format, output::OutputFormat::Pretty) {
                print!(
                    "{}",
                    format_collection_summary(&path, &reports, min_score, entity)
                );
            }

            let all_passed = reports.iter().all(|r| r.passed);
            let all_above_min = min_score
                .map(|min| reports.iter().all(|r| r.security_score >= min))
                .unwrap_or(true);
            std::process::exit(if all_passed && all_above_min { 0 } else { 1 });
        }

        Commands::CheckTools => {
            println!("{}", "Scanner Availability".bold().underline());
            println!();

            // Deduplicate across skill and agent scanner sets so shared scanners
            // appear once and both frontmatter variants are shown.
            let mut seen = std::collections::HashSet::new();
            let combined: Vec<Box<dyn scanners::Scanner>> = scanners::skill_scanners()
                .into_iter()
                .chain(scanners::agent_scanners())
                .filter(|s| seen.insert(s.name().to_string()))
                .collect();

            for scanner in &combined {
                let status = if scanner.is_available() {
                    "READY".green().bold().to_string()
                } else {
                    "NOT AVAILABLE".red().to_string()
                };

                println!(
                    "  [{status}] {name:<20} {desc}",
                    name = scanner.name(),
                    desc = scanner.description(),
                );
            }

            println!();
            println!(
                "Note: Core scanners (bash_patterns, prompt, package_install) require no external tools."
            );
        }

        Commands::ListRules { mode } => {
            let rules = match mode {
                RuleMode::Skill => scanners::all_rules(),
                RuleMode::Agent => scanners::all_agent_rules(),
                RuleMode::All => scanners::all_unique_rules(),
            };

            let mode_label = match mode {
                RuleMode::Skill => "Skill",
                RuleMode::Agent => "Agent",
                RuleMode::All => "All",
            };

            println!(
                "{}",
                format!("Built-in Rules ({mode_label})").bold().underline()
            );
            println!();

            let mut current_scanner = "";
            for rule in &rules {
                if rule.scanner != current_scanner {
                    if !current_scanner.is_empty() {
                        println!();
                    }
                    println!("  {}", rule.scanner.bold());
                    current_scanner = rule.scanner;
                }

                let severity = match rule.severity {
                    "error" => "ERROR".red().bold().to_string(),
                    "warning" => " WARN".yellow().bold().to_string(),
                    "info" => " INFO".blue().to_string(),
                    _ => rule.severity.to_string(),
                };

                println!(
                    "    [{severity}] {id:<40} {message}",
                    id = rule.id,
                    message = rule.message,
                );
            }

            println!();
            println!("  Total: {} rules", rules.len());
        }

        Commands::Explain { rule_id, mode } => {
            let rules = match mode {
                RuleMode::Skill => scanners::all_rules(),
                RuleMode::Agent => scanners::all_agent_rules(),
                RuleMode::All => scanners::all_unique_rules(),
            };
            match rules.iter().find(|r| r.id == rule_id) {
                Some(rule) => {
                    println!("{}", rule.id.bold());
                    println!();
                    println!("  Scanner:      {}", rule.scanner);
                    println!("  Severity:     {}", rule.severity);
                    println!("  Description:  {}", rule.message);
                    println!("  Remediation:  {}", rule.remediation);
                }
                None => {
                    eprintln!("Unknown rule: {rule_id}");
                    eprintln!(
                        "Use 'oxidized-agentic-audit list-rules --mode all' to see all available rules."
                    );
                    std::process::exit(2);
                }
            }
        }
    }
}

/// Maps an [`AuditType`] to its audit mode, sentinel filename, entity label, and article.
///
/// Returns `(AuditMode, sentinel, entity_label, article)` where `article` is
/// the grammatically correct indefinite article ("a" or "an") for the entity.
fn audit_type_meta(audit_type: AuditType) -> (AuditMode, &'static str, &'static str, &'static str) {
    match audit_type {
        AuditType::Skill => (AuditMode::Skill, "SKILL.md", "skill", "a"),
        AuditType::Agent => (AuditMode::Agent, "AGENT.md", "agent", "an"),
    }
}

/// Returns immediate child directories of `path` that contain a file named `sentinel`,
/// sorted alphabetically by directory name.
fn find_artifact_dirs(path: &std::path::Path, sentinel: &str) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(path) else {
        return vec![];
    };

    let mut dirs: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| p.join(sentinel).exists())
        .collect();

    dirs.sort();
    dirs
}

/// Renders a compact summary table after all individual reports have been printed.
///
/// `entity_label` should be `"skill"` or `"agent"` to customise the summary header.
/// When `min_score` is `Some(n)`, rows whose score is below `n` are annotated
/// with a red `[< N]` marker so failures are immediately visible.
fn format_collection_summary(
    collection_path: &std::path::Path,
    reports: &[AuditReport],
    min_score: Option<u8>,
    entity_label: &str,
) -> String {
    use oxidized_agentic_audit::finding::AuditStatus;

    let mut out = String::new();
    let separator = "─".repeat(66);

    out.push('\n');
    out.push_str(&format!(
        "{}\n",
        format!(
            "  Collection Summary: {}  ({} {}s)",
            collection_path.display(),
            reports.len(),
            entity_label,
        )
        .bold()
        .underline()
    ));
    out.push_str(&format!("{}\n", separator.dimmed()));

    let mut n_failed = 0usize;
    let mut n_warned = 0usize;
    let mut n_passed = 0usize;
    let mut n_below_min = 0usize;

    for report in reports {
        let (icon, status_str) = match report.status {
            AuditStatus::Passed => {
                n_passed += 1;
                (
                    "✓".green().to_string(),
                    "PASSED ".green().bold().to_string(),
                )
            }
            AuditStatus::Warning => {
                n_warned += 1;
                (
                    "⚠".yellow().to_string(),
                    "WARNING".yellow().bold().to_string(),
                )
            }
            AuditStatus::Failed => {
                n_failed += 1;
                ("✗".red().to_string(), "FAILED ".red().bold().to_string())
            }
        };

        let score_col = {
            let s = format!(
                "{:>3}/100 ({})",
                report.security_score, report.security_grade
            );
            match report.security_score {
                90..=100 => s.green().bold().to_string(),
                60..=89 => s.yellow().bold().to_string(),
                _ => s.red().bold().to_string(),
            }
        };

        let min_score_marker = match min_score {
            Some(min) if report.security_score < min => {
                n_below_min += 1;
                format!(" {}", format!("[< {min}]").red().bold())
            }
            _ => String::new(),
        };

        let (errors, warnings, info) = report.count_by_severity();
        out.push_str(&format!(
            "  {icon}  {name:<22} {status}  {score}  {e} err, {w} warn, {i} info{marker}\n",
            name = report.skill,
            status = status_str,
            score = score_col,
            e = errors,
            w = warnings,
            i = info,
            marker = min_score_marker,
        ));
    }

    out.push_str(&format!("{}\n", separator.dimmed()));

    let mut footer = format!(
        "  Total: {}  {}  {}",
        format!("{} failed", n_failed).red().bold(),
        format!("{} warnings", n_warned).yellow().bold(),
        format!("{} passed", n_passed).green().bold(),
    );
    if let Some(min) = min_score {
        if n_below_min > 0 {
            footer.push_str(&format!(
                "  {}",
                format!("{} below min-score ({})", n_below_min, min)
                    .red()
                    .bold()
            ));
        }
    }
    footer.push('\n');
    out.push_str(&footer);

    out
}
