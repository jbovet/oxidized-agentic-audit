mod cli;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use oxidized_skills::{audit, config, finding::AuditReport, output, scanners};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Audit {
            path,
            format,
            output: output_path,
            strict,
            config: config_path,
        } => {
            if !path.exists() {
                eprintln!("Error: path does not exist: {}", path.display());
                std::process::exit(2);
            }

            // Detect collection directories early to give a helpful error rather
            // than a confusing "SKILL.md not found" failure on every scanner.
            let skill_children = find_skill_dirs(&path);
            if !path.join("SKILL.md").exists() && !skill_children.is_empty() {
                eprintln!(
                    "Error: '{}' looks like a skills collection directory, not a single skill.",
                    path.display()
                );
                eprintln!();
                eprintln!("To audit all skills at once:");
                eprintln!("  oxidized-skills audit-all {}", path.display());
                eprintln!();
                eprintln!("To audit a specific skill:");
                for child in &skill_children {
                    eprintln!("  oxidized-skills audit {}", child.display());
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

            let report = audit::run_audit(&path, &config);
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

            std::process::exit(if report.passed { 0 } else { 1 });
        }

        Commands::AuditAll {
            path,
            format,
            strict,
            config: config_path,
        } => {
            if !path.exists() {
                eprintln!("Error: path does not exist: {}", path.display());
                std::process::exit(2);
            }

            let skill_dirs = find_skill_dirs(&path);
            if skill_dirs.is_empty() {
                eprintln!(
                    "Error: no skill directories found in '{}' (no subdirectory contains a SKILL.md)",
                    path.display()
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
            for skill_dir in &skill_dirs {
                let report = audit::run_audit(skill_dir, &config);
                let formatted = output::format_report(&report, &format);
                print!("{formatted}");
                reports.push(report);
            }

            // Print collection summary for pretty format
            if matches!(format, output::OutputFormat::Pretty) {
                print!("{}", format_collection_summary(&path, &reports));
            }

            let all_passed = reports.iter().all(|r| r.passed);
            std::process::exit(if all_passed { 0 } else { 1 });
        }

        Commands::CheckTools => {
            println!("{}", "Scanner Availability".bold().underline());
            println!();

            let all = scanners::all_scanners();
            for scanner in &all {
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

        Commands::ListRules => {
            let rules = scanners::all_rules();
            println!("{}", "Built-in Rules".bold().underline());
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
                    "    [{severity}] {id:<30} {message}",
                    id = rule.id,
                    message = rule.message,
                );
            }

            println!();
            println!("  Total: {} rules", rules.len());
        }

        Commands::Explain { rule_id } => {
            let rules = scanners::all_rules();
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
                    eprintln!("Use 'oxidized-skills list-rules' to see all available rules.");
                    std::process::exit(2);
                }
            }
        }
    }
}

/// Returns immediate child directories of `path` that contain a `SKILL.md` file,
/// sorted alphabetically by directory name.
fn find_skill_dirs(path: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(path) else {
        return vec![];
    };

    let mut dirs: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| p.join("SKILL.md").exists())
        .collect();

    dirs.sort();
    dirs
}

/// Renders a compact summary table after all individual skill reports have been printed.
fn format_collection_summary(collection_path: &std::path::Path, reports: &[AuditReport]) -> String {
    use oxidized_skills::finding::AuditStatus;

    let mut out = String::new();
    let separator = "─".repeat(66);

    out.push('\n');
    out.push_str(&format!(
        "{}\n",
        format!(
            "  Collection Summary: {}  ({} skills)",
            collection_path.display(),
            reports.len()
        )
        .bold()
        .underline()
    ));
    out.push_str(&format!("{}\n", separator.dimmed()));

    let mut n_failed = 0usize;
    let mut n_warned = 0usize;
    let mut n_passed = 0usize;

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
            let s = format!("{:>3}/100 ({})", report.security_score, report.security_grade);
            match report.security_score {
                90..=100 => s.green().bold().to_string(),
                60..=89 => s.yellow().bold().to_string(),
                _ => s.red().bold().to_string(),
            }
        };

        let (errors, warnings, info) = report.count_by_severity();
        out.push_str(&format!(
            "  {icon}  {name:<22} {status}  {score}  {e}e {w}w {i}i\n",
            name = report.skill,
            status = status_str,
            score = score_col,
            e = errors,
            w = warnings,
            i = info,
        ));
    }

    out.push_str(&format!("{}\n", separator.dimmed()));
    out.push_str(&format!(
        "  Total: {}  {}  {}\n",
        format!("{} failed", n_failed).red().bold(),
        format!("{} warnings", n_warned).yellow().bold(),
        format!("{} passed", n_passed).green().bold(),
    ));

    out
}
