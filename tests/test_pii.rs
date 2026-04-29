use std::path::Path;

use oxidized_agentic_audit::config::Config;
use oxidized_agentic_audit::finding::{ScanResult, Severity};
use oxidized_agentic_audit::scanners::pii::PiiScanner;
use oxidized_agentic_audit::scanners::Scanner;

fn scan_fixture(fixture: &str) -> ScanResult {
    let config = Config::default();
    let path = Path::new("tests/fixtures").join(fixture);
    PiiScanner.scan(&path, &config)
}

fn write_skill(name: &str, body: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(name), body).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// Fixture: tests/fixtures/pii-skill (SKILL.md + scripts/setup.sh)
// ---------------------------------------------------------------------------

#[test]
fn pii_fixture_runs_without_skip_or_error() {
    let result = scan_fixture("pii-skill");
    assert!(!result.skipped, "scanner must not skip");
    assert!(result.error.is_none(), "scanner must not error");
    assert!(
        result.files_scanned >= 2,
        "fixture has SKILL.md and scripts/setup.sh, got {}",
        result.files_scanned
    );
}

#[test]
fn fixture_flags_real_email_only() {
    let result = scan_fixture("pii-skill");
    let emails: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pii/P1-email")
        .collect();
    // Real emails: alice.smith@acme-industries.com (SKILL.md) and
    // charlie@acme-industries.com (setup.sh).
    // Placeholder emails (user@example.com, noreply@anthropic.com) and the
    // suppressed bob@realcompany.com must NOT appear.
    assert_eq!(
        emails.len(),
        2,
        "expected exactly 2 P1-email findings (alice + charlie), got: {emails:?}"
    );
    for f in &emails {
        let snip = f.snippet.as_deref().unwrap_or("");
        assert!(
            !snip.contains("user@example.com"),
            "test domain must not fire P1"
        );
        assert!(
            !snip.contains("noreply@anthropic.com"),
            "noreply mailbox must not fire P1"
        );
        assert!(
            !snip.contains("bob@realcompany.com"),
            "suppressed line must not fire P1"
        );
    }
}

#[test]
fn pii_findings_do_not_expose_raw_values() {
    let result = scan_fixture("pii-skill");
    let raw_values = [
        "alice.smith@acme-industries.com",
        "charlie@acme-industries.com",
        "456-78-9012",
        "4242 4242 4242 4242",
        "10.0.0.5",
        "192.168.50.7",
        "api.prod.corp",
        "db-primary.intranet",
    ];

    for finding in &result.findings {
        for raw in raw_values {
            assert!(
                !finding.message.contains(raw),
                "PII finding message leaked raw sensitive value: {raw}"
            );
            if let Some(snippet) = &finding.snippet {
                assert!(
                    !snippet.contains(raw),
                    "PII finding snippet leaked raw sensitive value: {raw}"
                );
            }
        }
    }
}

#[test]
fn fixture_flags_real_ssn_as_error() {
    let result = scan_fixture("pii-skill");
    let ssn_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pii/P2-ssn")
        .collect();
    assert_eq!(
        ssn_findings.len(),
        1,
        "expected exactly 1 P2-ssn finding; got: {} findings",
        ssn_findings.len()
    );
    assert_eq!(ssn_findings[0].severity, Severity::Error);
}

#[test]
fn fixture_flags_luhn_valid_card_only() {
    let result = scan_fixture("pii-skill");
    let cc: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pii/P3-credit-card")
        .collect();
    assert_eq!(
        cc.len(),
        1,
        "expected exactly 1 P3-credit-card finding (Visa test card); got: {cc:?}"
    );
    assert_eq!(cc[0].severity, Severity::Error);
}

#[test]
fn fixture_flags_private_ipv4() {
    let result = scan_fixture("pii-skill");
    let ips: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pii/P4-private-ipv4")
        .collect();
    // 10.0.0.5 (SKILL.md) + 192.168.50.7 (setup.sh).  8.8.8.8 (public) and
    // 1.1.1.1 (public) must not appear.
    assert_eq!(
        ips.len(),
        2,
        "expected 2 private-IPv4 findings; got: {ips:?}"
    );
    for f in &ips {
        assert_eq!(f.severity, Severity::Info);
    }
}

#[test]
fn fixture_flags_internal_hostname() {
    let result = scan_fixture("pii-skill");
    let hosts: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pii/P5-internal-host")
        .collect();
    // api.prod.corp + db-primary.intranet
    assert_eq!(
        hosts.len(),
        2,
        "expected 2 internal-hostname findings; got: {hosts:?}"
    );
}

#[test]
fn fixture_inline_suppression_silences_email() {
    let result = scan_fixture("pii-skill");
    let suppressed: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.snippet
                .as_deref()
                .is_some_and(|s| s.contains("realcompany.com"))
        })
        .collect();
    assert!(
        suppressed.is_empty(),
        "trailing # scan:ignore must silence the line; got: {suppressed:?}"
    );
}

// ---------------------------------------------------------------------------
// Synthetic / inline cases
// ---------------------------------------------------------------------------

#[test]
fn placeholder_email_does_not_fire() {
    let dir = write_skill(
        "SKILL.md",
        "support: user@example.com or no-reply@anywhere.io\n",
    );
    let result = PiiScanner.scan(dir.path(), &Config::default());
    assert!(
        result.findings.iter().all(|f| f.rule_id != "pii/P1-email"),
        "test/example/no-reply addresses must not fire P1; got: {:?}",
        result.findings
    );
}

#[test]
fn placeholder_ssn_does_not_fire() {
    let dir = write_skill("SKILL.md", "documentation example: 123-45-6789\n");
    let result = PiiScanner.scan(dir.path(), &Config::default());
    assert!(
        result.findings.iter().all(|f| f.rule_id != "pii/P2-ssn"),
        "famous placeholder SSN must not fire; got: {:?}",
        result.findings
    );
}

#[test]
fn invalid_ssn_ranges_do_not_fire() {
    // 666 area, 900-area, and 000 area are all SSA-invalid.
    let dir = write_skill(
        "SKILL.md",
        "test 666-12-3456 and 999-12-3456 and 000-12-3456\n",
    );
    let result = PiiScanner.scan(dir.path(), &Config::default());
    assert!(
        result.findings.iter().all(|f| f.rule_id != "pii/P2-ssn"),
        "invalid SSN ranges must not fire; got: {:?}",
        result.findings
    );
}

#[test]
fn random_16_digits_do_not_fire_credit_card() {
    // 1234567890123456 is not Luhn-valid.
    let dir = write_skill("SKILL.md", "batch id 1234567890123456\n");
    let result = PiiScanner.scan(dir.path(), &Config::default());
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.rule_id != "pii/P3-credit-card"),
        "non-Luhn 16-digit run must not fire P3; got: {:?}",
        result.findings
    );
}

#[test]
fn luhn_credit_card_with_dashes_fires() {
    // Visa test card with dashes — Luhn must still validate after stripping.
    let dir = write_skill("SKILL.md", "card: 4242-4242-4242-4242\n");
    let result = PiiScanner.scan(dir.path(), &Config::default());
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "pii/P3-credit-card"),
        "Luhn-valid card with dash separators must fire P3"
    );
}

#[test]
fn public_ipv4_does_not_fire() {
    let dir = write_skill("SKILL.md", "use 8.8.8.8 or 1.1.1.1 for DNS\n");
    let result = PiiScanner.scan(dir.path(), &Config::default());
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.rule_id != "pii/P4-private-ipv4"),
        "public DNS addresses must not fire P4; got: {:?}",
        result.findings
    );
}

#[test]
fn loopback_and_link_local_fire() {
    let dir = write_skill(
        "SKILL.md",
        "localhost is 127.0.0.1; link-local 169.254.0.1\n",
    );
    let result = PiiScanner.scan(dir.path(), &Config::default());
    let hits: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pii/P4-private-ipv4")
        .collect();
    assert_eq!(
        hits.len(),
        2,
        "loopback + link-local both fire; got: {hits:?}"
    );
}

#[test]
fn version_string_does_not_fire_ipv4() {
    // 1.2.3.4 is technically a valid public IPv4 — won't fire P4 (not private).
    // 999.999.999.999 has out-of-range octets — must not fire even though it
    // matches the dotted-quad regex.
    let dir = write_skill("SKILL.md", "released 999.999.999.999\n");
    let result = PiiScanner.scan(dir.path(), &Config::default());
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.rule_id != "pii/P4-private-ipv4"),
        "out-of-range octets must not fire P4; got: {:?}",
        result.findings
    );
}

#[test]
fn multiple_internal_tlds_fire() {
    let body = "hosts: foo.internal, bar.local, baz.lan, qux.intranet, quux.corp\n";
    let dir = write_skill("SKILL.md", body);
    let result = PiiScanner.scan(dir.path(), &Config::default());
    let hosts: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "pii/P5-internal-host")
        .collect();
    assert_eq!(
        hosts.len(),
        5,
        "all five internal TLDs must fire; got: {hosts:?}"
    );
}

#[test]
fn non_scanned_extension_is_ignored() {
    // PII rules apply to *.md/.markdown/.sh/.bash/.zsh only — TS files
    // routinely contain test fixtures and should not be scanned.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("fixture.ts"),
        "const email = 'real.user@acme.com';\n",
    )
    .unwrap();
    let result = PiiScanner.scan(dir.path(), &Config::default());
    assert_eq!(result.files_scanned, 0);
    assert!(result.findings.is_empty());
}

#[test]
fn every_emitted_rule_is_registered() {
    use oxidized_agentic_audit::scanners::pii::rules;
    let registered: std::collections::HashSet<&str> = rules().iter().map(|r| r.id).collect();
    let result = scan_fixture("pii-skill");
    for f in &result.findings {
        assert!(
            registered.contains(f.rule_id.as_str()),
            "scanner emitted unregistered rule_id {:?}",
            f.rule_id
        );
    }
}
