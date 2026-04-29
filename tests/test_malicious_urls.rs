use std::path::Path;

use oxidized_agentic_audit::config::Config;
use oxidized_agentic_audit::finding::{ScanResult, Severity};
use oxidized_agentic_audit::scanners::malicious_urls::MaliciousUrlsScanner;
use oxidized_agentic_audit::scanners::Scanner;

fn scan_fixture(fixture: &str) -> ScanResult {
    let config = Config::default();
    let path = Path::new("tests/fixtures").join(fixture);
    MaliciousUrlsScanner.scan(&path, &config)
}

fn write_skill(name: &str, body: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(name), body).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// Fixture: tests/fixtures/url-skill (covers SKILL.md + scripts/install.sh)
// ---------------------------------------------------------------------------

#[test]
fn url_fixture_runs_without_skip_or_error() {
    let result = scan_fixture("url-skill");
    assert!(!result.skipped, "scanner must not skip");
    assert!(result.error.is_none(), "scanner must not error");
    assert!(
        result.files_scanned >= 2,
        "fixture has SKILL.md and scripts/install.sh, got {}",
        result.files_scanned
    );
}

#[test]
fn url_fixture_flags_shortener() {
    let result = scan_fixture("url-skill");
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "url/U1-shortener"),
        "expected url/U1-shortener for bit.ly / tinyurl.com"
    );
}

#[test]
fn url_fixture_flags_paste_site_as_error() {
    let result = scan_fixture("url-skill");
    let paste = result
        .findings
        .iter()
        .find(|f| f.rule_id == "url/U2-paste")
        .expect("expected url/U2-paste finding for pastebin.com / transfer.sh");
    assert_eq!(
        paste.severity,
        Severity::Error,
        "paste-site finding must be Error severity"
    );
}

#[test]
fn url_fixture_flags_ip_literal() {
    let result = scan_fixture("url-skill");
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "url/U3-ip-literal"),
        "expected url/U3-ip-literal for 10.0.0.5 / 192.168.1.50"
    );
}

#[test]
fn url_fixture_flags_suspicious_tld() {
    let result = scan_fixture("url-skill");
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "url/U4-suspicious-tld"),
        "expected url/U4-suspicious-tld for promo.xyz"
    );
}

#[test]
fn url_fixture_flags_non_https() {
    let result = scan_fixture("url-skill");
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "url/U5-non-https"),
        "expected url/U5-non-https for http:// URLs"
    );
}

#[test]
fn url_fixture_does_not_flag_allowlisted_github() {
    let result = scan_fixture("url-skill");
    let gh: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.snippet
                .as_deref()
                .is_some_and(|s| s.contains("github.com"))
        })
        .collect();
    assert!(
        gh.is_empty(),
        "github.com is allowlisted by default; got findings: {gh:?}"
    );
}

#[test]
fn url_fixture_inline_suppression_silences_t_co() {
    let result = scan_fixture("url-skill");
    let t_co: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.snippet.as_deref().is_some_and(|s| s.contains("t.co")))
        .collect();
    assert!(
        t_co.is_empty(),
        "trailing # scan:ignore must silence the t.co line; got: {t_co:?}"
    );
}

// ---------------------------------------------------------------------------
// Inline / synthetic cases that don't need a fixture on disk
// ---------------------------------------------------------------------------

#[test]
fn ipv6_bracketed_literal_fires_u3() {
    let dir = write_skill("SKILL.md", "fetch http://[2001:db8::1]/install.sh\n");
    let result = MaliciousUrlsScanner.scan(dir.path(), &Config::default());
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "url/U3-ip-literal"),
        "bracketed IPv6 literal must trigger U3, got: {:?}",
        result.findings
    );
}

#[test]
fn ip_literal_does_not_double_fire_u5() {
    // An IPv4 host over http:// must produce only U3, not also U5.
    let dir = write_skill("SKILL.md", "see http://10.0.0.1/x\n");
    let result = MaliciousUrlsScanner.scan(dir.path(), &Config::default());
    assert_eq!(
        result.findings.len(),
        1,
        "expected exactly one finding (U3); got: {:?}",
        result.findings
    );
    assert_eq!(result.findings[0].rule_id, "url/U3-ip-literal");
}

#[test]
fn allowlist_subdomain_match_silences_findings() {
    // `raw.githubusercontent.com` should match a `githubusercontent.com` allowlist
    // entry via subdomain (`*.<entry>`) suffix matching.
    let dir = write_skill(
        "SKILL.md",
        "see https://raw.githubusercontent.com/foo/bar/main/x\n",
    );
    let result = MaliciousUrlsScanner.scan(dir.path(), &Config::default());
    assert!(
        result.findings.is_empty(),
        "subdomain of allowlisted host must produce no findings, got: {:?}",
        result.findings
    );
}

#[test]
fn custom_allowlist_silences_finding() {
    let dir = write_skill("SKILL.md", "see https://internal.corp.example/x\n");
    let mut config = Config::default();
    config
        .allowlist
        .domains
        .push("internal.corp.example".to_string());
    config.allowlist.normalize();
    let result = MaliciousUrlsScanner.scan(dir.path(), &config);
    assert!(
        result.findings.is_empty(),
        "custom-allowlisted host must produce no findings, got: {:?}",
        result.findings
    );
}

#[test]
fn multiple_urls_on_one_line_are_each_classified() {
    let dir = write_skill(
        "SKILL.md",
        "see https://bit.ly/a and https://pastebin.com/b\n",
    );
    let result = MaliciousUrlsScanner.scan(dir.path(), &Config::default());
    let ids: std::collections::HashSet<&str> =
        result.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains("url/U1-shortener"), "expected U1 from bit.ly");
    assert!(
        ids.contains("url/U2-paste"),
        "expected U2 from pastebin.com"
    );
}

#[test]
fn no_url_no_findings() {
    let dir = write_skill("SKILL.md", "this skill has no URLs at all\n");
    let result = MaliciousUrlsScanner.scan(dir.path(), &Config::default());
    assert!(
        result.findings.is_empty(),
        "lines without URLs must not produce findings"
    );
}

#[test]
fn case_insensitive_host_matching() {
    // Host comparison must lowercase before matching against the shortener list.
    let dir = write_skill("SKILL.md", "see https://BIT.LY/abc\n");
    let result = MaliciousUrlsScanner.scan(dir.path(), &Config::default());
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "url/U1-shortener"),
        "uppercase host must still match the shortener list"
    );
}

#[test]
fn snippet_truncation_no_panic_on_multibyte_chars() {
    // Lines longer than 120 chars are truncated; cut must land on a char boundary.
    let prefix = "x".repeat(116);
    let body = format!("see https://bit.ly/abc 🔥{prefix}end\n");
    let dir = write_skill("SKILL.md", &body);
    // Must not panic.
    let _ = MaliciousUrlsScanner.scan(dir.path(), &Config::default());
}

// ---------------------------------------------------------------------------
// Rule registration smoke test — every emitted rule_id must be in rules()
// ---------------------------------------------------------------------------

#[test]
fn every_emitted_rule_is_registered() {
    use oxidized_agentic_audit::scanners::malicious_urls::rules;
    let registered: std::collections::HashSet<&str> = rules().iter().map(|r| r.id).collect();
    let result = scan_fixture("url-skill");
    for f in &result.findings {
        assert!(
            registered.contains(f.rule_id.as_str()),
            "scanner emitted unregistered rule_id {:?}",
            f.rule_id
        );
    }
}
