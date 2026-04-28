use std::path::Path;

use oxidized_agentic_audit::config::Config;
use oxidized_agentic_audit::finding::ScanResult;
use oxidized_agentic_audit::scanners::obfuscation::ObfuscationScanner;
use oxidized_agentic_audit::scanners::Scanner;

fn scan_fixture(fixture: &str) -> ScanResult {
    let config = Config::default();
    let path = Path::new("tests/fixtures").join(fixture);
    ObfuscationScanner.scan(&path, &config)
}

fn write_skill(name: &str, body: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(name), body).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// Fixture: tests/fixtures/obfuscation-skill
// ---------------------------------------------------------------------------

#[test]
fn obfuscation_fixture_runs_without_skip_or_error() {
    let result = scan_fixture("obfuscation-skill");
    assert!(!result.skipped, "scanner must not skip");
    assert!(result.error.is_none(), "scanner must not error");
    assert!(result.files_scanned >= 1);
}

#[test]
fn fixture_flags_base64() {
    let result = scan_fixture("obfuscation-skill");
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "obfusc/O1-base64"),
        "expected obfusc/O1-base64 for the prose-embedded base64 line"
    );
}

#[test]
fn fixture_flags_hex_blob() {
    let result = scan_fixture("obfuscation-skill");
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "obfusc/O2-hex-blob"),
        "expected obfusc/O2-hex-blob for the prose-embedded hex line"
    );
}

#[test]
fn fixture_flags_high_entropy_non_base64() {
    let result = scan_fixture("obfuscation-skill");
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "obfusc/O3-high-entropy"),
        "expected obfusc/O3-high-entropy for the symbol-rich token"
    );
}

#[test]
fn fixture_skips_fenced_code_block() {
    let result = scan_fixture("obfuscation-skill");
    // The SAME base64 payload appears in prose and inside a fenced block.
    // We expect exactly ONE base64 finding (from the prose line); the fenced
    // copy must be ignored.
    let count = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "obfusc/O1-base64")
        .count();
    assert_eq!(
        count, 1,
        "fenced base64 copy must be ignored; got {count} O1 findings"
    );
}

#[test]
fn fixture_skips_inline_code() {
    let result = scan_fixture("obfuscation-skill");
    // Inline-code-wrapped base64 should not contribute another finding.
    // Combined with the fenced check, count must remain 1.
    let count = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "obfusc/O1-base64")
        .count();
    assert_eq!(count, 1, "inline-code base64 must be ignored");
}

#[test]
fn fixture_skips_urls() {
    let result = scan_fixture("obfuscation-skill");
    // The URL contains a high-entropy path segment; if URL-stripping works,
    // no finding's snippet should include "example.com".
    let url_hits: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.snippet
                .as_deref()
                .is_some_and(|s| s.contains("example.com"))
        })
        .collect();
    assert!(
        url_hits.is_empty(),
        "URL paths must be excluded; got: {url_hits:?}"
    );
}

#[test]
fn fixture_inline_suppression_silences_finding() {
    let result = scan_fixture("obfuscation-skill");
    // The suppressed line carries `# scan:ignore`; no finding may reference it.
    let suppressed_hits: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.snippet
                .as_deref()
                .is_some_and(|s| s.contains("Suppressed payload"))
        })
        .collect();
    assert!(
        suppressed_hits.is_empty(),
        "trailing # scan:ignore must silence the finding; got: {suppressed_hits:?}"
    );
}

// ---------------------------------------------------------------------------
// Inline / synthetic cases
// ---------------------------------------------------------------------------

#[test]
fn plain_prose_produces_no_findings() {
    let body = "# Title\n\nThe quick brown fox jumps over the lazy dog. \
                Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod \
                tempor incididunt ut labore et dolore magna aliqua.\n";
    let dir = write_skill("SKILL.md", body);
    let result = ObfuscationScanner.scan(dir.path(), &Config::default());
    assert!(
        result.findings.is_empty(),
        "natural English prose must produce no findings, got: {:?}",
        result.findings
    );
}

#[test]
fn short_hex_does_not_fire() {
    // Git short hash (7 chars) and a SHA-1 truncation (< 40 chars) — must not fire.
    let dir = write_skill(
        "SKILL.md",
        "see commit abc1234 or even abc1234567890abc1234\n",
    );
    let result = ObfuscationScanner.scan(dir.path(), &Config::default());
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.rule_id != "obfusc/O2-hex-blob"),
        "short hex below 40 chars must not fire O2; got: {:?}",
        result.findings
    );
}

#[test]
fn all_uppercase_token_does_not_fire_base64() {
    // 60 uppercase-only chars match the base64 charset but lack diversity.
    // O1 must not fire; entropy of all-uppercase is also too low for O3.
    let body = "Acronym: ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCD\n";
    let dir = write_skill("SKILL.md", body);
    let result = ObfuscationScanner.scan(dir.path(), &Config::default());
    let o1: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "obfusc/O1-base64")
        .collect();
    assert!(
        o1.is_empty(),
        "all-uppercase token must not fire O1 (no charset diversity); got: {o1:?}"
    );
}

#[test]
fn fence_state_persists_across_lines() {
    // Two lines of base64 inside a fenced block must both be ignored.
    let body = "intro\n\n```\nVGhpc0lzU29tZUJhc2U2NEVuY29kZWREYXRhMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE0=\nVGhpc0lzU29tZUJhc2U2NEVuY29kZWREYXRhMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE0=\n```\noutro\n";
    let dir = write_skill("SKILL.md", body);
    let result = ObfuscationScanner.scan(dir.path(), &Config::default());
    assert!(
        result.findings.is_empty(),
        "all base64 inside the fenced block must be ignored, got: {:?}",
        result.findings
    );
}

#[test]
fn hex_outside_fence_fires_after_fenced_hex() {
    // Closing fence must un-set in_fence so subsequent prose hex DOES fire.
    let body = "```\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n```\nblob: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    let dir = write_skill("SKILL.md", body);
    let result = ObfuscationScanner.scan(dir.path(), &Config::default());
    let o2: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "obfusc/O2-hex-blob")
        .collect();
    assert_eq!(
        o2.len(),
        1,
        "exactly one O2 expected — the post-fence prose hex"
    );
}

#[test]
fn multibyte_punctuation_does_not_panic() {
    // A token that ends in a non-ASCII char tests trim_matches + slicing.
    let body = "weird «VGhpc0lzU29tZUJhc2U2NEVuY29kZWREYXRhMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE0=»\n";
    let dir = write_skill("SKILL.md", body);
    // Must not panic regardless of whether the finding fires.
    let _ = ObfuscationScanner.scan(dir.path(), &Config::default());
}

#[test]
fn non_markdown_file_is_not_scanned() {
    // .sh files must not be scanned by this scanner — base64 in scripts is
    // routine and would produce noise.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("setup.sh"),
        "echo VGhpc0lzU29tZUJhc2U2NEVuY29kZWREYXRhMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE0=\n",
    )
    .unwrap();
    let result = ObfuscationScanner.scan(dir.path(), &Config::default());
    assert_eq!(result.files_scanned, 0, "shell files must be excluded");
    assert!(result.findings.is_empty());
}

#[test]
fn every_emitted_rule_is_registered() {
    use oxidized_agentic_audit::scanners::obfuscation::rules;
    let registered: std::collections::HashSet<&str> = rules().iter().map(|r| r.id).collect();
    let result = scan_fixture("obfuscation-skill");
    for f in &result.findings {
        assert!(
            registered.contains(f.rule_id.as_str()),
            "scanner emitted unregistered rule_id {:?}",
            f.rule_id
        );
    }
}
