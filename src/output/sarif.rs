//! [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) output formatter.
//!
//! Produces a standards-compliant SARIF document that can be consumed by GitHub
//! Code Scanning, VS Code SARIF Viewer, and other SARIF-aware tools.

use crate::finding::{AuditReport, Finding, Severity};
use serde_sarif::sarif::{
    ArtifactLocation, Location, Message, MultiformatMessageString, PhysicalLocation, PropertyBag,
    Region, ReportingDescriptor, Result as SarifResult, ResultLevel, Run, Sarif, Tool,
    ToolComponent,
};
use std::collections::{BTreeMap, HashMap};

/// Formats an [`AuditReport`] as a [SARIF 2.1.0] JSON document.
///
/// Both active and suppressed findings are included so that downstream tools
/// can display suppression state. Rules are deduplicated and referenced by
/// index.
///
/// # Panics
///
/// Panics if the SARIF structure cannot be serialized (should not happen with
/// valid data).
///
/// [SARIF 2.1.0]: https://sarifweb.azurewebsites.net/
pub fn format(report: &AuditReport) -> String {
    let all_findings: Vec<&Finding> = report
        .findings
        .iter()
        .chain(report.suppressed.iter())
        .collect();

    // Collect unique rules
    let mut rule_map: HashMap<&str, &Finding> = HashMap::new();
    for f in &all_findings {
        rule_map.entry(f.rule_id.as_str()).or_insert(f);
    }

    let mut rule_ids: Vec<&str> = rule_map.keys().copied().collect();
    rule_ids.sort();

    let rule_index: HashMap<&str, i64> = rule_ids
        .iter()
        .enumerate()
        .map(|(i, id)| (*id, i as i64))
        .collect();

    let rules: Vec<ReportingDescriptor> = rule_ids
        .iter()
        .map(|id| {
            let f = rule_map[id];
            let mut rule = ReportingDescriptor::builder().id(id.to_string()).build();
            rule.short_description = Some(
                MultiformatMessageString::builder()
                    .text(f.message.clone())
                    .build(),
            );
            if let Some(ref rem) = f.remediation {
                rule.help = Some(
                    MultiformatMessageString::builder()
                        .text(rem.clone())
                        .build(),
                );
            }
            rule
        })
        .collect();

    let results: Vec<SarifResult> = all_findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Error => ResultLevel::Error,
                Severity::Warning => ResultLevel::Warning,
                Severity::Info => ResultLevel::Note,
            };

            let mut result = SarifResult::builder()
                .message(Message::builder().text(f.message.clone()).build())
                .build();

            result.rule_id = Some(f.rule_id.clone());
            result.level = Some(level);
            result.rule_index = rule_index.get(f.rule_id.as_str()).copied();

            if let Some(ref file) = f.file {
                let uri = file.to_string_lossy().replace('\\', "/");

                let mut location = Location::builder().build();
                let mut physical = PhysicalLocation::builder().build();

                physical.artifact_location = Some(ArtifactLocation::builder().uri(uri).build());

                if let Some(line) = f.line {
                    physical.region = Some(Region::builder().start_line(line as i64).build());
                }

                location.physical_location = Some(physical);
                result.locations = Some(vec![location]);
            }

            result
        })
        .collect();

    let driver = ToolComponent::builder()
        .name("oxidized-skills")
        .version(env!("CARGO_PKG_VERSION").to_string())
        .rules(rules)
        .build();

    let tool = Tool::builder().driver(driver).build();

    let mut run = Run::builder().tool(tool).results(results).build();

    // Embed the security score in the SARIF run.properties bag (SARIF 2.1.0 §3.19).
    // `additional_properties` is the standard extension point for custom metadata;
    // GitHub Code Scanning and VS Code SARIF Viewer pass unknown properties through
    // transparently, so this does not break any consumer.
    let mut score_props: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    score_props.insert(
        "security_score".to_string(),
        serde_json::json!(report.security_score),
    );
    score_props.insert(
        "security_grade".to_string(),
        serde_json::json!(report.security_grade.to_string()),
    );
    let mut props = PropertyBag::builder().build();
    props.additional_properties = score_props;
    run.properties = Some(props);

    let sarif = Sarif::builder().version("2.1.0").runs(vec![run]).build();

    serde_json::to_string_pretty(&sarif).expect("SARIF serialization failed")
}
