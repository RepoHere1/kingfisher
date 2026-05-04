//! Discord incoming-webhook payload (`embeds`).
//!
//! A single embed carries the summary as `fields`, the per-finding detail in
//! the embed `description`, and a footer with the Kingfisher version. The
//! sidebar is color-coded the same way the Teams card is: red on any active
//! credential, amber for unverified findings, green for a clean run.

use serde_json::{Value, json};

use crate::alerts::AlertSummary;
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 10;

// Discord embed `description` is capped at 4096 chars and each `fields[].value`
// at 1024. We keep the per-finding block well under both — the section is
// truncated to 1900 chars (leaving room for the trailing "…N more" line) so
// servers running older Discord clients render the embed without truncation.
const DESCRIPTION_SOFT_LIMIT: usize = 1900;

const COLOR_RED: u32 = 0xC0_39_2B; // active live secrets
const COLOR_AMBER: u32 = 0xF3_9C_12; // findings present, none verified active
const COLOR_GREEN: u32 = 0x27_AE_60; // clean

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    let title = if summary.total == 0 {
        "Kingfisher: scan complete — no findings".to_string()
    } else {
        format!(
            "Kingfisher: {} finding{} ({} active, {} inactive, {} unknown)",
            summary.total,
            plural(summary.total),
            summary.active,
            summary.inactive,
            summary.unknown
        )
    };

    let color = if summary.active > 0 {
        COLOR_RED
    } else if summary.total > 0 {
        COLOR_AMBER
    } else {
        COLOR_GREEN
    };

    let mut fields: Vec<Value> = vec![
        json!({ "name": "Active",   "value": summary.active.to_string(),   "inline": true }),
        json!({ "name": "Inactive", "value": summary.inactive.to_string(), "inline": true }),
        json!({ "name": "Unknown",  "value": summary.unknown.to_string(),  "inline": true }),
    ];
    if let Some(t) = &summary.target {
        fields.push(json!({
            "name": "Target",
            "value": format!("`{}`", truncate(t, 1000)),
            "inline": false,
        }));
    }
    if !summary.by_rule.is_empty() {
        let lines: Vec<String> =
            summary.by_rule.iter().map(|(rule, count)| format!("• `{rule}` — {count}")).collect();
        fields.push(json!({
            "name": "Top rules",
            "value": truncate(&lines.join("\n"), 1000),
            "inline": false,
        }));
    }

    let mut embed = json!({
        "title": title,
        "color": color,
        "fields": fields,
        "footer": { "text": format!("kingfisher v{}", summary.kingfisher_version) },
    });

    if !findings.is_empty() {
        let take = findings.len().min(PER_FINDING_LIMIT);
        let mut detail = String::new();
        for f in findings.iter().take(take) {
            let snippet = if include_secret {
                truncate(&f.finding.snippet, 32)
            } else {
                "<redacted>".to_string()
            };
            detail.push_str(&format!(
                "• `{}` at `{}:{}` — `{}` (validation: {})\n",
                f.rule.id, f.finding.path, f.finding.line, snippet, f.finding.validation.status,
            ));
        }
        if findings.len() > take {
            detail.push_str(&format!("…{} more findings omitted", findings.len() - take));
        }
        embed["description"] = Value::String(truncate(&detail, DESCRIPTION_SOFT_LIMIT));
    }

    json!({ "embeds": [embed] })
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let prefix: String = s.chars().take(n).collect();
    format!("{prefix}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(total: usize, active: usize) -> AlertSummary {
        AlertSummary {
            total,
            active,
            inactive: 0,
            unknown: 0,
            by_rule: vec![],
            kingfisher_version: "test".to_string(),
            target: None,
        }
    }

    #[test]
    fn color_red_when_active() {
        let p = build_payload(&summary(3, 1), &[], false);
        assert_eq!(p["embeds"][0]["color"], COLOR_RED);
    }

    #[test]
    fn color_amber_when_findings_no_active() {
        let p = build_payload(&summary(2, 0), &[], false);
        assert_eq!(p["embeds"][0]["color"], COLOR_AMBER);
    }

    #[test]
    fn color_green_when_empty() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["embeds"][0]["color"], COLOR_GREEN);
        assert_eq!(p["embeds"][0]["title"], "Kingfisher: scan complete — no findings");
    }

    #[test]
    fn footer_carries_version() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["embeds"][0]["footer"]["text"], "kingfisher vtest");
    }

    #[test]
    fn empty_findings_has_no_description() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert!(p["embeds"][0].get("description").is_none());
    }
}
