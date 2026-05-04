//! Google Chat incoming-webhook payload (`cardsV2`).
//!
//! Google Chat does not expose a card-color knob in the public webhook API the
//! way Discord/Teams/Mattermost do, so severity is encoded textually in the
//! header title. The card uses two sections: a "Summary" with `decoratedText`
//! widgets for the active/inactive/unknown counts, and a "Findings" section
//! with a `textParagraph` widget. `textParagraph.text` accepts a small
//! markdown subset (`*bold*`, `_italic_`, backtick code spans).

use serde_json::{Value, json};

use crate::alerts::AlertSummary;
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 10;

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    let title = if summary.total == 0 {
        "Kingfisher: scan complete — no findings".to_string()
    } else {
        let prefix = if summary.active > 0 { "🚨 " } else { "" };
        format!(
            "{}Kingfisher: {} finding{} ({} active, {} inactive, {} unknown)",
            prefix,
            summary.total,
            plural(summary.total),
            summary.active,
            summary.inactive,
            summary.unknown
        )
    };

    let mut summary_widgets: Vec<Value> = vec![
        json!({ "decoratedText": { "topLabel": "Active",   "text": summary.active.to_string() } }),
        json!({ "decoratedText": { "topLabel": "Inactive", "text": summary.inactive.to_string() } }),
        json!({ "decoratedText": { "topLabel": "Unknown",  "text": summary.unknown.to_string() } }),
    ];
    if let Some(t) = &summary.target {
        summary_widgets.push(json!({
            "decoratedText": { "topLabel": "Target", "text": t }
        }));
    }
    if !summary.by_rule.is_empty() {
        let lines: Vec<String> = summary
            .by_rule
            .iter()
            .map(|(rule, count)| format!("• <code>{rule}</code> — {count}"))
            .collect();
        summary_widgets.push(json!({
            "textParagraph": { "text": format!("<b>Top rules</b><br>{}", lines.join("<br>")) }
        }));
    }

    let mut sections: Vec<Value> = vec![json!({
        "header": "Summary",
        "widgets": summary_widgets,
    })];

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
                "• <b>{}</b> at <code>{}:{}</code> — <code>{}</code> (validation: {})<br>",
                f.rule.id, f.finding.path, f.finding.line, snippet, f.finding.validation.status,
            ));
        }
        if findings.len() > take {
            detail.push_str(&format!("<i>…{} more findings omitted</i>", findings.len() - take));
        }
        sections.push(json!({
            "header": "Findings",
            "widgets": [{ "textParagraph": { "text": detail } }],
        }));
    }

    json!({
        "cardsV2": [{
            "cardId": "kingfisher-alert",
            "card": {
                "header": {
                    "title": title,
                    "subtitle": format!("kingfisher v{}", summary.kingfisher_version),
                },
                "sections": sections,
            }
        }]
    })
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
    fn empty_payload_has_no_findings_section() {
        let p = build_payload(&summary(0, 0), &[], false);
        let sections = p["cardsV2"][0]["card"]["sections"].as_array().unwrap();
        assert_eq!(sections.len(), 1, "expected only the Summary section");
        assert_eq!(sections[0]["header"], "Summary");
    }

    #[test]
    fn title_prefixes_emoji_when_active() {
        let p = build_payload(&summary(3, 1), &[], false);
        let title = p["cardsV2"][0]["card"]["header"]["title"].as_str().unwrap();
        assert!(title.starts_with("🚨"), "active findings should prefix the title with 🚨");
    }

    #[test]
    fn title_no_emoji_when_findings_no_active() {
        let p = build_payload(&summary(2, 0), &[], false);
        let title = p["cardsV2"][0]["card"]["header"]["title"].as_str().unwrap();
        assert!(!title.starts_with("🚨"), "no active findings → no emoji prefix");
    }

    #[test]
    fn subtitle_carries_version() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["cardsV2"][0]["card"]["header"]["subtitle"], "kingfisher vtest");
    }
}
