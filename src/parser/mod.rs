use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;

use crate::types::{Finding, RedTeamId, Severity};

// ─── Pre-compiled Regexes ──────────────────────────────────────

/// Matches `## [RT-A] ...` through `## [RT-D] ...`
static RE_SOURCE_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^##\s+\[RT-([A-D])\]").expect("valid regex"));

/// Matches `### FATAL` or `### HIGH`
static RE_SEVERITY_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^###\s+(FATAL|HIGH)").expect("valid regex"));

/// Matches finding headers in multiple LLM output formats:
///
/// - Standard:         `1. **title** (file.rs:123-456)`
/// - Backtick-wrapped: 1. **title** (`` `file.rs:137` ``)
/// - L-prefixed:       `1. **title** (file.rs:L137)`
/// - Multi-file:       `1. **title** (file.rs, other.rs)`
/// - No line number:   `1. **title** (file.rs)`
///
/// Captures: (1)=title, (2)=first file path, (3)=start line?, (4)=end line?
static RE_FINDING_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\d+\.\s+\*\*(.+?)\*\*\s+\(`?([^:,`)\s]+)(?::L?(\d+)(?:-L?(\d+))?)?")
        .expect("valid regex")
});

/// Matches `   - 問題：...` or `   - Problem: ...`
static RE_PROBLEM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s+-\s+(?:問題|Problem)[：:](.+)").expect("valid regex"));

/// Matches `   - 攻擊場景：...` or `   - Attack scenario: ...`
static RE_ATTACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s+-\s+(?:攻擊場景|Attack [Ss]cenario|Combined [Ss]cenario)[：:](.+)")
        .expect("valid regex")
});

/// Matches `   - 建議修復：...` or `   - Suggested fix: ...`
static RE_FIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s+-\s+(?:建議修復|Suggested [Ff]ix)[：:](.+)").expect("valid regex")
});

// ─── Public API ────────────────────────────────────────────────

/// Parse structured red team markdown output into `Finding` structs.
///
/// The expected format uses hierarchical headers:
/// - `## [RT-A] description` — red team source
/// - `### FATAL` / `### HIGH` — severity
/// - `1. **title** (file:line-line)` — individual finding
/// - `- 問題：...` / `- 攻擊場景：...` / `- 建議修復：...` — details
pub fn parse_red_team_output(md: &str) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut current_source: Option<RedTeamId> = None;
    let mut current_severity: Option<Severity> = None;

    // In-progress finding being assembled
    let mut pending: Option<PartialFinding> = None;
    let mut counter: u32 = 0;

    for line in md.lines() {
        // Check for source header: ## [RT-A] ...
        if let Some(caps) = RE_SOURCE_HEADER.captures(line) {
            flush_pending(&mut pending, &mut findings, &mut counter);
            current_source = Some(match &caps[1] {
                "A" => RedTeamId::RtA,
                "B" => RedTeamId::RtB,
                "C" => RedTeamId::RtC,
                "D" => RedTeamId::RtD,
                _ => continue,
            });
            current_severity = None;
            continue;
        }

        // Check for severity header: ### FATAL / ### HIGH
        if let Some(caps) = RE_SEVERITY_HEADER.captures(line) {
            flush_pending(&mut pending, &mut findings, &mut counter);
            current_severity = Some(match &caps[1] {
                "FATAL" => Severity::Fatal,
                "HIGH" => Severity::High,
                _ => continue,
            });
            continue;
        }

        // Check for finding header: 1. **title** (path:line-line)
        if let Some(caps) = RE_FINDING_HEADER.captures(line) {
            flush_pending(&mut pending, &mut findings, &mut counter);

            let title = caps[1].to_string();
            let file_path = PathBuf::from(&caps[2]);
            let line_range = caps.get(3).map(|start_m| {
                let start: u32 = start_m.as_str().parse().unwrap_or(0);
                let end: u32 = caps
                    .get(4)
                    .map_or(start, |m| m.as_str().parse().unwrap_or(start));
                (start, end)
            });

            pending = Some(PartialFinding {
                source: current_source,
                severity: current_severity,
                title,
                file_path,
                line_range,
                problem: None,
                attack_scenario: None,
                suggested_fix: None,
            });
            continue;
        }

        // Fill in sub-fields of the current pending finding
        if let Some(ref mut pf) = pending {
            if let Some(caps) = RE_PROBLEM.captures(line) {
                pf.problem = Some(caps[1].trim().to_string());
            } else if let Some(caps) = RE_ATTACK.captures(line) {
                pf.attack_scenario = Some(caps[1].trim().to_string());
            } else if let Some(caps) = RE_FIX.captures(line) {
                pf.suggested_fix = Some(caps[1].trim().to_string());
            }
        }
    }

    // Flush last pending finding
    flush_pending(&mut pending, &mut findings, &mut counter);

    Ok(findings)
}

// ─── Internal Types ────────────────────────────────────────────

struct PartialFinding {
    source: Option<RedTeamId>,
    severity: Option<Severity>,
    title: String,
    file_path: PathBuf,
    line_range: Option<(u32, u32)>,
    problem: Option<String>,
    attack_scenario: Option<String>,
    suggested_fix: Option<String>,
}

fn flush_pending(
    pending: &mut Option<PartialFinding>,
    findings: &mut Vec<Finding>,
    counter: &mut u32,
) {
    let Some(pf) = pending.take() else {
        return;
    };

    // Skip findings with empty problem AND empty attack_scenario — they're
    // likely parser artifacts from LLM format deviations, not real findings.
    let has_problem = pf.problem.as_deref().is_some_and(|s| !s.is_empty());
    let has_attack = pf.attack_scenario.as_deref().is_some_and(|s| !s.is_empty());
    if !has_problem && !has_attack {
        return;
    }

    *counter += 1;

    let source = pf.source.unwrap_or(RedTeamId::RtA);
    let severity = pf.severity.unwrap_or(Severity::High);

    let mut finding = Finding::new(severity, pf.title, source, pf.file_path);
    finding.id = format!("RT-{counter:03}");
    finding.line_range = pf.line_range;
    finding.problem = pf.problem.unwrap_or_default();
    finding.attack_scenario = pf.attack_scenario.unwrap_or_default();
    finding.suggested_fix = pf.suggested_fix;

    findings.push(finding);
}
