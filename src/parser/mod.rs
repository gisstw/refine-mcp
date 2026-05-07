use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

use crate::types::{Finding, FindingStatus, RedTeamId, Severity};

// ─── Pre-compiled Regexes ──────────────────────────────────────

/// Matches `## [RT-A] ...` through `## [RT-D] ...`
static RE_SOURCE_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^##\s+\[RT-([A-D])\]").expect("valid regex"));

/// Matches `### FATAL` or `### HIGH`
static RE_SEVERITY_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^###\s+(FATAL|HIGH)").expect("valid regex"));

/// Matches finding headers WITH file path in multiple LLM output formats:
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

/// Matches finding headers WITHOUT file path (plan-level findings):
///
/// - `1. **title**`
/// - `1. **title** — description after em-dash`
///
/// Captures: (1)=title
static RE_FINDING_HEADER_NO_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d+\.\s+\*\*(.+?)\*\*\s*$").expect("valid regex"));

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

// ─── JSON Schema (§3.1 / §3.2) ─────────────────────────────────

/// Strict schema for a red team finding when the LLM emits JSON.
/// `affected_plan_steps` is required and must be non-empty —
/// `["OUT_OF_SCOPE"]` is the explicit opt-out (Tier 2 §0.5 / RT-B4).
#[derive(Debug, Deserialize)]
struct RawFinding {
    title: String,
    severity: String,
    file_path: String,
    #[serde(default)]
    line_range: Option<(u32, u32)>,
    #[serde(default)]
    problem: String,
    #[serde(default)]
    attack_scenario: String,
    #[serde(default)]
    suggested_fix: Option<String>,
    affected_plan_steps: Vec<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

/// Which path successfully parsed a given red team report. The synthesize
/// handler surfaces this so the agent knows when output is degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMethod {
    StrictJson,
    JsonAfterStrip,
    LegacyMarkdown,
}

// ─── Public API ────────────────────────────────────────────────

/// Parse a red team report into `Finding` structs. Tries three strategies
/// in order — strict JSON, JSON after stripping markdown fences, then the
/// legacy markdown parser — all within a single call (Tier 2 §0.5 / RT-B3:
/// no cross-call retry state).
///
/// Returns an error rather than `Ok(vec![])` when the input is non-empty
/// but every strategy produces zero findings — that's the silent-failure
/// shape we explicitly want to flag.
pub fn parse_red_team_output(text: &str) -> anyhow::Result<Vec<Finding>> {
    let (findings, _method) = parse_red_team_output_with_method(text)?;
    Ok(findings)
}

/// Same as [`parse_red_team_output`] but also reports which strategy
/// succeeded, so callers can warn the user when they've fallen back to
/// the legacy markdown parser.
pub fn parse_red_team_output_with_method(
    text: &str,
) -> anyhow::Result<(Vec<Finding>, ParseMethod)> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok((Vec::new(), ParseMethod::StrictJson));
    }

    // Stage 1: strict JSON.
    if let Ok(raw) = serde_json::from_str::<Vec<RawFinding>>(trimmed) {
        let findings = raw_findings_to_findings(raw)?;
        return Ok((findings, ParseMethod::StrictJson));
    }

    // Stage 2: JSON after stripping ```json fences.
    let stripped = strip_markdown_fences(trimmed);
    if stripped != trimmed {
        if let Ok(raw) = serde_json::from_str::<Vec<RawFinding>>(stripped.trim()) {
            let findings = raw_findings_to_findings(raw)?;
            return Ok((findings, ParseMethod::JsonAfterStrip));
        }
    }

    // Stage 3: legacy markdown parser. Treat 0 findings as "the input
    // parsed but had no valid finding blocks" only when the input does
    // NOT look like JSON. If it started with `[` we know JSON parsing
    // failed above and zero markdown findings means total format
    // mismatch — surface that as an error.
    let findings = parse_red_team_markdown(text)?;
    if findings.is_empty() && looks_like_json(trimmed) {
        return Err(anyhow::anyhow!(
            "Parser produced 0 findings from JSON-looking input — likely schema mismatch. \
             Expected a JSON array of findings."
        ));
    }
    Ok((findings, ParseMethod::LegacyMarkdown))
}

fn looks_like_json(trimmed: &str) -> bool {
    let stripped = strip_markdown_fences(trimmed).trim();
    stripped.starts_with('[') || stripped.starts_with('{')
}

/// Strip a leading triple-backtick `json` fence and its trailing triple
/// backticks (case-insensitive on `json`). Returns the original string if
/// no fences are present.
fn strip_markdown_fences(text: &str) -> &str {
    let t = text.trim();
    let bytes = t.as_bytes();
    if !bytes.starts_with(b"```") {
        return text;
    }
    // Find the first newline after the opening fence.
    let after_open = match t.find('\n') {
        Some(i) => &t[i + 1..],
        None => return text,
    };
    // Find the closing fence.
    if let Some(close_idx) = after_open.rfind("```") {
        return after_open[..close_idx].trim_end();
    }
    text
}

fn raw_findings_to_findings(raw: Vec<RawFinding>) -> anyhow::Result<Vec<Finding>> {
    let mut errors: Vec<String> = Vec::new();
    let mut out = Vec::with_capacity(raw.len());
    for (i, r) in raw.into_iter().enumerate() {
        if r.affected_plan_steps.is_empty() {
            errors.push(format!(
                "finding #{}: affected_plan_steps is empty (use [\"OUT_OF_SCOPE\"] explicitly)",
                i + 1
            ));
            continue;
        }
        if r.title.trim().is_empty() {
            errors.push(format!("finding #{}: title is empty", i + 1));
            continue;
        }
        let severity = match r.severity.to_lowercase().as_str() {
            "fatal" | "critical" => Severity::Fatal,
            "high" => Severity::High,
            other => {
                errors.push(format!(
                    "finding #{}: invalid severity '{other}' (expected fatal/high)",
                    i + 1
                ));
                continue;
            }
        };
        // Source code is also encoded in prompt routing; missing or unknown
        // tags fall back to RtA.
        let source = match r.source.as_deref().map(str::to_uppercase).as_deref() {
            Some("RT-B" | "RTB") => RedTeamId::RtB,
            Some("RT-C" | "RTC") => RedTeamId::RtC,
            Some("RT-D" | "RTD") => RedTeamId::RtD,
            _ => RedTeamId::RtA,
        };
        let mut finding = Finding::new(
            severity,
            r.title,
            source,
            PathBuf::from(r.file_path),
        );
        finding.id = format!("RT-{:03}", i + 1);
        finding.line_range = r.line_range;
        finding.problem = r.problem;
        finding.attack_scenario = r.attack_scenario;
        finding.suggested_fix = r.suggested_fix;
        finding.affected_plan_steps = r.affected_plan_steps;
        finding.status = FindingStatus::New;
        if let Some(cat) = r.category {
            // Stash category in symbol_path until we have a dedicated field;
            // it's purely informational at the moment.
            finding.symbol_path = Some(format!("category:{cat}"));
        }
        out.push(finding);
    }
    if !errors.is_empty() {
        return Err(anyhow::anyhow!(
            "JSON schema validation failed:\n{}",
            errors.join("\n")
        ));
    }
    Ok(out)
}

/// The historical markdown parser. Kept as a fallback for legacy red team
/// output that doesn't (yet) follow the JSON schema. Same signature as the
/// pre-§3.2 `parse_red_team_output` so the public-facing wrapper can swap
/// between this and the JSON path without churn.
#[allow(clippy::unnecessary_wraps)]
fn parse_red_team_markdown(md: &str) -> anyhow::Result<Vec<Finding>> {
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

        // Check for finding header: 1. **title** (path:line-line) or 1. **title**
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

        // Fallback: finding header without file path (plan-level findings)
        if let Some(caps) = RE_FINDING_HEADER_NO_FILE.captures(line) {
            flush_pending(&mut pending, &mut findings, &mut counter);

            let title = caps[1].to_string();

            pending = Some(PartialFinding {
                source: current_source,
                severity: current_severity,
                title,
                file_path: PathBuf::from("(plan-level)"),
                line_range: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_code_level_findings_with_file_path() {
        let md = "\
## [RT-A] Single-Op Analysis

### FATAL

1. **SQL Injection in search** (app/Controllers/SearchController.php:45-60)
   - Problem: User input interpolated into raw SQL
   - Attack scenario: Attacker drops database via search field
   - Suggested fix: Use parameterized queries

### HIGH

1. **Missing null check** (app/Services/PaymentService.php:120)
   - Problem: Config value used without fallback
   - Attack scenario: App crashes when config key is unset
";
        let findings = parse_red_team_output(md).unwrap();
        assert_eq!(findings.len(), 2);

        assert_eq!(findings[0].title, "SQL Injection in search");
        assert_eq!(
            findings[0].file_path,
            PathBuf::from("app/Controllers/SearchController.php")
        );
        assert_eq!(findings[0].line_range, Some((45, 60)));
        assert_eq!(findings[0].severity, Severity::Fatal);
        assert_eq!(findings[0].sources, vec![RedTeamId::RtA]);
        assert!(findings[0].problem.contains("raw SQL"));

        assert_eq!(findings[1].title, "Missing null check");
        assert_eq!(findings[1].line_range, Some((120, 120)));
        assert_eq!(findings[1].severity, Severity::High);
    }

    #[test]
    fn parses_plan_level_findings_without_file_path() {
        let md = "\
## [RT-A] Silent Failure + Type Safety

### FATAL

1. **Embedding Model Drift Creates Invisible RAG Corruption**
   - Problem: ChromaDB stores vectors with no metadata about which embedding model produced them
   - Attack scenario: Model weights change silently, cosine similarity returns meaningless results

2. **No Ingestion Idempotency**
   - Problem: Running ingestion twice doubles vector weight
   - Suggested fix: Use content hash as deterministic ID

### HIGH

1. **Big5 Encoding Emails Produce Garbage Chunks**
   - Problem: Taiwanese email contains Big5-encoded content
   - Attack scenario: Lossy UTF-8 conversion produces garbage embeddings
";
        let findings = parse_red_team_output(md).unwrap();
        assert_eq!(
            findings.len(),
            3,
            "should parse all 3 findings: {findings:?}"
        );

        // All plan-level findings get the default path
        for f in &findings {
            assert_eq!(f.file_path, PathBuf::from("(plan-level)"));
            assert_eq!(f.line_range, None);
        }

        assert_eq!(findings[0].severity, Severity::Fatal);
        assert_eq!(
            findings[0].title,
            "Embedding Model Drift Creates Invisible RAG Corruption"
        );
        assert!(findings[0].problem.contains("ChromaDB"));
        assert!(findings[0].attack_scenario.contains("cosine similarity"));

        assert_eq!(findings[1].title, "No Ingestion Idempotency");
        assert!(findings[1].suggested_fix.is_some());

        assert_eq!(findings[2].severity, Severity::High);
    }

    #[test]
    fn mixed_code_and_plan_findings() {
        let md = "\
## [RT-B] Concurrency Analysis

### FATAL

1. **Rate Limit Cascade** (src/server.rs:30-50)
   - Problem: No backpressure on API calls

2. **SSE Stream Orphaning**
   - Problem: SSE connections drop on restart with no graceful degradation
   - Attack scenario: Thundering herd on reconnect
";
        let findings = parse_red_team_output(md).unwrap();
        assert_eq!(findings.len(), 2);

        // First: code-level with file path
        assert_eq!(findings[0].file_path, PathBuf::from("src/server.rs"));
        assert_eq!(findings[0].line_range, Some((30, 50)));

        // Second: plan-level without file path
        assert_eq!(findings[1].file_path, PathBuf::from("(plan-level)"));
        assert_eq!(findings[1].line_range, None);
        assert!(findings[1].attack_scenario.contains("Thundering herd"));
    }

    #[test]
    fn empty_input_returns_empty() {
        let findings = parse_red_team_output("").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn skips_findings_without_problem_or_attack() {
        let md = "\
## [RT-A] Analysis

### HIGH

1. **Title Only No Details**
";
        let findings = parse_red_team_output(md).unwrap();
        assert!(
            findings.is_empty(),
            "should skip findings without problem or attack_scenario"
        );
    }

    // ── JSON path (§3.2) ──

    #[test]
    fn parses_strict_json_array() {
        let json = r#"[
            {
                "title": "SQL injection in cart",
                "severity": "fatal",
                "file_path": "app/CartController.php",
                "line_range": [42, 50],
                "problem": "User input goes straight into raw SQL",
                "attack_scenario": "Drop cart_items via crafted query",
                "suggested_fix": "Use parameterized queries",
                "affected_plan_steps": ["§2.3"],
                "source": "RT-A",
                "category": "silent_failure"
            }
        ]"#;
        let (findings, method) = parse_red_team_output_with_method(json).unwrap();
        assert_eq!(method, ParseMethod::StrictJson);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Fatal);
        assert_eq!(findings[0].sources, vec![RedTeamId::RtA]);
        assert_eq!(findings[0].affected_plan_steps, vec!["§2.3"]);
        assert_eq!(
            findings[0].symbol_path.as_deref(),
            Some("category:silent_failure")
        );
    }

    #[test]
    fn parses_json_after_stripping_markdown_fences() {
        let wrapped = "```json\n[{\
            \"title\":\"X\",\
            \"severity\":\"high\",\
            \"file_path\":\"a.rs\",\
            \"problem\":\"p\",\
            \"attack_scenario\":\"a\",\
            \"affected_plan_steps\":[\"OUT_OF_SCOPE\"]\
        }]\n```";
        let (findings, method) = parse_red_team_output_with_method(wrapped).unwrap();
        assert_eq!(method, ParseMethod::JsonAfterStrip);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn rejects_json_with_empty_affected_plan_steps() {
        let json = r#"[{
            "title": "X",
            "severity": "high",
            "file_path": "a.rs",
            "problem": "p",
            "attack_scenario": "a",
            "affected_plan_steps": []
        }]"#;
        let err = parse_red_team_output(json).unwrap_err();
        assert!(
            err.to_string().contains("affected_plan_steps"),
            "expected schema error mentioning affected_plan_steps, got: {err}"
        );
    }

    #[test]
    fn json_looking_input_with_zero_findings_is_an_error() {
        // Valid JSON shape but parses to nothing useful via markdown either.
        let bad = "[ \"random text\" ]";
        let err = parse_red_team_output(bad).unwrap_err();
        // Exact message varies; the key thing is it's an error, not Ok([]).
        let msg = err.to_string();
        assert!(
            msg.contains("schema") || msg.contains("0 findings") || msg.contains("invalid"),
            "expected schema-mismatch error, got: {msg}"
        );
    }

    #[test]
    fn pure_markdown_with_zero_findings_is_not_an_error() {
        // Random prose that isn't a finding report and isn't JSON-looking
        // should still parse to Ok(empty) — only JSON-shaped input gets
        // the strict-zero treatment.
        let prose = "Just some discussion without any structured findings.\n";
        let findings = parse_red_team_output(prose).unwrap();
        assert!(findings.is_empty());
    }
}
