use crate::facts::types::FactTable;
use crate::types::{Finding, RedTeamId, RedTeamPrompt, RefineMode};

// ─── Embedded Templates ────────────────────────────────────────

const TEMPLATE_RT_A: &str = include_str!("../../templates/rt_a_single_op.md");
const TEMPLATE_RT_B: &str = include_str!("../../templates/rt_b_multi_op.md");
const TEMPLATE_BLUE: &str = include_str!("../../templates/blue_cross_analysis.md");

// ─── Public API ────────────────────────────────────────────────

/// Build red team prompts from fact tables and plan content.
///
/// Returns 2 prompts (RT-A and RT-B) with model recommendations based on mode.
#[must_use]
pub fn build_red_team_prompts(
    mode: RefineMode,
    plan_content: &str,
    fact_tables: &[FactTable],
) -> Vec<RedTeamPrompt> {
    let facts_json =
        serde_json::to_string_pretty(fact_tables).unwrap_or_else(|_| "[]".to_string());

    let rt_a = TEMPLATE_RT_A
        .replace("{plan_content}", plan_content)
        .replace("{fact_tables}", &facts_json);

    let rt_b = TEMPLATE_RT_B
        .replace("{plan_content}", plan_content)
        .replace("{fact_tables}", &facts_json);

    vec![
        RedTeamPrompt {
            id: RedTeamId::RtA,
            prompt: rt_a,
            recommended_model: mode.red_model().to_string(),
        },
        RedTeamPrompt {
            id: RedTeamId::RtB,
            prompt: rt_b,
            recommended_model: mode.red_model().to_string(),
        },
    ]
}

/// Build blue team prompt from pre-processed findings.
///
/// The blue team receives only the deduped, validated, ranked findings —
/// NOT the raw red team output. This cuts input from ~15K to ~3K tokens.
#[must_use]
pub fn build_blue_team_prompt(
    mode: RefineMode,
    findings: &[Finding],
    plan_summary: &str,
) -> RedTeamPrompt {
    let findings_json =
        serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string());

    let prompt = TEMPLATE_BLUE
        .replace("{findings_json}", &findings_json)
        .replace("{plan_summary}", plan_summary);

    RedTeamPrompt {
        id: RedTeamId::RtA, // Blue team doesn't have its own ID; reuse for struct compatibility
        prompt,
        recommended_model: mode.blue_model().to_string(),
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::types::{FunctionFact, Language};
    use std::path::PathBuf;

    fn sample_fact_table() -> FactTable {
        FactTable {
            file: PathBuf::from("app/Services/TestService.php"),
            language: Language::Php,
            functions: vec![FunctionFact {
                name: "process".to_string(),
                line_range: (10, 30),
                return_type: Some("void".to_string()),
                parameters: Vec::new(),
                transaction: None,
                locks: Vec::new(),
                catch_blocks: Vec::new(),
                external_calls: Vec::new(),
                state_mutations: Vec::new(),
                null_risks: Vec::new(),
            }],
            warnings: vec!["process: 2 SQL mutations without transaction".to_string()],
        }
    }

    #[test]
    fn red_team_prompts_contain_plan_and_facts() {
        let facts = vec![sample_fact_table()];
        let prompts = build_red_team_prompts(RefineMode::Default, "My plan content", &facts);

        assert_eq!(prompts.len(), 2);
        assert_eq!(prompts[0].id, RedTeamId::RtA);
        assert_eq!(prompts[1].id, RedTeamId::RtB);

        // Plan content injected
        assert!(prompts[0].prompt.contains("My plan content"));
        assert!(prompts[1].prompt.contains("My plan content"));

        // Facts injected
        assert!(prompts[0].prompt.contains("TestService.php"));
        assert!(prompts[1].prompt.contains("TestService.php"));
    }

    #[test]
    fn red_team_model_matches_mode() {
        let facts = vec![sample_fact_table()];

        let default_prompts = build_red_team_prompts(RefineMode::Default, "plan", &facts);
        assert_eq!(default_prompts[0].recommended_model, "opus");

        let lite_prompts = build_red_team_prompts(RefineMode::Lite, "plan", &facts);
        assert_eq!(lite_prompts[0].recommended_model, "sonnet");

        let auto_prompts = build_red_team_prompts(RefineMode::Auto, "plan", &facts);
        assert_eq!(auto_prompts[0].recommended_model, "haiku");
    }

    #[test]
    fn blue_team_prompt_contains_findings() {
        let findings = vec![crate::types::Finding {
            id: "RT-001".to_string(),
            severity: crate::types::Severity::Fatal,
            title: "Test finding".to_string(),
            sources: vec![RedTeamId::RtA],
            file_path: PathBuf::from("app/Services/Svc.php"),
            line_range: Some((10, 20)),
            problem: "Test problem".to_string(),
            attack_scenario: "Test attack".to_string(),
            suggested_fix: None,
            affected_plan_steps: Vec::new(),
            status: crate::types::FindingStatus::New,
            impact_score: 100,
        }];

        let prompt = build_blue_team_prompt(RefineMode::Default, &findings, "Plan summary");

        assert!(prompt.prompt.contains("RT-001"));
        assert!(prompt.prompt.contains("Test finding"));
        assert!(prompt.prompt.contains("Plan summary"));
        assert_eq!(prompt.recommended_model, "opus");
    }

    #[test]
    fn blue_team_model_lite_uses_sonnet() {
        let prompt = build_blue_team_prompt(RefineMode::Lite, &[], "summary");
        assert_eq!(prompt.recommended_model, "sonnet");
    }
}
