use crate::facts::types::FactTable;
use crate::types::{Finding, RedTeamId, RedTeamPrompt, RefineMode};

// ─── Embedded Templates ────────────────────────────────────────

const TEMPLATE_RT_A: &str = include_str!("../../templates/rt_a_single_op.md");
const TEMPLATE_RT_B: &str = include_str!("../../templates/rt_b_multi_op.md");
const TEMPLATE_RT_C: &str = include_str!("../../templates/rt_c_data_integrity.md");
const TEMPLATE_RT_D: &str = include_str!("../../templates/rt_d_auth_boundary.md");
const TEMPLATE_BLUE: &str = include_str!("../../templates/blue_cross_analysis.md");

// ─── Public API ────────────────────────────────────────────────

/// Build red team prompts from fact tables and plan content.
///
/// Returns `red_count` prompts (2-4) with model recommendations based on mode.
/// - 2: RT-A (single-op) + RT-B (multi-op)        — default
/// - 3: + RT-C (data integrity)
/// - 4: + RT-D (auth boundary)
#[must_use]
pub fn build_red_team_prompts_n(
    mode: RefineMode,
    plan_content: &str,
    fact_tables: &[FactTable],
    red_count: usize,
) -> Vec<RedTeamPrompt> {
    let count = red_count.clamp(2, 4);
    let ids: Vec<RedTeamId> = [
        RedTeamId::RtA,
        RedTeamId::RtB,
        RedTeamId::RtC,
        RedTeamId::RtD,
    ][..count]
        .to_vec();
    build_red_team_prompts_selected(mode, plan_content, fact_tables, &ids)
}

/// Build red team prompts for a specific set of selected red team roles.
///
/// Use this with [`auto_select_red_teams`] for fact-driven team selection,
/// or pass a hand-picked list of roles.
#[must_use]
pub fn build_red_team_prompts_selected(
    mode: RefineMode,
    plan_content: &str,
    fact_tables: &[FactTable],
    teams: &[RedTeamId],
) -> Vec<RedTeamPrompt> {
    let facts_json = serde_json::to_string_pretty(fact_tables).unwrap_or_else(|_| "[]".to_string());

    teams
        .iter()
        .map(|id| {
            let template = template_for(*id);
            let prompt = template
                .replace("{plan_content}", plan_content)
                .replace("{fact_tables}", &facts_json);
            RedTeamPrompt {
                id: *id,
                prompt,
                recommended_model: mode.red_model().to_string(),
            }
        })
        .collect()
}

/// Automatically select which red teams to run based on fact table signals.
///
/// Always includes RT-A and RT-B (baseline). Adds RT-C/RT-D when the facts
/// suggest those analysis dimensions would find real issues.
///
/// # Selection logic
///
/// | Signal in FactTable | Red Team added |
/// |---------------------|----------------|
/// | mutations without transaction | RT-C (data integrity) |
/// | external calls in transaction | RT-C (data integrity) |
/// | catch blocks with `SilentSwallow` | RT-C (data integrity) |
/// | file path contains auth/permission/middleware/login/session | RT-D (auth boundary) |
/// | null risks present | (already covered by RT-A) |
#[must_use]
pub fn auto_select_red_teams(fact_tables: &[FactTable]) -> Vec<RedTeamId> {
    let mut teams = vec![RedTeamId::RtA, RedTeamId::RtB];

    let mut need_rt_c = false;
    let mut need_rt_d = false;

    for table in fact_tables {
        // RT-C signals: data integrity concerns
        for f in &table.functions {
            // Mutations without transaction = data integrity risk
            if f.state_mutations.len() >= 2 && f.transaction.is_none() {
                need_rt_c = true;
            }
            // External call inside transaction = partial failure risk
            if f.external_calls.iter().any(|e| e.in_transaction) {
                need_rt_c = true;
            }
            // Silent swallow = data loss risk
            if f.catch_blocks
                .iter()
                .any(|c| c.action == crate::facts::types::CatchAction::SilentSwallow)
            {
                need_rt_c = true;
            }
        }

        // RT-D signals: auth/permission boundary concerns
        let path_lower = table.file.to_string_lossy().to_lowercase();
        if path_lower.contains("auth")
            || path_lower.contains("permission")
            || path_lower.contains("middleware")
            || path_lower.contains("login")
            || path_lower.contains("session")
            || path_lower.contains("guard")
            || path_lower.contains("policy")
            || path_lower.contains("role")
            || path_lower.contains("access")
            || path_lower.contains("token")
        {
            need_rt_d = true;
        }
    }

    if need_rt_c {
        teams.push(RedTeamId::RtC);
    }
    if need_rt_d {
        teams.push(RedTeamId::RtD);
    }

    teams
}

/// Build red team prompts with the mode's default `red_count` (always 2).
///
/// For configurable count, use [`build_red_team_prompts_n`].
/// For fact-driven selection, use [`auto_select_red_teams`] + [`build_red_team_prompts_selected`].
#[must_use]
pub fn build_red_team_prompts(
    mode: RefineMode,
    plan_content: &str,
    fact_tables: &[FactTable],
) -> Vec<RedTeamPrompt> {
    build_red_team_prompts_n(mode, plan_content, fact_tables, mode.red_count())
}

fn template_for(id: RedTeamId) -> &'static str {
    match id {
        RedTeamId::RtA => TEMPLATE_RT_A,
        RedTeamId::RtB => TEMPLATE_RT_B,
        RedTeamId::RtC => TEMPLATE_RT_C,
        RedTeamId::RtD => TEMPLATE_RT_D,
    }
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
    let findings_json = serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string());

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

    #[test]
    fn auto_select_baseline_only() {
        // No special signals → only RT-A + RT-B
        let facts = vec![sample_fact_table()];
        let teams = auto_select_red_teams(&facts);
        assert_eq!(teams, vec![RedTeamId::RtA, RedTeamId::RtB]);
    }

    #[test]
    fn auto_select_adds_rt_c_for_mutations_without_tx() {
        use crate::facts::types::{MutationFact, MutationKind};
        let facts = vec![FactTable {
            file: PathBuf::from("app/Services/PaymentService.php"),
            language: Language::Php,
            functions: vec![FunctionFact {
                name: "transferFunds".to_string(),
                line_range: (10, 40),
                return_type: None,
                parameters: Vec::new(),
                transaction: None, // No transaction!
                locks: Vec::new(),
                catch_blocks: Vec::new(),
                external_calls: Vec::new(),
                state_mutations: vec![
                    MutationFact {
                        line: 15,
                        kind: MutationKind::Update,
                        target: "debit".into(),
                    },
                    MutationFact {
                        line: 20,
                        kind: MutationKind::Update,
                        target: "credit".into(),
                    },
                ],
                null_risks: Vec::new(),
            }],
            warnings: vec![],
        }];
        let teams = auto_select_red_teams(&facts);
        assert!(
            teams.contains(&RedTeamId::RtC),
            "should add RT-C for unprotected mutations"
        );
        assert!(
            !teams.contains(&RedTeamId::RtD),
            "should not add RT-D without auth signals"
        );
    }

    #[test]
    fn auto_select_adds_rt_d_for_auth_files() {
        let facts = vec![FactTable {
            file: PathBuf::from("app/Http/Middleware/AuthMiddleware.php"),
            language: Language::Php,
            functions: vec![],
            warnings: vec![],
        }];
        let teams = auto_select_red_teams(&facts);
        assert!(
            teams.contains(&RedTeamId::RtD),
            "should add RT-D for auth-related files"
        );
    }

    #[test]
    fn auto_select_adds_rt_c_for_external_call_in_tx() {
        use crate::facts::types::{ExternalCallFact, TransactionFact};
        let facts = vec![FactTable {
            file: PathBuf::from("app/Services/OrderService.php"),
            language: Language::Php,
            functions: vec![FunctionFact {
                name: "placeOrder".to_string(),
                line_range: (10, 50),
                return_type: None,
                parameters: Vec::new(),
                transaction: Some(TransactionFact {
                    line_range: (12, 48),
                    has_lock_for_update: false,
                }),
                locks: Vec::new(),
                catch_blocks: Vec::new(),
                external_calls: vec![ExternalCallFact {
                    line: 30,
                    target: "PaymentGateway::charge".into(),
                    in_transaction: true,
                    description: Some("HTTP call inside DB transaction".into()),
                }],
                state_mutations: Vec::new(),
                null_risks: Vec::new(),
            }],
            warnings: vec![],
        }];
        let teams = auto_select_red_teams(&facts);
        assert!(
            teams.contains(&RedTeamId::RtC),
            "external call in tx → RT-C"
        );
    }

    #[test]
    fn auto_select_full_suite() {
        use crate::facts::types::{CatchAction, CatchFact, MutationFact, MutationKind};
        let facts = vec![FactTable {
            file: PathBuf::from("app/Http/Middleware/SessionGuard.php"),
            language: Language::Php,
            functions: vec![FunctionFact {
                name: "handle".to_string(),
                line_range: (5, 30),
                return_type: None,
                parameters: Vec::new(),
                transaction: None,
                locks: Vec::new(),
                catch_blocks: vec![CatchFact {
                    line: 20,
                    catches: "Exception".into(),
                    action: CatchAction::SilentSwallow,
                    side_effects_before: vec![],
                }],
                external_calls: Vec::new(),
                state_mutations: vec![
                    MutationFact {
                        line: 10,
                        kind: MutationKind::Create,
                        target: "a".into(),
                    },
                    MutationFact {
                        line: 15,
                        kind: MutationKind::Update,
                        target: "b".into(),
                    },
                ],
                null_risks: Vec::new(),
            }],
            warnings: vec![],
        }];
        let teams = auto_select_red_teams(&facts);
        assert_eq!(teams.len(), 4, "should select all 4 teams: {teams:?}");
        assert_eq!(
            teams,
            vec![
                RedTeamId::RtA,
                RedTeamId::RtB,
                RedTeamId::RtC,
                RedTeamId::RtD
            ]
        );
    }

    #[test]
    fn build_selected_respects_team_list() {
        let facts = vec![sample_fact_table()];
        let teams = vec![RedTeamId::RtB, RedTeamId::RtD]; // skip A and C
        let prompts = build_red_team_prompts_selected(RefineMode::Lite, "plan", &facts, &teams);
        assert_eq!(prompts.len(), 2);
        assert_eq!(prompts[0].id, RedTeamId::RtB);
        assert_eq!(prompts[1].id, RedTeamId::RtD);
    }
}
