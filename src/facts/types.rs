use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Structured facts extracted from a single source file via tree-sitter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactTable {
    pub file: PathBuf,
    pub language: Language,
    #[serde(default)]
    pub functions: Vec<FunctionFact>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Php,
    Rust,
}

/// Facts about a single function/method.
///
/// All `Vec` and `bool` fields use `#[serde(default)]` because the JSON may
/// pass through an LLM orchestrator that drops empty arrays or `false` values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFact {
    pub name: String,
    pub line_range: (u32, u32),
    pub return_type: Option<String>,
    #[serde(default)]
    pub parameters: Vec<ParamFact>,
    pub transaction: Option<TransactionFact>,
    #[serde(default)]
    pub locks: Vec<LockFact>,
    #[serde(default)]
    pub catch_blocks: Vec<CatchFact>,
    #[serde(default)]
    pub external_calls: Vec<ExternalCallFact>,
    #[serde(default)]
    pub state_mutations: Vec<MutationFact>,
    #[serde(default)]
    pub null_risks: Vec<NullRiskFact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamFact {
    pub name: String,
    pub type_hint: Option<String>,
    #[serde(default)]
    pub nullable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionFact {
    pub line_range: (u32, u32),
    #[serde(default)]
    pub has_lock_for_update: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockFact {
    pub line: u32,
    pub kind: LockKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LockKind {
    LockForUpdate,
    CacheLock,
    SharedLock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchFact {
    pub line: u32,
    pub catches: String,
    pub action: CatchAction,
    #[serde(default)]
    pub side_effects_before: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CatchAction {
    Rethrow,
    LogAndReturn,
    LogAndContinue,
    SilentSwallow,
    ReturnDefault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalCallFact {
    pub line: u32,
    pub target: String,
    #[serde(default)]
    pub in_transaction: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationFact {
    pub line: u32,
    pub kind: MutationKind,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    Create,
    Update,
    Delete,
    Save,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullRiskFact {
    pub line: u32,
    pub expression: String,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_fact_table() -> FactTable {
        FactTable {
            file: PathBuf::from("app/Services/BillingService.php"),
            language: Language::Php,
            functions: vec![FunctionFact {
                name: "processPayment".to_string(),
                line_range: (42, 98),
                return_type: Some("bool".to_string()),
                parameters: vec![ParamFact {
                    name: "$amount".to_string(),
                    type_hint: Some("float".to_string()),
                    nullable: false,
                }],
                transaction: Some(TransactionFact {
                    line_range: (50, 95),
                    has_lock_for_update: true,
                }),
                locks: vec![LockFact {
                    line: 52,
                    kind: LockKind::LockForUpdate,
                }],
                catch_blocks: vec![CatchFact {
                    line: 90,
                    catches: "\\Exception".to_string(),
                    action: CatchAction::LogAndReturn,
                    side_effects_before: vec!["DB::insert payment_log".to_string()],
                }],
                external_calls: vec![ExternalCallFact {
                    line: 70,
                    target: "CathayPaymentProcessingService::authorize".to_string(),
                    in_transaction: true,
                    description: Some("Cathay SOAP API call inside DB transaction".to_string()),
                }],
                state_mutations: vec![MutationFact {
                    line: 75,
                    kind: MutationKind::Create,
                    target: "Pricing_receipt".to_string(),
                }],
                null_risks: vec![NullRiskFact {
                    line: 45,
                    expression: "$reservation->member".to_string(),
                    reason: "member relation can be null for walk-in guests".to_string(),
                }],
            }],
            warnings: vec![],
        }
    }

    #[test]
    fn fact_table_roundtrip_json() {
        let original = sample_fact_table();
        let json = serde_json::to_string_pretty(&original).expect("serialize");
        let restored: FactTable = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.file, original.file);
        assert_eq!(restored.language, original.language);
        assert_eq!(restored.functions.len(), 1);
        assert_eq!(restored.functions[0].name, "processPayment");
        assert_eq!(restored.functions[0].locks[0].kind, LockKind::LockForUpdate);
        assert_eq!(
            restored.functions[0].catch_blocks[0].action,
            CatchAction::LogAndReturn
        );
        assert_eq!(
            restored.functions[0].state_mutations[0].kind,
            MutationKind::Create
        );
    }

    #[test]
    fn language_serializes_as_snake_case() {
        let json = serde_json::to_string(&Language::Php).expect("serialize");
        assert_eq!(json, "\"php\"");

        let json = serde_json::to_string(&Language::Rust).expect("serialize");
        assert_eq!(json, "\"rust\"");
    }

    #[test]
    fn catch_action_variants_roundtrip() {
        let actions = [
            CatchAction::Rethrow,
            CatchAction::LogAndReturn,
            CatchAction::LogAndContinue,
            CatchAction::SilentSwallow,
            CatchAction::ReturnDefault,
        ];
        for action in &actions {
            let json = serde_json::to_string(action).expect("serialize");
            let restored: CatchAction = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&restored, action);
        }
    }
}
