use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Structured facts extracted from a single source file via tree-sitter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactTable {
    pub file: PathBuf,
    #[serde(default)]
    pub language: Language,
    #[serde(default)]
    pub functions: Vec<FunctionFact>,
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Callers of functions in this file, populated by `expand_blast_radius`
    #[serde(default)]
    pub callers: Vec<CallerFact>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    #[default]
    Php,
    Rust,
    TypeScript,
    Python,
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
    #[serde(default)]
    pub expression: String,
    #[serde(default)]
    pub reason: String,
}

// ─── Blast Radius Facts ─────────────────────────────────────

/// A caller of a function found via grep search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerFact {
    pub symbol: String,
    pub caller_file: PathBuf,
    pub caller_line: u32,
    pub context: String,
}

// ─── Schema Facts ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SchemaSnapshot {
    pub tables: Vec<SchemaTable>,
    #[serde(default)]
    pub type_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaTable {
    pub table_name: String,
    pub columns: Vec<ColumnFact>,
    #[serde(default)]
    pub foreign_keys: Vec<ForeignKeyFact>,
    #[serde(default)]
    pub indexes: Vec<String>,
    pub source_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnFact {
    pub name: String,
    pub col_type: String,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default)]
    pub has_default: bool,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForeignKeyFact {
    pub column: String,
    pub references_table: String,
    pub references_column: String,
    pub on_delete: Option<String>,
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
                    target: "PaymentGateway::authorize".to_string(),
                    in_transaction: true,
                    description: Some("Payment API call inside DB transaction".to_string()),
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
            callers: vec![],
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

    #[test]
    fn caller_fact_roundtrip() {
        let caller = CallerFact {
            symbol: "createMainBill".to_string(),
            caller_file: PathBuf::from("app/Services/WalkinBetaService.php"),
            caller_line: 142,
            context: "$this->billingService->createMainBill($orderSerial)".to_string(),
        };
        let json = serde_json::to_string(&caller).expect("serialize");
        let restored: CallerFact = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.symbol, "createMainBill");
        assert_eq!(restored.caller_line, 142);
    }

    #[test]
    fn schema_snapshot_roundtrip() {
        let schema = SchemaSnapshot {
            tables: vec![SchemaTable {
                table_name: "reservations".to_string(),
                columns: vec![ColumnFact {
                    name: "status".to_string(),
                    col_type: "tinyInteger".to_string(),
                    nullable: false,
                    has_default: true,
                    default_value: Some("1".to_string()),
                }],
                foreign_keys: vec![ForeignKeyFact {
                    column: "Rt_id".to_string(),
                    references_table: "room_type".to_string(),
                    references_column: "id".to_string(),
                    on_delete: Some("CASCADE".to_string()),
                }],
                indexes: vec!["idx_status".to_string()],
                source_file: PathBuf::from("database/migrations/create_reservations.php"),
            }],
            type_warnings: vec!["price is VARCHAR".to_string()],
        };
        let json = serde_json::to_string_pretty(&schema).expect("serialize");
        let restored: SchemaSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.tables.len(), 1);
        assert_eq!(restored.tables[0].columns[0].col_type, "tinyInteger");
        assert_eq!(
            restored.tables[0].foreign_keys[0].on_delete.as_deref(),
            Some("CASCADE")
        );
    }

    #[test]
    fn fact_table_with_callers_roundtrip() {
        let table = FactTable {
            file: PathBuf::from("app/Services/Test.php"),
            language: Language::Php,
            functions: vec![],
            warnings: vec![],
            callers: vec![CallerFact {
                symbol: "test".to_string(),
                caller_file: PathBuf::from("app/Other.php"),
                caller_line: 10,
                context: "->test()".to_string(),
            }],
        };
        let json = serde_json::to_string(&table).expect("serialize");
        let restored: FactTable = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.callers.len(), 1);
    }
}
