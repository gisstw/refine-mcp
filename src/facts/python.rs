use std::path::Path;
use std::sync::{LazyLock, OnceLock};

use regex::Regex;
use tree_sitter::Parser;

use super::types::{
    CatchAction, CatchFact, ExternalCallFact, FactTable, FunctionFact, Language, LockFact,
    LockKind, MutationFact, MutationKind, NullRiskFact, ParamFact, TransactionFact,
};

// ─── Pre-compiled Regexes ──────────────────────────────────────

struct ExternalCallPattern {
    regex: Regex,
    description: &'static str,
}

fn external_call_patterns() -> &'static [ExternalCallPattern] {
    static PATTERNS: OnceLock<Vec<ExternalCallPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            ExternalCallPattern {
                regex: Regex::new(r"requests\.(get|post|put|delete|patch)\(").expect("valid regex"),
                description: "requests HTTP call",
            },
            ExternalCallPattern {
                regex: Regex::new(r"httpx\.(get|post|put|delete|patch|AsyncClient)\(")
                    .expect("valid regex"),
                description: "httpx HTTP call",
            },
            ExternalCallPattern {
                regex: Regex::new(r"urllib\.request\.|urlopen\(").expect("valid regex"),
                description: "urllib HTTP call",
            },
            ExternalCallPattern {
                regex: Regex::new(r"aiohttp\.ClientSession\(").expect("valid regex"),
                description: "aiohttp HTTP call",
            },
            ExternalCallPattern {
                regex: Regex::new(r"subprocess\.(run|call|Popen|check_output)\(")
                    .expect("valid regex"),
                description: "subprocess call",
            },
        ]
    })
}

// ─── Public API ────────────────────────────────────────────────

/// Extract structured facts from Python source code using tree-sitter.
pub fn extract_python_facts(path: &Path, source: &str) -> anyhow::Result<FactTable> {
    let mut parser = Parser::new();
    let language = tree_sitter_python::LANGUAGE.into();
    parser.set_language(&language)?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse Python: {}", path.display()))?;

    let root = tree.root_node();
    let source_bytes = source.as_bytes();

    let mut functions = Vec::new();
    let mut warnings = Vec::new();

    collect_functions(root, source_bytes, &mut functions);
    generate_warnings(&functions, &mut warnings);

    Ok(FactTable {
        file: path.to_path_buf(),
        language: Language::Python,
        functions,
        warnings,
    })
}

// ─── AST Walking ───────────────────────────────────────────────

fn collect_functions(node: tree_sitter::Node, source: &[u8], functions: &mut Vec<FunctionFact>) {
    if node.kind() == "function_definition" {
        if let Some(fact) = extract_function_fact(node, source) {
            functions.push(fact);
        }
        // Don't return — collect nested functions too
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_functions(child, source, functions);
    }
}

fn extract_function_fact(func: tree_sitter::Node, source: &[u8]) -> Option<FunctionFact> {
    let name_node = func.child_by_field_name("name")?;
    let fn_name = name_node.utf8_text(source).ok()?.to_string();

    #[allow(clippy::cast_possible_truncation)]
    let start_line = func.start_position().row as u32 + 1;
    #[allow(clippy::cast_possible_truncation)]
    let end_line = func.end_position().row as u32 + 1;
    let fn_text = func.utf8_text(source).ok()?;

    let return_type = extract_return_type(func, source);
    let parameters = extract_parameters(func, source);
    let transaction = extract_transaction(fn_text, start_line);
    let locks = extract_locks(fn_text, start_line);
    let catch_blocks = extract_catch_blocks(fn_text, start_line);
    let external_calls = extract_external_calls(fn_text, start_line, transaction.as_ref());
    let state_mutations = extract_mutations(fn_text, start_line);
    let null_risks = extract_null_risks(fn_text, start_line);

    Some(FunctionFact {
        name: fn_name,
        line_range: (start_line, end_line),
        return_type,
        parameters,
        transaction,
        locks,
        catch_blocks,
        external_calls,
        state_mutations,
        null_risks,
    })
}

// ─── Fact Extractors ───────────────────────────────────────────

fn extract_return_type(func: tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Python: def foo() -> str: → return_type field
    let ret = func.child_by_field_name("return_type")?;
    let text = ret.utf8_text(source).ok()?.trim().to_string();
    Some(text)
}

fn extract_parameters(func: tree_sitter::Node, source: &[u8]) -> Vec<ParamFact> {
    let params_node = func.child_by_field_name("parameters");
    let Some(params_node) = params_node else {
        return Vec::new();
    };

    let mut params = Vec::new();
    let mut cursor = params_node.walk();

    for child in params_node.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                let name = child.utf8_text(source).ok().unwrap_or("?").to_string();
                if name != "self" && name != "cls" {
                    params.push(ParamFact {
                        name,
                        type_hint: None,
                        nullable: false,
                    });
                }
            }
            "typed_parameter" | "default_parameter" | "typed_default_parameter" => {
                let name = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("?")
                    .to_string();

                if name == "self" || name == "cls" {
                    continue;
                }

                let type_text = child
                    .child_by_field_name("type")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(String::from);

                let nullable = type_text.as_deref().is_some_and(|t| {
                    t.contains("Optional") || t.contains("None") || t.contains("| None")
                }) || child.kind() == "default_parameter"
                    || child.kind() == "typed_default_parameter";

                params.push(ParamFact {
                    name,
                    type_hint: type_text,
                    nullable,
                });
            }
            _ => {}
        }
    }
    params
}

fn extract_transaction(fn_text: &str, start_line: u32) -> Option<TransactionFact> {
    static RE_TX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"transaction\.atomic|session\.begin\(|session\.commit\(|\.transaction\(\)|BEGIN",
        )
        .expect("valid regex")
    });

    if RE_TX.is_match(fn_text) {
        let lines: Vec<&str> = fn_text.lines().collect();
        let start = lines.iter().position(|l| RE_TX.is_match(l)).unwrap_or(0);
        #[allow(clippy::cast_possible_truncation)]
        Some(TransactionFact {
            line_range: (start_line + start as u32, start_line + lines.len() as u32),
            has_lock_for_update: fn_text.contains("FOR UPDATE")
                || fn_text.contains("select_for_update"),
        })
    } else {
        None
    }
}

fn extract_locks(fn_text: &str, start_line: u32) -> Vec<LockFact> {
    static RE_LOCK: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(Lock|RLock|Semaphore|acquire|threading\.Lock|asyncio\.Lock)\b")
            .expect("valid regex")
    });

    let mut locks = Vec::new();
    for (i, line) in fn_text.lines().enumerate() {
        if RE_LOCK.is_match(line) {
            #[allow(clippy::cast_possible_truncation)]
            locks.push(LockFact {
                kind: LockKind::CacheLock,
                line: start_line + i as u32,
            });
        }
    }
    locks
}

fn extract_catch_blocks(fn_text: &str, start_line: u32) -> Vec<CatchFact> {
    let mut catches = Vec::new();
    let lines: Vec<&str> = fn_text.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Python: except ExceptionType: or except: (bare except)
        if trimmed.starts_with("except") {
            let exception_type = if trimmed == "except:" {
                "bare except (catches all)".to_string()
            } else {
                trimmed
                    .strip_prefix("except ")
                    .and_then(|s| s.split(':').next())
                    .and_then(|s| s.split(" as ").next())
                    .unwrap_or("Exception")
                    .trim()
                    .to_string()
            };

            // Look at what happens in the except block (next 5 lines)
            let block_end = (i + 5).min(lines.len());
            let block_text: String = lines[i..block_end].join("\n");

            let action = if block_text.contains("raise") {
                CatchAction::Rethrow
            } else if block_text.contains("logging.")
                || block_text.contains("logger.")
                || block_text.contains("print(")
            {
                CatchAction::LogAndContinue
            } else if block_text.contains("return") {
                CatchAction::ReturnDefault
            } else if block_text.trim_end() == "pass" || block_text.contains("\n    pass") {
                CatchAction::SilentSwallow
            } else {
                CatchAction::SilentSwallow
            };

            #[allow(clippy::cast_possible_truncation)]
            catches.push(CatchFact {
                catches: exception_type,
                action,
                line: start_line + i as u32,
                side_effects_before: Vec::new(),
            });
        }
    }
    catches
}

fn extract_external_calls(
    fn_text: &str,
    start_line: u32,
    transaction: Option<&TransactionFact>,
) -> Vec<ExternalCallFact> {
    let mut calls = Vec::new();

    for (i, line) in fn_text.lines().enumerate() {
        for pattern in external_call_patterns() {
            if pattern.regex.is_match(line) {
                #[allow(clippy::cast_possible_truncation)]
                calls.push(ExternalCallFact {
                    target: pattern.description.to_string(),
                    line: start_line + i as u32,
                    in_transaction: transaction.is_some(),
                    description: Some(pattern.description.to_string()),
                });
                break;
            }
        }
    }
    calls
}

fn extract_mutations(fn_text: &str, start_line: u32) -> Vec<MutationFact> {
    // Django ORM
    static RE_CREATE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\.(create|bulk_create|get_or_create|save)\(|session\.add\(")
            .expect("valid regex")
    });
    static RE_UPDATE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\.(update|bulk_update|filter\(.*\)\.update)\(|session\.merge\(")
            .expect("valid regex")
    });
    static RE_DELETE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\.(delete|bulk_delete)\(|session\.delete\(").expect("valid regex")
    });
    static RE_SQL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(INSERT|UPDATE|DELETE)\b.*\b(INTO|SET|FROM)\b").expect("valid regex")
    });

    let mut mutations = Vec::new();
    for (i, line) in fn_text.lines().enumerate() {
        let kind = if RE_CREATE.is_match(line) {
            Some(MutationKind::Create)
        } else if RE_UPDATE.is_match(line) {
            Some(MutationKind::Update)
        } else if RE_DELETE.is_match(line) {
            Some(MutationKind::Delete)
        } else if RE_SQL.is_match(line) {
            if line.to_uppercase().contains("INSERT") {
                Some(MutationKind::Create)
            } else if line.to_uppercase().contains("UPDATE") {
                Some(MutationKind::Update)
            } else {
                Some(MutationKind::Delete)
            }
        } else {
            None
        };

        if let Some(kind) = kind {
            #[allow(clippy::cast_possible_truncation)]
            mutations.push(MutationFact {
                kind,
                target: line.trim().to_string(),
                line: start_line + i as u32,
            });
        }
    }
    mutations
}

fn extract_null_risks(fn_text: &str, start_line: u32) -> Vec<NullRiskFact> {
    // Python: bare except, string formatting in SQL
    static RE_SQL_FORMAT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?:execute|cursor\.execute|raw)\(.*(?:f"|%s|\.format\()"#)
            .expect("valid regex")
    });
    static RE_BARE_EXCEPT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*except\s*:").expect("valid regex"));

    let mut risks = Vec::new();
    for (i, line) in fn_text.lines().enumerate() {
        if RE_SQL_FORMAT.is_match(line) {
            #[allow(clippy::cast_possible_truncation)]
            risks.push(NullRiskFact {
                expression: line.trim().to_string(),
                line: start_line + i as u32,
                reason: "SQL string interpolation (injection risk)".to_string(),
            });
        }
        if RE_BARE_EXCEPT.is_match(line) {
            #[allow(clippy::cast_possible_truncation)]
            risks.push(NullRiskFact {
                expression: "bare except".to_string(),
                line: start_line + i as u32,
                reason: "bare except catches all exceptions including KeyboardInterrupt"
                    .to_string(),
            });
        }
    }
    risks
}

// ─── Warning Generation ───────────────────────────────────────

fn generate_warnings(functions: &[FunctionFact], warnings: &mut Vec<String>) {
    for f in functions {
        // Multiple mutations without transaction
        if f.state_mutations.len() >= 2 && f.transaction.is_none() {
            warnings.push(format!(
                "{}: {} mutations without transaction",
                f.name,
                f.state_mutations.len()
            ));
        }

        // External call inside transaction
        for ext in &f.external_calls {
            if ext.in_transaction {
                warnings.push(format!(
                    "{}: external call ({}) inside transaction at line {}",
                    f.name, ext.target, ext.line
                ));
            }
        }

        // Silent swallow / bare except
        for c in &f.catch_blocks {
            if c.action == CatchAction::SilentSwallow {
                warnings.push(format!("{}: silent catch at line {}", f.name, c.line));
            }
            if c.catches.contains("bare except") {
                warnings.push(format!(
                    "{}: bare except at line {} (catches KeyboardInterrupt, SystemExit)",
                    f.name, c.line
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_source() -> String {
        std::fs::read_to_string("tests/fixtures/sample_service.py")
            .expect("fixture file should exist")
    }

    #[test]
    fn extracts_functions() {
        let source = fixture_source();
        let table = extract_python_facts(Path::new("sample_service.py"), &source).unwrap();
        assert_eq!(table.language, Language::Python);
        assert!(
            table.functions.len() >= 5,
            "should find at least 5 methods, found {}",
            table.functions.len()
        );
        let names: Vec<&str> = table.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"cancel_and_refund"),
            "missing cancel_and_refund: {names:?}"
        );
        assert!(
            names.contains(&"create_online_reservation"),
            "missing create_online_reservation: {names:?}"
        );
        assert!(
            names.contains(&"dangerous_query"),
            "missing dangerous_query: {names:?}"
        );
    }

    #[test]
    fn detects_transaction() {
        let source = fixture_source();
        let table = extract_python_facts(Path::new("sample_service.py"), &source).unwrap();
        let cancel_fn = table
            .functions
            .iter()
            .find(|f| f.name == "cancel_and_refund")
            .unwrap();
        assert!(
            cancel_fn.transaction.is_some(),
            "cancel_and_refund should have a transaction"
        );
        assert!(
            cancel_fn.transaction.as_ref().unwrap().has_lock_for_update,
            "should detect select_for_update"
        );
    }

    #[test]
    fn detects_external_calls() {
        let source = fixture_source();
        let table = extract_python_facts(Path::new("sample_service.py"), &source).unwrap();
        let cancel_fn = table
            .functions
            .iter()
            .find(|f| f.name == "cancel_and_refund")
            .unwrap();
        assert!(
            !cancel_fn.external_calls.is_empty(),
            "cancel_and_refund should have external calls (requests.post)"
        );
        assert!(
            cancel_fn.external_calls[0].in_transaction,
            "requests.post is inside transaction"
        );
    }

    #[test]
    fn detects_mutations() {
        let source = fixture_source();
        let table = extract_python_facts(Path::new("sample_service.py"), &source).unwrap();
        let create_fn = table
            .functions
            .iter()
            .find(|f| f.name == "create_online_reservation")
            .unwrap();
        assert!(
            create_fn.state_mutations.len() >= 2,
            "create_online_reservation should detect 2 create mutations, found {}",
            create_fn.state_mutations.len()
        );
    }

    #[test]
    fn detects_bare_except_as_catch() {
        let source = fixture_source();
        let table = extract_python_facts(Path::new("sample_service.py"), &source).unwrap();
        let dangerous_fn = table
            .functions
            .iter()
            .find(|f| f.name == "dangerous_query")
            .unwrap();
        assert!(
            !dangerous_fn.catch_blocks.is_empty(),
            "dangerous_query should detect bare except"
        );
        assert!(
            dangerous_fn.catch_blocks[0].catches.contains("bare except"),
            "should identify as bare except"
        );
        assert_eq!(
            dangerous_fn.catch_blocks[0].action,
            CatchAction::SilentSwallow,
            "bare except + pass = SilentSwallow"
        );
    }

    #[test]
    fn detects_sql_injection_risk() {
        let source = fixture_source();
        let table = extract_python_facts(Path::new("sample_service.py"), &source).unwrap();
        let dangerous_fn = table
            .functions
            .iter()
            .find(|f| f.name == "dangerous_query")
            .unwrap();
        let has_sql_risk = dangerous_fn
            .null_risks
            .iter()
            .any(|r| r.reason.contains("SQL"));
        assert!(has_sql_risk, "should detect SQL string interpolation risk");
    }

    #[test]
    fn detects_locks() {
        let source = fixture_source();
        let table = extract_python_facts(Path::new("sample_service.py"), &source).unwrap();
        let lock_fn = table
            .functions
            .iter()
            .find(|f| f.name == "process_with_lock")
            .unwrap();
        assert!(
            !lock_fn.locks.is_empty(),
            "process_with_lock should detect Lock usage"
        );
    }

    #[test]
    fn detects_subprocess() {
        let source = fixture_source();
        let table = extract_python_facts(Path::new("sample_service.py"), &source).unwrap();
        let lock_fn = table
            .functions
            .iter()
            .find(|f| f.name == "process_with_lock")
            .unwrap();
        assert!(
            !lock_fn.external_calls.is_empty(),
            "process_with_lock should detect subprocess.run"
        );
    }

    #[test]
    fn generates_warnings() {
        let source = fixture_source();
        let table = extract_python_facts(Path::new("sample_service.py"), &source).unwrap();
        // cancel_and_refund: external call inside transaction
        let has_ext_in_tx = table.warnings.iter().any(|w| w.contains("external call"));
        // dangerous_query: silent catch + bare except
        let has_silent = table
            .warnings
            .iter()
            .any(|w| w.contains("silent") || w.contains("bare"));
        assert!(
            has_ext_in_tx || has_silent,
            "should generate warnings: {:?}",
            table.warnings
        );
    }
}
