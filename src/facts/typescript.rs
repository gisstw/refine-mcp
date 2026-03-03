use std::path::Path;
use std::sync::{LazyLock, OnceLock};

use regex::Regex;
use tree_sitter::Parser;

use super::types::{
    CatchAction, CatchFact, ExternalCallFact, FactTable, FunctionFact, Language, LockFact,
    LockKind, MutationFact, MutationKind, NullRiskFact, ParamFact, TransactionFact,
};

// ─── Pre-compiled Regexes ──────────────────────────────────────

static RE_AWAIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bawait\b").expect("valid regex"));

#[allow(dead_code)] // reserved for future Promise chain detection
static RE_PROMISE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.then\(|Promise\.(all|race|any|allSettled)\(").expect("valid regex")
});

struct ExternalCallPattern {
    regex: Regex,
    description: &'static str,
}

fn external_call_patterns() -> &'static [ExternalCallPattern] {
    static PATTERNS: OnceLock<Vec<ExternalCallPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            ExternalCallPattern {
                regex: Regex::new(r"\bfetch\(").expect("valid regex"),
                description: "fetch() API call",
            },
            ExternalCallPattern {
                regex: Regex::new(r"axios\.(get|post|put|delete|patch)\(").expect("valid regex"),
                description: "axios HTTP call",
            },
            ExternalCallPattern {
                regex: Regex::new(r"\.(get|post|put|delete|patch)\(.*https?://")
                    .expect("valid regex"),
                description: "HTTP call",
            },
        ]
    })
}

// ─── Public API ────────────────────────────────────────────────

/// Extract structured facts from TypeScript/JavaScript source code using tree-sitter.
pub fn extract_ts_facts(path: &Path, source: &str) -> anyhow::Result<FactTable> {
    let mut parser = Parser::new();

    // Choose TSX or regular TS based on extension
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("ts");
    let language = match ext {
        "tsx" | "jsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        _ => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    parser.set_language(&language)?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse TypeScript: {}", path.display()))?;

    let root = tree.root_node();
    let source_bytes = source.as_bytes();

    let mut functions = Vec::new();
    let mut warnings = Vec::new();

    collect_functions(root, source_bytes, &mut functions);
    generate_warnings(&functions, &mut warnings);

    Ok(FactTable {
        file: path.to_path_buf(),
        language: Language::TypeScript,
        functions,
        warnings,
    })
}

// ─── AST Walking ───────────────────────────────────────────────

/// Walk the AST to find function-like nodes.
fn collect_functions(node: tree_sitter::Node, source: &[u8], functions: &mut Vec<FunctionFact>) {
    match node.kind() {
        // Named functions: function foo() {}
        "function_declaration" | "method_definition" | "function" => {
            if let Some(fact) = extract_function_fact(node, source) {
                functions.push(fact);
            }
            return;
        }
        // Arrow functions assigned to variables: const foo = () => {}
        "lexical_declaration" | "variable_declaration" => {
            if let Some(fact) = extract_arrow_function(node, source) {
                functions.push(fact);
                return;
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_functions(child, source, functions);
    }
}

fn extract_function_fact(func: tree_sitter::Node, source: &[u8]) -> Option<FunctionFact> {
    let name = func
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(source).ok())
        .unwrap_or("<anonymous>")
        .to_string();

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
        name,
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

/// Extract arrow functions assigned to const/let/var.
fn extract_arrow_function(decl: tree_sitter::Node, source: &[u8]) -> Option<FunctionFact> {
    // Walk the variable_declarator children
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        if child.kind() == "variable_declarator" {
            let name_node = child.child_by_field_name("name")?;
            let value_node = child.child_by_field_name("value")?;
            if value_node.kind() == "arrow_function" {
                let name = name_node.utf8_text(source).ok()?.to_string();

                #[allow(clippy::cast_possible_truncation)]
                let start_line = value_node.start_position().row as u32 + 1;
                #[allow(clippy::cast_possible_truncation)]
                let end_line = value_node.end_position().row as u32 + 1;
                let fn_text = value_node.utf8_text(source).ok()?;

                let return_type = extract_return_type(value_node, source);
                let parameters = extract_parameters(value_node, source);
                let transaction = extract_transaction(fn_text, start_line);
                let locks = extract_locks(fn_text, start_line);
                let catch_blocks = extract_catch_blocks(fn_text, start_line);
                let external_calls =
                    extract_external_calls(fn_text, start_line, transaction.as_ref());
                let state_mutations = extract_mutations(fn_text, start_line);
                let null_risks = extract_null_risks(fn_text, start_line);

                return Some(FunctionFact {
                    name,
                    line_range: (start_line, end_line),
                    return_type,
                    parameters,
                    transaction,
                    locks,
                    catch_blocks,
                    external_calls,
                    state_mutations,
                    null_risks,
                });
            }
        }
    }
    None
}

// ─── Fact Extractors ───────────────────────────────────────────

fn extract_return_type(func: tree_sitter::Node, source: &[u8]) -> Option<String> {
    // TS: function foo(): string {} → return_type field is type_annotation
    let ret = func.child_by_field_name("return_type")?;
    let text = ret.utf8_text(source).ok()?.trim().to_string();
    // Strip leading `: `
    Some(text.strip_prefix(": ").unwrap_or(&text).to_string())
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
            "required_parameter" | "optional_parameter" => {
                let name = child
                    .child_by_field_name("pattern")
                    .or_else(|| child.child_by_field_name("name"))
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("?")
                    .to_string();

                let type_text = child
                    .child_by_field_name("type")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(|t| t.strip_prefix(": ").unwrap_or(t).to_string());

                let nullable = type_text
                    .as_deref()
                    .is_some_and(|t| t.contains("null") || t.contains("undefined"))
                    || child.kind() == "optional_parameter";

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
        Regex::new(r"\.\$?transaction\(|\bstartTransaction\(|\bknex\.transaction\(")
            .expect("valid regex")
    });

    if RE_TX.is_match(fn_text) {
        let lines: Vec<&str> = fn_text.lines().collect();
        let start = lines.iter().position(|l| RE_TX.is_match(l)).unwrap_or(0);
        #[allow(clippy::cast_possible_truncation)]
        Some(TransactionFact {
            line_range: (start_line + start as u32, start_line + lines.len() as u32),
            has_lock_for_update: fn_text.contains("FOR UPDATE"),
        })
    } else {
        None
    }
}

fn extract_locks(fn_text: &str, start_line: u32) -> Vec<LockFact> {
    static RE_LOCK: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(mutex|lock|semaphore|acquire)\b").expect("valid regex")
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
        if line.contains("catch") && (line.contains('(') || line.contains('{')) {
            // Look at what happens in the catch block (next 5 lines)
            let block_end = (i + 5).min(lines.len());
            let block_text: String = lines[i..block_end].join("\n");

            let action = if block_text.contains("throw") {
                CatchAction::Rethrow
            } else if block_text.contains("console.log")
                || block_text.contains("console.error")
                || block_text.contains("logger")
            {
                CatchAction::LogAndContinue
            } else if block_text.contains("return") {
                CatchAction::ReturnDefault
            } else {
                CatchAction::SilentSwallow
            };

            #[allow(clippy::cast_possible_truncation)]
            catches.push(CatchFact {
                catches: "Error".to_string(),
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
                    target: line.trim().to_string(),
                    line: start_line + i as u32,
                    in_transaction: transaction.is_some(),
                    description: Some(pattern.description.to_string()),
                });
                break;
            }
        }

        // Also catch await with fetch-like patterns
        #[allow(clippy::cast_possible_truncation)]
        let line_num = start_line + i as u32;
        if RE_AWAIT.is_match(line)
            && (line.contains("fetch") || line.contains("axios") || line.contains("http"))
            && !calls.iter().any(|c| c.line == line_num)
        {
            calls.push(ExternalCallFact {
                target: line.trim().to_string(),
                line: line_num,
                in_transaction: transaction.is_some(),
                description: Some("async external call".to_string()),
            });
        }
    }
    calls
}

fn extract_mutations(fn_text: &str, start_line: u32) -> Vec<MutationFact> {
    static RE_CREATE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\.(create|insert|insertMany|insertOne|save)\(").expect("valid regex")
    });
    static RE_UPDATE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\.(update|updateMany|updateOne|findAndUpdate|upsert|set)\(")
            .expect("valid regex")
    });
    static RE_DELETE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\.(delete|deleteMany|deleteOne|remove|destroy)\(").expect("valid regex")
    });

    let mut mutations = Vec::new();
    for (i, line) in fn_text.lines().enumerate() {
        let kind = if RE_CREATE.is_match(line) {
            Some(MutationKind::Create)
        } else if RE_UPDATE.is_match(line) {
            Some(MutationKind::Update)
        } else if RE_DELETE.is_match(line) {
            Some(MutationKind::Delete)
        } else {
            None
        };

        if let Some(kind) = kind {
            let target = line.trim().to_string();
            #[allow(clippy::cast_possible_truncation)]
            mutations.push(MutationFact {
                kind,
                target,
                line: start_line + i as u32,
            });
        }
    }
    mutations
}

fn extract_null_risks(fn_text: &str, start_line: u32) -> Vec<NullRiskFact> {
    static RE_NON_NULL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(\w+)!\.").expect("valid regex") // non-null assertion: foo!.bar
    });
    static RE_AS_ANY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\bas\s+any\b").expect("valid regex") // as any cast
    });

    let mut risks = Vec::new();
    for (i, line) in fn_text.lines().enumerate() {
        if let Some(caps) = RE_NON_NULL.captures(line) {
            #[allow(clippy::cast_possible_truncation)]
            risks.push(NullRiskFact {
                expression: caps[1].to_string(),
                line: start_line + i as u32,
                reason: "non-null assertion operator (!)".to_string(),
            });
        }
        if RE_AS_ANY.is_match(line) {
            #[allow(clippy::cast_possible_truncation)]
            risks.push(NullRiskFact {
                expression: line.trim().to_string(),
                line: start_line + i as u32,
                reason: "'as any' bypasses type checking".to_string(),
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

        // Silent swallow catch
        for c in &f.catch_blocks {
            if c.action == CatchAction::SilentSwallow {
                warnings.push(format!(
                    "{}: silent catch (swallows error) at line {}",
                    f.name, c.line
                ));
            }
        }

        // Unhandled Promise (no await + no .then + no .catch)
        // This is detected at a higher level; skip for now
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_source() -> String {
        std::fs::read_to_string("tests/fixtures/sample_service.ts")
            .expect("fixture file should exist")
    }

    #[test]
    fn extracts_functions() {
        let source = fixture_source();
        let table = extract_ts_facts(Path::new("sample_service.ts"), &source).unwrap();
        assert_eq!(table.language, Language::TypeScript);
        assert!(
            table.functions.len() >= 3,
            "should find at least 3 functions, found {}",
            table.functions.len()
        );
        let names: Vec<&str> = table.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"cancelAndRefund"),
            "missing cancelAndRefund: {names:?}"
        );
        assert!(
            names.contains(&"modifyReservation"),
            "missing modifyReservation: {names:?}"
        );
        assert!(
            names.contains(&"processPayment"),
            "missing processPayment: {names:?}"
        );
    }

    #[test]
    fn detects_transaction() {
        let source = fixture_source();
        let table = extract_ts_facts(Path::new("sample_service.ts"), &source).unwrap();
        let cancel_fn = table
            .functions
            .iter()
            .find(|f| f.name == "cancelAndRefund")
            .unwrap();
        assert!(
            cancel_fn.transaction.is_some(),
            "cancelAndRefund should have a transaction"
        );
    }

    #[test]
    fn detects_external_calls() {
        let source = fixture_source();
        let table = extract_ts_facts(Path::new("sample_service.ts"), &source).unwrap();
        let cancel_fn = table
            .functions
            .iter()
            .find(|f| f.name == "cancelAndRefund")
            .unwrap();
        assert!(
            !cancel_fn.external_calls.is_empty(),
            "cancelAndRefund should have external calls (fetch)"
        );
        assert!(
            cancel_fn.external_calls[0].in_transaction,
            "fetch is inside transaction"
        );
    }

    #[test]
    fn detects_mutations() {
        let source = fixture_source();
        let table = extract_ts_facts(Path::new("sample_service.ts"), &source).unwrap();
        let modify_fn = table
            .functions
            .iter()
            .find(|f| f.name == "modifyReservation")
            .unwrap();
        assert!(
            !modify_fn.state_mutations.is_empty(),
            "modifyReservation should detect update mutation"
        );
    }

    #[test]
    fn detects_null_risks() {
        let source = fixture_source();
        let table = extract_ts_facts(Path::new("sample_service.ts"), &source).unwrap();
        // cancelAndRefund uses reservation!.paymentId (non-null assertion)
        let cancel_fn = table
            .functions
            .iter()
            .find(|f| f.name == "cancelAndRefund")
            .unwrap();
        assert!(
            !cancel_fn.null_risks.is_empty(),
            "should detect non-null assertion (!)"
        );
        // processPayment uses `as any`
        let process_fn = table
            .functions
            .iter()
            .find(|f| f.name == "processPayment")
            .unwrap();
        let has_as_any = process_fn
            .null_risks
            .iter()
            .any(|r| r.reason.contains("as any"));
        assert!(has_as_any, "should detect 'as any' cast");
    }

    #[test]
    fn detects_catch_blocks() {
        let source = fixture_source();
        let table = extract_ts_facts(Path::new("sample_service.ts"), &source).unwrap();
        let cancel_fn = table
            .functions
            .iter()
            .find(|f| f.name == "cancelAndRefund")
            .unwrap();
        assert_eq!(cancel_fn.catch_blocks.len(), 1);
        assert_eq!(
            cancel_fn.catch_blocks[0].action,
            CatchAction::LogAndContinue
        );
    }

    #[test]
    fn generates_warnings() {
        let source = fixture_source();
        let table = extract_ts_facts(Path::new("sample_service.ts"), &source).unwrap();
        // modifyReservation: 2 mutations without transaction
        let has_mutation_warning = table.warnings.iter().any(|w| w.contains("mutation"));
        // cancelAndRefund: external call inside transaction
        let has_ext_in_tx = table.warnings.iter().any(|w| w.contains("external call"));
        assert!(
            has_mutation_warning || has_ext_in_tx,
            "should generate at least one warning: {:?}",
            table.warnings
        );
    }

    #[test]
    fn detects_parameters() {
        let source = fixture_source();
        let table = extract_ts_facts(Path::new("sample_service.ts"), &source).unwrap();
        let process_fn = table
            .functions
            .iter()
            .find(|f| f.name == "processPayment")
            .unwrap();
        assert!(
            process_fn.parameters.len() >= 2,
            "should have amount and token params"
        );
        let token_param = process_fn.parameters.iter().find(|p| p.name == "token");
        assert!(token_param.is_some(), "should find token param");
        if let Some(t) = token_param {
            assert!(t.nullable, "token? should be nullable (optional param)");
        }
    }
}
