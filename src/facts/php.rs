use std::path::Path;
use std::sync::{LazyLock, OnceLock};

use regex::Regex;
use tree_sitter::Parser;

use super::types::{
    CatchAction, CatchFact, ExternalCallFact, FactTable, FunctionFact, Language, LockFact,
    LockKind, MutationFact, MutationKind, NullRiskFact, ParamFact, TransactionFact,
};

// ─── Pre-compiled Regexes ──────────────────────────────────────

static RE_RETURN_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\)\s*:\s*(\??\s*\w+)").expect("valid regex"));

static RE_TYPED_PARAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\??\w+)\s+(\$\w+)").expect("valid regex"));

static RE_BARE_PARAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\$\w+)").expect("valid regex"));

static RE_CATCH_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"catch\s*\(([^)]+)\)").expect("valid regex"));

struct ExternalCallPattern {
    regex: Regex,
    description: &'static str,
}

fn external_call_patterns() -> &'static [ExternalCallPattern] {
    static PATTERNS: OnceLock<Vec<ExternalCallPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            ExternalCallPattern {
                regex: Regex::new(r"\$this->(\w+Service)->\w+").expect("valid regex"),
                description: "service call",
            },
            ExternalCallPattern {
                regex: Regex::new(r"\w+::dispatch").expect("valid regex"),
                description: "event dispatch",
            },
            ExternalCallPattern {
                regex: Regex::new(r"event\(").expect("valid regex"),
                description: "event",
            },
            ExternalCallPattern {
                regex: Regex::new(r"Mail::").expect("valid regex"),
                description: "email",
            },
            ExternalCallPattern {
                regex: Regex::new(r"Http::\w+").expect("valid regex"),
                description: "http call",
            },
        ]
    })
}

struct MutationPattern {
    regex: Regex,
    kind: MutationKind,
}

fn mutation_patterns() -> &'static [MutationPattern] {
    static PATTERNS: OnceLock<Vec<MutationPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            MutationPattern {
                regex: Regex::new(r"(\w+)::create\(").expect("valid regex"),
                kind: MutationKind::Create,
            },
            MutationPattern {
                regex: Regex::new(r"->update\(").expect("valid regex"),
                kind: MutationKind::Update,
            },
            MutationPattern {
                regex: Regex::new(r"->delete\(").expect("valid regex"),
                kind: MutationKind::Delete,
            },
            MutationPattern {
                regex: Regex::new(r"->save\(").expect("valid regex"),
                kind: MutationKind::Save,
            },
        ]
    })
}

// ─── Public API ────────────────────────────────────────────────

/// Extract structured facts from PHP source code using tree-sitter.
pub fn extract_php_facts(path: &Path, source: &str) -> anyhow::Result<FactTable> {
    let mut parser = Parser::new();
    let language = tree_sitter_php::LANGUAGE_PHP.into();
    parser.set_language(&language)?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse PHP: {}", path.display()))?;

    let root = tree.root_node();
    let source_bytes = source.as_bytes();

    let mut functions = Vec::new();
    let mut warnings = Vec::new();

    collect_methods(root, source_bytes, &mut functions);
    generate_warnings(&functions, &mut warnings);

    Ok(FactTable {
        file: path.to_path_buf(),
        language: Language::Php,
        functions,
        warnings,
    })
}

// ─── AST Walking ───────────────────────────────────────────────

/// Walk the AST to find all `method_declaration` nodes and extract facts.
fn collect_methods(node: tree_sitter::Node, source: &[u8], functions: &mut Vec<FunctionFact>) {
    if node.kind() == "method_declaration" {
        if let Some(fact) = extract_method_fact(node, source) {
            functions.push(fact);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_methods(child, source, functions);
    }
}

fn extract_method_fact(method: tree_sitter::Node, source: &[u8]) -> Option<FunctionFact> {
    let name_node = method.child_by_field_name("name")?;
    let method_name = name_node.utf8_text(source).ok()?.to_string();

    #[allow(clippy::cast_possible_truncation)]
    let start_line = method.start_position().row as u32 + 1;
    #[allow(clippy::cast_possible_truncation)]
    let end_line = method.end_position().row as u32 + 1;
    let method_text = method.utf8_text(source).ok()?;

    let return_type = extract_return_type(method_text);
    let parameters = extract_parameters(method, source);
    let transaction = extract_transaction(method_text, start_line);
    let locks = extract_locks(method_text, start_line);
    let catch_blocks = extract_catch_blocks(method, source);
    let external_calls = extract_external_calls(method_text, start_line, transaction.as_ref());
    let state_mutations = extract_mutations(method_text, start_line);
    let null_risks = extract_null_risks(method_text, start_line);

    Some(FunctionFact {
        name: method_name,
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

fn extract_return_type(method_text: &str) -> Option<String> {
    RE_RETURN_TYPE
        .captures(method_text)
        .map(|c| c[1].trim().to_string())
}

fn extract_parameters(method: tree_sitter::Node, source: &[u8]) -> Vec<ParamFact> {
    let mut params = Vec::new();
    let Some(formal_params) = find_child_by_kind(method, "formal_parameters") else {
        return params;
    };

    let mut cursor = formal_params.walk();
    for param in formal_params.children(&mut cursor) {
        let k = param.kind();
        if k != "simple_parameter" && k != "property_promotion_parameter" {
            continue;
        }
        let text = param.utf8_text(source).unwrap_or_default();
        let nullable = text.contains('?');

        if let Some(caps) = RE_TYPED_PARAM.captures(text) {
            params.push(ParamFact {
                name: caps[2].to_string(),
                type_hint: Some(caps[1].to_string()),
                nullable,
            });
        } else if let Some(caps) = RE_BARE_PARAM.captures(text) {
            params.push(ParamFact {
                name: caps[1].to_string(),
                type_hint: None,
                nullable: false,
            });
        }
    }
    params
}

fn find_child_by_kind<'tree>(
    node: tree_sitter::Node<'tree>,
    kind: &str,
) -> Option<tree_sitter::Node<'tree>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).find(|c| c.kind() == kind)
}

fn extract_transaction(method_text: &str, base_line: u32) -> Option<TransactionFact> {
    if !method_text.contains("DB::transaction") {
        return None;
    }
    let lines: Vec<&str> = method_text.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.contains("DB::transaction"))?;
    let has_lock = method_text.contains("lockForUpdate");
    #[allow(clippy::cast_possible_truncation)]
    Some(TransactionFact {
        line_range: (base_line + start as u32, base_line + lines.len() as u32),
        has_lock_for_update: has_lock,
    })
}

fn extract_locks(method_text: &str, base_line: u32) -> Vec<LockFact> {
    let mut locks = Vec::new();
    for (i, line) in method_text.lines().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let line_num = base_line + i as u32;
        if line.contains("lockForUpdate") {
            locks.push(LockFact {
                line: line_num,
                kind: LockKind::LockForUpdate,
            });
        }
        if line.contains("Cache::lock") {
            locks.push(LockFact {
                line: line_num,
                kind: LockKind::CacheLock,
            });
        }
        if line.contains("sharedLock") {
            locks.push(LockFact {
                line: line_num,
                kind: LockKind::SharedLock,
            });
        }
    }
    locks
}

fn extract_catch_blocks(method: tree_sitter::Node, source: &[u8]) -> Vec<CatchFact> {
    let mut catches = Vec::new();
    walk_for_catch(method, source, &mut catches);
    catches
}

fn walk_for_catch(node: tree_sitter::Node, source: &[u8], catches: &mut Vec<CatchFact>) {
    if node.kind() == "catch_clause" {
        #[allow(clippy::cast_possible_truncation)]
        let line = node.start_position().row as u32 + 1;
        let text = node.utf8_text(source).unwrap_or_default();

        let catches_type = RE_CATCH_TYPE
            .captures(text)
            .map_or_else(|| "unknown".to_string(), |c| c[1].trim().to_string());

        let action = if text.contains("throw") {
            CatchAction::Rethrow
        } else if text.contains("Log::") && text.contains("return") {
            CatchAction::LogAndReturn
        } else if text.contains("Log::") {
            CatchAction::LogAndContinue
        } else if text.contains("return") {
            CatchAction::ReturnDefault
        } else {
            CatchAction::SilentSwallow
        };

        catches.push(CatchFact {
            line,
            catches: catches_type,
            action,
            side_effects_before: Vec::new(),
        });
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_for_catch(child, source, catches);
    }
}

fn extract_external_calls(
    method_text: &str,
    base_line: u32,
    transaction: Option<&TransactionFact>,
) -> Vec<ExternalCallFact> {
    let mut calls = Vec::new();

    for (i, line) in method_text.lines().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let line_num = base_line + i as u32;
        for pat in external_call_patterns() {
            if let Some(m) = pat.regex.find(line) {
                let in_tx = transaction
                    .is_some_and(|t| line_num >= t.line_range.0 && line_num <= t.line_range.1);
                calls.push(ExternalCallFact {
                    line: line_num,
                    target: m.as_str().to_string(),
                    in_transaction: in_tx,
                    description: Some(pat.description.to_string()),
                });
            }
        }
    }
    calls
}

fn extract_mutations(method_text: &str, base_line: u32) -> Vec<MutationFact> {
    let mut mutations = Vec::new();

    for (i, line) in method_text.lines().enumerate() {
        for pat in mutation_patterns() {
            if let Some(m) = pat.regex.find(line) {
                #[allow(clippy::cast_possible_truncation)]
                mutations.push(MutationFact {
                    line: base_line + i as u32,
                    kind: pat.kind.clone(),
                    target: m.as_str().trim_end_matches('(').to_string(),
                });
            }
        }
    }
    mutations
}

fn extract_null_risks(method_text: &str, base_line: u32) -> Vec<NullRiskFact> {
    let mut risks = Vec::new();
    for (i, line) in method_text.lines().enumerate() {
        let has_find = line.contains("->find(") || line.contains("::find(");
        let has_first = line.contains("->first()") || line.contains("::first()");
        if (has_find || has_first) && !line.contains("?->") && !line.contains("if (") {
            #[allow(clippy::cast_possible_truncation)]
            risks.push(NullRiskFact {
                line: base_line + i as u32,
                expression: line.trim().to_string(),
                reason: "find()/first() can return null".to_string(),
            });
        }
    }
    risks
}

// ─── Warning Generation ────────────────────────────────────────

fn generate_warnings(functions: &[FunctionFact], warnings: &mut Vec<String>) {
    for f in functions {
        if f.transaction.is_none() && f.state_mutations.len() > 1 {
            warnings.push(format!(
                "{}: {} state mutations without DB::transaction",
                f.name,
                f.state_mutations.len()
            ));
        }
        for call in &f.external_calls {
            if call.in_transaction {
                warnings.push(format!(
                    "{}: external call ({}) inside transaction at L{}",
                    f.name, call.target, call.line
                ));
            }
        }
        for catch in &f.catch_blocks {
            if matches!(
                catch.action,
                CatchAction::LogAndReturn | CatchAction::SilentSwallow
            ) && !catch.side_effects_before.is_empty()
            {
                warnings.push(format!(
                    "{}: catch at L{} swallows exception after side effects",
                    f.name, catch.line
                ));
            }
        }
        if f.transaction.is_none()
            && f.locks.is_empty()
            && !f.state_mutations.is_empty()
            && f.null_risks
                .iter()
                .any(|r| r.expression.contains("find") || r.expression.contains("first"))
        {
            warnings.push(format!(
                "{}: read-modify-write without lock (TOCTOU risk)",
                f.name
            ));
        }
    }
}
