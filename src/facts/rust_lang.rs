use std::path::Path;
use std::sync::{LazyLock, OnceLock};

use regex::Regex;
use tree_sitter::Parser;

use super::types::{
    CatchAction, CatchFact, ExternalCallFact, FactTable, FunctionFact, Language, LockFact,
    LockKind, MutationFact, MutationKind, NullRiskFact, ParamFact, TransactionFact,
};

// ─── Pre-compiled Regexes ──────────────────────────────────────

static RE_SQL_FOR_UPDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)FOR\s+UPDATE").expect("valid regex"));

static RE_SQL_INSERT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bINSERT\b").expect("valid regex"));

static RE_SQL_UPDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bUPDATE\b.*\bSET\b").expect("valid regex"));

static RE_SQL_DELETE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bDELETE\b").expect("valid regex"));

static RE_SQL_SELECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bSELECT\b").expect("valid regex"));

struct ExternalCallPattern {
    regex: Regex,
    description: &'static str,
}

fn external_call_patterns() -> &'static [ExternalCallPattern] {
    static PATTERNS: OnceLock<Vec<ExternalCallPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            ExternalCallPattern {
                regex: Regex::new(r"reqwest::|client\.(get|post|put|delete)\(")
                    .expect("valid regex"),
                description: "HTTP call",
            },
            ExternalCallPattern {
                regex: Regex::new(r"tokio::spawn\(").expect("valid regex"),
                description: "spawned task",
            },
        ]
    })
}

// ─── Public API ────────────────────────────────────────────────

/// Extract structured facts from Rust source code using tree-sitter.
pub fn extract_rust_facts(path: &Path, source: &str) -> anyhow::Result<FactTable> {
    let mut parser = Parser::new();
    let language = tree_sitter_rust::LANGUAGE.into();
    parser.set_language(&language)?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse Rust: {}", path.display()))?;

    let root = tree.root_node();
    let source_bytes = source.as_bytes();

    let mut functions = Vec::new();
    let mut warnings = Vec::new();

    collect_functions(root, source_bytes, &mut functions);
    generate_warnings(&functions, &mut warnings);
    generate_toctou_warnings(&functions, source, &mut warnings);

    Ok(FactTable {
        file: path.to_path_buf(),
        language: Language::Rust,
        functions,
        warnings,
        callers: vec![],
    })
}

// ─── AST Walking ───────────────────────────────────────────────

/// Walk the AST to find all `function_item` nodes.
fn collect_functions(node: tree_sitter::Node, source: &[u8], functions: &mut Vec<FunctionFact>) {
    if node.kind() == "function_item" {
        if let Some(fact) = extract_function_fact(node, source) {
            functions.push(fact);
        }
        return;
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
        return_paths: Vec::new(),
        silent_skips: Vec::new(),
    })
}

// ─── Fact Extractors ───────────────────────────────────────────

fn extract_return_type(func: tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Look for return_type field in the AST
    let ret_type = func.child_by_field_name("return_type")?;
    let text = ret_type.utf8_text(source).ok()?.to_string();
    // Strip leading "-> "
    let trimmed = text.strip_prefix("-> ").unwrap_or(&text).trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn extract_parameters(func: tree_sitter::Node, source: &[u8]) -> Vec<ParamFact> {
    let mut params = Vec::new();
    let Some(param_list) = func.child_by_field_name("parameters") else {
        return params;
    };

    let mut cursor = param_list.walk();
    for child in param_list.children(&mut cursor) {
        if child.kind() == "parameter" {
            let text = child.utf8_text(source).unwrap_or_default();
            // Parse `name: Type` pattern
            if let Some((name, type_hint)) = text.split_once(':') {
                let name = name.trim().to_string();
                let type_hint = type_hint.trim().to_string();
                let nullable = type_hint.starts_with("Option<");
                params.push(ParamFact {
                    name,
                    type_hint: Some(type_hint),
                    nullable,
                });
            }
        }
    }
    params
}

fn extract_transaction(fn_text: &str, base_line: u32) -> Option<TransactionFact> {
    // Look for sqlx transaction patterns: pool.begin(), .begin().await
    if !fn_text.contains(".begin()") {
        return None;
    }
    let lines: Vec<&str> = fn_text.lines().collect();
    let start = lines.iter().position(|l| l.contains(".begin()"))?;
    let has_lock = RE_SQL_FOR_UPDATE.is_match(fn_text);

    // Find commit line for range end
    let end = lines
        .iter()
        .rposition(|l| l.contains(".commit()"))
        .unwrap_or(lines.len() - 1);

    #[allow(clippy::cast_possible_truncation)]
    Some(TransactionFact {
        line_range: (base_line + start as u32, base_line + end as u32 + 1),
        has_lock_for_update: has_lock,
    })
}

fn extract_locks(fn_text: &str, base_line: u32) -> Vec<LockFact> {
    let mut locks = Vec::new();
    for (i, line) in fn_text.lines().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let line_num = base_line + i as u32;
        if RE_SQL_FOR_UPDATE.is_match(line) {
            locks.push(LockFact {
                line: line_num,
                kind: LockKind::LockForUpdate,
            });
        }
        if line.contains("RwLock::") || line.contains(".read()") || line.contains(".write()") {
            locks.push(LockFact {
                line: line_num,
                kind: LockKind::SharedLock,
            });
        }
        if line.contains("Mutex::") || line.contains(".lock()") {
            // Exclude Cache::lock (PHP pattern, not relevant in Rust)
            if !line.contains("Cache::lock") {
                locks.push(LockFact {
                    line: line_num,
                    kind: LockKind::CacheLock,
                });
            }
        }
    }
    locks
}

fn extract_catch_blocks(fn_text: &str, base_line: u32) -> Vec<CatchFact> {
    let mut catches = Vec::new();
    let lines: Vec<&str> = fn_text.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        // Detect match Err(e) => { ... } patterns
        if line.contains("Err(") && (line.contains("=>") || line.contains("Err(e)")) {
            #[allow(clippy::cast_possible_truncation)]
            let line_num = base_line + i as u32;

            // Look at the next few lines to determine action
            let block_text: String = lines[i..std::cmp::min(i + 5, lines.len())].join("\n");

            let action = if block_text.contains("return Err(") || block_text.contains("anyhow!") {
                CatchAction::Rethrow
            } else if (block_text.contains("tracing::error")
                || block_text.contains("log::error")
                || block_text.contains("eprintln"))
                && block_text.contains("return")
            {
                CatchAction::LogAndReturn
            } else if block_text.contains("tracing::") || block_text.contains("log::") {
                CatchAction::LogAndContinue
            } else if block_text.contains("return Ok(") || block_text.contains("Default::default") {
                CatchAction::ReturnDefault
            } else {
                CatchAction::SilentSwallow
            };

            catches.push(CatchFact {
                line: line_num,
                catches: "Err".to_string(),
                action,
                side_effects_before: Vec::new(),
            });
        }
    }
    catches
}

fn extract_external_calls(
    fn_text: &str,
    base_line: u32,
    transaction: Option<&TransactionFact>,
) -> Vec<ExternalCallFact> {
    let mut calls = Vec::new();

    for (i, line) in fn_text.lines().enumerate() {
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

fn extract_mutations(fn_text: &str, base_line: u32) -> Vec<MutationFact> {
    let mut mutations = Vec::new();
    let all_lines: Vec<&str> = fn_text.lines().collect();

    for (i, line) in all_lines.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let line_num = base_line + i as u32;

        // Detect SQL operations in sqlx query strings
        if line.contains("sqlx::query") || line.contains("query!") || line.contains("query_as!") {
            // Dynamically collect lines until we see .bind(, .fetch, .execute, or closing )
            let block = collect_sql_block(&all_lines, i);

            if RE_SQL_INSERT.is_match(&block) {
                mutations.push(MutationFact {
                    line: line_num,
                    kind: MutationKind::Create,
                    target: "sqlx INSERT".to_string(),
                });
            }
            if RE_SQL_UPDATE.is_match(&block) {
                mutations.push(MutationFact {
                    line: line_num,
                    kind: MutationKind::Update,
                    target: "sqlx UPDATE".to_string(),
                });
            }
            if RE_SQL_DELETE.is_match(&block) {
                mutations.push(MutationFact {
                    line: line_num,
                    kind: MutationKind::Delete,
                    target: "sqlx DELETE".to_string(),
                });
            }
        }
    }
    mutations
}

/// Collect SQL query text from the start line until a terminator (.bind, .fetch, .execute)
/// or a maximum of 20 lines. This handles multi-line SQL strings that span many lines.
fn collect_sql_block(lines: &[&str], start: usize) -> String {
    let max_end = (start + 20).min(lines.len());
    let mut parts = Vec::new();
    for (offset, &line) in lines[start..max_end].iter().enumerate() {
        parts.push(line);
        let trimmed = line.trim();
        // Stop at common sqlx chain terminators
        if offset > 0
            && (trimmed.starts_with(".bind(")
                || trimmed.starts_with(".fetch")
                || trimmed.starts_with(".execute")
                || trimmed == ")")
        {
            break;
        }
    }
    parts.join(" ")
}

fn extract_null_risks(fn_text: &str, base_line: u32) -> Vec<NullRiskFact> {
    let mut risks = Vec::new();
    for (i, line) in fn_text.lines().enumerate() {
        // .unwrap() is a null/panic risk in production
        if line.contains(".unwrap()") && !line.trim_start().starts_with("//") {
            #[allow(clippy::cast_possible_truncation)]
            risks.push(NullRiskFact {
                line: base_line + i as u32,
                expression: line.trim().to_string(),
                reason: ".unwrap() can panic at runtime".to_string(),
            });
        }
        // .expect() without context is also risky
        if line.contains(".expect(") && !line.trim_start().starts_with("//") {
            #[allow(clippy::cast_possible_truncation)]
            risks.push(NullRiskFact {
                line: base_line + i as u32,
                expression: line.trim().to_string(),
                reason: ".expect() can panic at runtime".to_string(),
            });
        }
    }
    risks
}

// ─── Warning Generation ────────────────────────────────────────

fn generate_warnings(functions: &[FunctionFact], warnings: &mut Vec<String>) {
    for f in functions {
        // Multiple SQL mutations without transaction
        if f.transaction.is_none() && f.state_mutations.len() > 1 {
            warnings.push(format!(
                "{}: {} SQL mutations without transaction",
                f.name,
                f.state_mutations.len()
            ));
        }
    }
    // TOCTOU warnings are handled by generate_toctou_warnings() with source access
}

/// Extended warning generation with access to source text.
pub(crate) fn generate_toctou_warnings(
    functions: &[FunctionFact],
    source: &str,
    warnings: &mut Vec<String>,
) {
    let lines: Vec<&str> = source.lines().collect();
    for f in functions {
        if f.transaction.is_some() || f.locks.iter().any(|l| l.kind == LockKind::LockForUpdate) {
            continue;
        }
        if f.state_mutations.is_empty() {
            continue;
        }

        // Check if the function body contains a SELECT
        let fn_start = f.line_range.0.saturating_sub(1) as usize;
        let fn_end = std::cmp::min(f.line_range.1 as usize, lines.len());
        let fn_body: String = lines[fn_start..fn_end].join("\n");

        // SQL read-modify-write pattern
        if RE_SQL_SELECT.is_match(&fn_body)
            && (RE_SQL_UPDATE.is_match(&fn_body) || RE_SQL_DELETE.is_match(&fn_body))
        {
            warnings.push(format!(
                "{}: read-modify-write without lock or transaction (TOCTOU risk)",
                f.name
            ));
        }

        // File system read-then-write pattern (read_to_string + write/fs::write)
        let has_fs_read = fn_body.contains("read_to_string")
            || fn_body.contains("fs::read")
            || fn_body.contains("File::open");
        let has_fs_write = fn_body.contains("fs::write")
            || fn_body.contains("write_all")
            || fn_body.contains("File::create");
        if has_fs_read && has_fs_write {
            warnings.push(format!(
                "{}: file read-then-write without atomic rename (TOCTOU risk)",
                f.name
            ));
        }
    }
}
