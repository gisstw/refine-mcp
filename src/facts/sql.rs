//! `.sql` extraction via tree-sitter-sequel (§2.4).
//!
//! The goal isn't full SQL semantic analysis — just surface destructive
//! operations and schema mutations so RT-C (data integrity) can react.
//! Anything we can't classify falls through as plain warnings; the file
//! still gets a `FactTable` so downstream tools see it.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use tree_sitter::{Language, Parser, Tree};

use super::types::{ExtractMethod, FactTable};

fn sql_language() -> Language {
    static LANG: OnceLock<Language> = OnceLock::new();
    LANG.get_or_init(|| tree_sitter_sequel::LANGUAGE.into())
        .clone()
}

/// Parse a SQL file and emit warnings for destructive / risky operations.
/// The parser tolerates some syntactic variation across dialects; when it
/// errors out completely we still emit an empty table with a warning so
/// the agent learns the file was seen but couldn't be analyzed deeply.
pub fn extract_sql_facts(path: &Path, source: &str) -> Result<FactTable> {
    let mut parser = Parser::new();
    parser
        .set_language(&sql_language())
        .context("tree-sitter-sequel grammar load")?;

    let tree = parser.parse(source, None);

    let mut warnings = Vec::new();

    if let Some(tree) = tree.as_ref() {
        scan_destructive(tree, source, &mut warnings);
        scan_schema_mutation(tree, source, &mut warnings);
    } else {
        warnings.push("SQL parser returned no tree — falling back to text scan".into());
        scan_destructive_textual(source, &mut warnings);
    }

    // Cheap textual safety net even when AST parsing succeeded — covers
    // cases where the grammar version doesn't recognize the statement.
    scan_destructive_textual(source, &mut warnings);
    warnings.sort();
    warnings.dedup();

    Ok(FactTable {
        file: path.to_path_buf(),
        language: super::types::Language::default(),
        functions: vec![],
        warnings,
        callers: vec![],
        extract_method: ExtractMethod::TreeSitter,
        fingerprints: vec![],
    })
}

/// Walk the tree looking for `DROP TABLE`, `DROP COLUMN`, `TRUNCATE`,
/// `DELETE FROM` (without WHERE), `UPDATE` (without WHERE).
fn scan_destructive(tree: &Tree, source: &str, warnings: &mut Vec<String>) {
    let root = tree.root_node();
    let bytes = source.as_bytes();
    let mut cursor = root.walk();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        // tree-sitter-sequel uses lowercase node kinds like `drop_statement`,
        // `delete_statement`. Match conservatively.
        let line = u32::try_from(node.start_position().row + 1).unwrap_or(u32::MAX);
        match kind {
            "drop_statement" => {
                if let Ok(text) = node.utf8_text(bytes) {
                    let lower = text.to_lowercase();
                    if lower.contains("table") {
                        warnings.push(format!("Line {line}: DROP TABLE is destructive"));
                    } else if lower.contains("column") {
                        warnings.push(format!("Line {line}: DROP COLUMN is destructive"));
                    } else {
                        warnings.push(format!("Line {line}: DROP statement"));
                    }
                }
            }
            "truncate_statement" => {
                warnings.push(format!("Line {line}: TRUNCATE wipes table data"));
            }
            _ => {}
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Walk for ALTER TABLE add/drop column patterns to flag schema drift.
fn scan_schema_mutation(tree: &Tree, source: &str, warnings: &mut Vec<String>) {
    let root = tree.root_node();
    let bytes = source.as_bytes();
    let mut cursor = root.walk();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "alter_table_statement" {
            let line = u32::try_from(node.start_position().row + 1).unwrap_or(u32::MAX);
            if let Ok(text) = node.utf8_text(bytes) {
                let lower = text.to_lowercase();
                if lower.contains("drop column") {
                    warnings.push(format!("Line {line}: ALTER TABLE DROP COLUMN — data loss"));
                } else if lower.contains("not null") && lower.contains("add") {
                    warnings.push(format!(
                        "Line {line}: adding NOT NULL column requires backfill on existing rows"
                    ));
                }
            }
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Cheap regex-free textual scan as a safety net. Catches things the
/// grammar might tokenize differently across dialect versions.
fn scan_destructive_textual(source: &str, warnings: &mut Vec<String>) {
    for (idx, line) in source.lines().enumerate() {
        let upper = line.to_uppercase();
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if upper.contains("DROP TABLE") {
            warnings.push(format!("Line {line_no}: DROP TABLE is destructive"));
        }
        if upper.contains("DROP COLUMN") {
            warnings.push(format!(
                "Line {line_no}: ALTER TABLE DROP COLUMN — data loss"
            ));
        }
        if upper.contains("TRUNCATE") {
            warnings.push(format!("Line {line_no}: TRUNCATE wipes table data"));
        }
        // DELETE FROM without WHERE
        if upper.contains("DELETE FROM") && !upper.contains("WHERE") {
            warnings.push(format!("Line {line_no}: DELETE FROM without WHERE"));
        }
        // UPDATE ... SET ... without WHERE on same line (cheap heuristic)
        if upper.contains("UPDATE ") && upper.contains(" SET ") && !upper.contains("WHERE") {
            warnings.push(format!("Line {line_no}: UPDATE without WHERE"));
        }
        // ALTER TABLE adding NOT NULL — common migration pitfall
        if upper.contains("ALTER TABLE") && upper.contains("ADD") && upper.contains("NOT NULL") {
            warnings.push(format!(
                "Line {line_no}: adding NOT NULL column requires backfill on existing rows"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn drop_table_is_flagged() {
        let src = "DROP TABLE users;\n";
        let table = extract_sql_facts(&PathBuf::from("m.sql"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("DROP TABLE")),
            "expected DROP TABLE warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn truncate_is_flagged() {
        let src = "TRUNCATE TABLE logs;\n";
        let table = extract_sql_facts(&PathBuf::from("m.sql"), src).unwrap();
        assert!(table.warnings.iter().any(|w| w.contains("TRUNCATE")));
    }

    #[test]
    fn delete_without_where_is_flagged() {
        let src = "DELETE FROM users;\n";
        let table = extract_sql_facts(&PathBuf::from("m.sql"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("DELETE")),
            "expected DELETE warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn delete_with_where_is_not_flagged() {
        let src = "DELETE FROM users WHERE id = 1;\n";
        let table = extract_sql_facts(&PathBuf::from("m.sql"), src).unwrap();
        assert!(
            !table.warnings.iter().any(|w| w.contains("DELETE")),
            "DELETE with WHERE should not warn, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn alter_table_drop_column_is_flagged() {
        let src = "ALTER TABLE users DROP COLUMN email;\n";
        let table = extract_sql_facts(&PathBuf::from("m.sql"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| {
                let lower = w.to_lowercase();
                lower.contains("drop column") || lower.contains("data loss")
            }),
            "expected DROP COLUMN warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn empty_input_is_safe() {
        let table = extract_sql_facts(&PathBuf::from("m.sql"), "").unwrap();
        assert_eq!(table.extract_method, ExtractMethod::TreeSitter);
        assert!(table.warnings.is_empty());
    }
}
