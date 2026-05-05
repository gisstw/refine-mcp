//! AST-derived fingerprints for cross-run finding tracking (§2.1).
//!
//! Each addressable unit (function/method) produces a `FingerprintEntry`
//! whose `content_hash` is stable across whitespace shifts but breaks on
//! semantic edits. Subsequent runs compare hashes to auto-mark resolved
//! findings as `Fixed` without operator intervention.
//!
//! The hash mixes in the file path so that small or near-identical bodies
//! across different files do not collide (Tier 2 review §0.5 / RT-A2).

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::facts::types::{FactTable, FingerprintEntry};

/// How many surrounding lines to include around a function body when
/// computing its content hash. Some context tolerates trivial inserts
/// (a blank line, a doc comment) above the function while still detecting
/// real edits inside or immediately around it.
const CONTEXT_LINES: usize = 3;

/// Compute fingerprints for every function in `table`. `source` must be the
/// original file content the table was extracted from (unmodified — line
/// numbers in `FunctionFact::line_range` index into it).
#[must_use]
pub fn compute_for_table(table: &FactTable, source: &str) -> Vec<FingerprintEntry> {
    let lines: Vec<&str> = source.lines().collect();
    table
        .functions
        .iter()
        .map(|f| {
            let body = extract_body(&lines, f.line_range);
            // Until FunctionFact carries class/module qualification, the bare
            // name is fine — the file path and line_range mixed into the hash
            // give cross-file and same-file disambiguation respectively.
            let symbol_path = f.name.clone();
            let content_hash = compute_hash(&table.file, &symbol_path, f.line_range, &body);
            FingerprintEntry {
                line_range: f.line_range,
                symbol_path,
                content_hash,
            }
        })
        .collect()
}

/// Extract the function body plus `CONTEXT_LINES` of surrounding context,
/// then normalize to make the hash robust against incidental whitespace.
fn extract_body(lines: &[&str], range: (u32, u32)) -> String {
    if lines.is_empty() {
        return String::new();
    }
    // FunctionFact line_range is 1-indexed. Saturating math protects
    // synthetic entries with line 0.
    let start_one = range.0 as usize;
    let end_one = range.1 as usize;
    let start = start_one.saturating_sub(1).saturating_sub(CONTEXT_LINES);
    let end = end_one.saturating_add(CONTEXT_LINES).min(lines.len());
    if start >= end {
        return String::new();
    }
    normalize(&lines[start..end].join("\n"))
}

/// Normalize source for hashing: tabs → 4 spaces, drop trailing whitespace,
/// drop empty lines. The goal is to make the hash invariant under
/// re-indentation and blank-line shifts but sensitive to identifier or
/// statement changes.
fn normalize(src: &str) -> String {
    src.lines()
        .map(|l| l.replace('\t', "    ").trim_end().to_owned())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// SHA-256 of `file || \0 || symbol_path || \0 || start:end || \0 ||
/// normalized_body`. The line range is mixed in so that two same-named
/// functions in the same file (or any other case where the surrounding
/// context window overlaps and produces the same body) still hash distinctly.
/// Returns a lowercase hex string.
#[must_use]
pub fn compute_hash(
    file: &Path,
    symbol_path: &str,
    line_range: (u32, u32),
    normalized_body: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(file.to_string_lossy().as_bytes());
    h.update(b"\0");
    h.update(symbol_path.as_bytes());
    h.update(b"\0");
    h.update(line_range.0.to_le_bytes());
    h.update(b":");
    h.update(line_range.1.to_le_bytes());
    h.update(b"\0");
    h.update(normalized_body.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::types::{ExtractMethod, FactTable, FunctionFact, Language};
    use std::path::PathBuf;

    fn make_table(file: &str, fns: Vec<(&str, (u32, u32))>) -> FactTable {
        FactTable {
            file: PathBuf::from(file),
            language: Language::Rust,
            functions: fns
                .into_iter()
                .map(|(name, range)| FunctionFact {
                    name: name.to_string(),
                    line_range: range,
                    return_type: None,
                    parameters: vec![],
                    transaction: None,
                    locks: vec![],
                    catch_blocks: vec![],
                    external_calls: vec![],
                    state_mutations: vec![],
                    null_risks: vec![],
                    return_paths: vec![],
                    silent_skips: vec![],
                })
                .collect(),
            warnings: vec![],
            callers: vec![],
            extract_method: ExtractMethod::default(),
            fingerprints: vec![],
        }
    }

    #[test]
    fn whitespace_only_changes_do_not_change_hash() {
        let src1 = "fn foo() {\n    let x = 1;\n    x\n}\n";
        let src2 = "fn foo() {\n\tlet x = 1;\n\tx   \n}\n"; // tabs + trailing spaces
        let table = make_table("a.rs", vec![("foo", (1, 4))]);
        let fp1 = compute_for_table(&table, src1);
        let fp2 = compute_for_table(&table, src2);
        assert_eq!(fp1[0].content_hash, fp2[0].content_hash);
    }

    #[test]
    fn semantic_edits_change_hash() {
        let src1 = "fn foo() {\n    let x = 1;\n    x\n}\n";
        let src2 = "fn foo() {\n    let x = 2;\n    x\n}\n"; // 1 → 2
        let table = make_table("a.rs", vec![("foo", (1, 4))]);
        let fp1 = compute_for_table(&table, src1);
        let fp2 = compute_for_table(&table, src2);
        assert_ne!(fp1[0].content_hash, fp2[0].content_hash);
    }

    #[test]
    fn same_body_in_different_files_hashes_differently() {
        let src = "fn foo() {\n    let x = 1;\n    x\n}\n";
        let t1 = make_table("a.rs", vec![("foo", (1, 4))]);
        let t2 = make_table("b.rs", vec![("foo", (1, 4))]);
        let h1 = &compute_for_table(&t1, src)[0].content_hash;
        let h2 = &compute_for_table(&t2, src)[0].content_hash;
        assert_ne!(h1, h2, "file path must be part of the hash input");
    }

    #[test]
    fn same_function_name_different_lines_produces_distinct_entries() {
        let src = "fn foo() { 1 }\nfn foo() { 2 }\n";
        let table = make_table("a.rs", vec![("foo", (1, 1)), ("foo", (2, 2))]);
        let fps = compute_for_table(&table, src);
        assert_eq!(fps.len(), 2);
        assert_ne!(fps[0].content_hash, fps[1].content_hash);
    }

    #[test]
    fn empty_table_produces_no_entries() {
        let src = "fn foo() {}\n";
        let table = make_table("a.rs", vec![]);
        assert!(compute_for_table(&table, src).is_empty());
    }

    #[test]
    fn out_of_range_line_does_not_panic() {
        let src = "fn foo() {}\n";
        // line_range pointing past EOF — should produce stable (empty) body
        let table = make_table("a.rs", vec![("foo", (50, 100))]);
        let fps = compute_for_table(&table, src);
        assert_eq!(fps.len(), 1);
    }
}
