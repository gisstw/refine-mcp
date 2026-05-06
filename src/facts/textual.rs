//! Heuristic, parser-free fact extraction for file types we don't have a
//! tree-sitter grammar for (§2.5 textual fallback).
//!
//! The output is intentionally low-signal — just enough so that a downstream
//! red team gets *something* about the file rather than nothing, paired with
//! `ExtractMethod::Textual` so it knows to be cautious. Findings the red
//! team raises against textual files should be treated as suggestions, not
//! hard signals; a future P2 commit will cap their severity at `High`.

use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;
use regex::Regex;

use super::types::{ExtractMethod, FactTable, Language};

/// Hard cap on lines we scan per file. Anything past this is summarized in
/// a warning so very large files don't slow us down or balloon output.
const MAX_LINES_SCANNED: usize = 5_000;

/// Cap on warning entries we emit per file so a TODO-laden test fixture
/// doesn't drown the report.
const MAX_WARNINGS_PER_FILE: usize = 30;

static TODO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(TODO|FIXME|HACK|XXX)\b").unwrap());

static SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Keep this conservative — false positives drown out real signals.
    // Match `<key>=<value>` style assignments where the key looks
    // sensitive and the value is at least 12 chars of non-whitespace.
    Regex::new(r#"(?i)(?:api[_-]?key|secret|password|token|bearer)[\s:=]+["']?([A-Za-z0-9+/=_\-]{12,})"#)
        .unwrap()
});

/// Run a heuristic textual scan and return a `FactTable` tagged with
/// `ExtractMethod::Textual`. Always succeeds — fallback by definition
/// cannot fail in a way that should propagate.
pub fn extract_textual_facts(path: &Path, source: &str) -> Result<FactTable> {
    let mut warnings: Vec<String> = Vec::new();

    let total_lines = source.lines().count();
    if total_lines > MAX_LINES_SCANNED {
        warnings.push(format!(
            "Large file ({total_lines} lines), heuristic scan capped at {MAX_LINES_SCANNED}"
        ));
    }

    for (idx, line) in source.lines().take(MAX_LINES_SCANNED).enumerate() {
        if warnings.len() >= MAX_WARNINGS_PER_FILE {
            warnings.push(format!(
                "Reached {MAX_WARNINGS_PER_FILE} warnings, suppressing further heuristic hits"
            ));
            break;
        }
        let line_no = idx + 1;
        if TODO_RE.is_match(line) {
            warnings.push(format!("Line {line_no}: TODO/FIXME/HACK marker"));
        }
        if SECRET_RE.is_match(line) {
            warnings.push(format!(
                "Line {line_no}: looks like a hardcoded secret (api_key/password/token)"
            ));
        }
    }

    Ok(FactTable {
        file: path.to_path_buf(),
        // The Language enum doesn't yet have an "Other" variant; PHP is
        // the historical default. The extract_method tag is what red
        // teams actually key off of.
        language: Language::default(),
        functions: vec![],
        warnings,
        callers: vec![],
        extract_method: ExtractMethod::Textual,
        fingerprints: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn textual_marks_extract_method() {
        let table =
            extract_textual_facts(&PathBuf::from("a.lua"), "print('hi')\n").unwrap();
        assert_eq!(table.extract_method, ExtractMethod::Textual);
        assert!(table.functions.is_empty());
    }

    #[test]
    fn textual_flags_todo_markers() {
        let src = "function init()\n  -- TODO: handle null\n  return 1\nend\n";
        let table = extract_textual_facts(&PathBuf::from("a.lua"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("TODO")),
            "expected TODO warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn textual_flags_obvious_secrets() {
        let src = "API_KEY = \"sk-AbCd0123456789EfGh\"\n";
        let table = extract_textual_facts(&PathBuf::from("config.lua"), src).unwrap();
        assert!(
            table.warnings.iter().any(|w| w.contains("secret")),
            "expected secret warning, got: {:?}",
            table.warnings
        );
    }

    #[test]
    fn textual_caps_warnings_per_file() {
        // Generate >MAX_WARNINGS_PER_FILE TODO lines and verify cap.
        use std::fmt::Write;
        let mut src = String::new();
        for i in 0..(MAX_WARNINGS_PER_FILE + 5) {
            writeln!(src, "// TODO line {i}").unwrap();
        }
        let table = extract_textual_facts(&PathBuf::from("a.lua"), &src).unwrap();
        // +1 for the "Reached N warnings, suppressing..." entry
        assert!(
            table.warnings.len() <= MAX_WARNINGS_PER_FILE + 1,
            "warnings should be capped, got {}",
            table.warnings.len()
        );
        assert!(
            table.warnings.iter().any(|w| w.contains("suppressing")),
            "expected suppression notice"
        );
    }

    #[test]
    fn textual_does_not_panic_on_empty_input() {
        let table = extract_textual_facts(&PathBuf::from("empty"), "").unwrap();
        assert_eq!(table.extract_method, ExtractMethod::Textual);
        assert!(table.warnings.is_empty());
    }
}
