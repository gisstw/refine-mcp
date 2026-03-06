use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::types::CallerFact;

// ─── Pre-compiled Regexes ──────────────────────────────────────

/// Matches grep output lines: `file:line:context`
static RE_GREP_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^:]+):(\d+):(.+)$").expect("valid regex"));

/// Matches PHP/Rust/Python function definitions
static RE_FUNC_DEF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(public|protected|private|static|abstract|final|async|pub|fn|def)\s+")
        .expect("valid regex")
});

/// Matches comment lines
static RE_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?://|/?\*|#)").expect("valid regex"));

/// Matches `use` statements
static RE_USE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*use\s+").expect("valid regex"));

/// Matches unified diff file header `+++ b/filepath`
static RE_DIFF_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\+\+\+ b/(.+)$").expect("valid regex"));

/// Matches unified diff hunk header `@@ -old,count +new,count @@`
static RE_DIFF_HUNK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@").expect("valid regex"));

// ─── Types ─────────────────────────────────────────────────────

/// Result of expanding the blast radius for a set of symbols.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlastRadiusResult {
    /// Map from symbol name to its callers.
    pub call_graph: HashMap<String, Vec<CallerFact>>,
    /// Unique files that contain callers (deduplicated).
    pub expanded_files: Vec<String>,
    /// Total number of callers found across all symbols.
    pub total_callers: usize,
}

/// A hunk from a unified diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffHunk {
    pub new_start: u32,
    pub new_count: u32,
}

// ─── Public API ────────────────────────────────────────────────

/// Searches for callers of each symbol via `grep -rnw` and returns the
/// aggregated blast radius.
pub fn expand_blast_radius(
    symbols: &[String],
    search_paths: &[PathBuf],
    exclude_files: &[PathBuf],
    max_per_symbol: usize,
) -> BlastRadiusResult {
    let mut result = BlastRadiusResult::default();
    let mut file_set: HashSet<String> = HashSet::new();

    for symbol in symbols {
        let callers = grep_symbol(symbol, search_paths, exclude_files, max_per_symbol);
        for c in &callers {
            file_set.insert(c.caller_file.to_string_lossy().to_string());
        }
        result.total_callers += callers.len();
        result.call_graph.insert(symbol.clone(), callers);
    }

    result.expanded_files = file_set.into_iter().collect();
    result.expanded_files.sort();
    result
}

/// Extracts function/method names whose signatures changed according to
/// `git diff HEAD --unified=0`. Falls back to extracting all non-private
/// function names from the plan files if git diff is unavailable.
pub fn extract_changed_symbols(plan_files: &[PathBuf]) -> Vec<String> {
    let diff_output = Command::new("git")
        .args(["diff", "HEAD", "--unified=0"])
        .output();

    match diff_output {
        Ok(output) if output.status.success() || output.status.code() == Some(1) => {
            let diff = String::from_utf8_lossy(&output.stdout);
            if diff.is_empty() {
                return fallback_extract_symbols(plan_files);
            }
            let hunks = parse_diff_hunks(&diff);
            let mut symbols = Vec::new();

            for plan_file in plan_files {
                let file_str = plan_file.to_string_lossy();
                // Find matching hunks for this file
                let file_hunks: Vec<&DiffHunk> = hunks
                    .iter()
                    .filter(|(path, _)| file_str.ends_with(*path))
                    .flat_map(|(_, h)| h)
                    .collect();

                if file_hunks.is_empty() {
                    continue;
                }

                // Parse the file with tree-sitter to find method declarations
                let source = match std::fs::read_to_string(plan_file) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                let mut parser = tree_sitter::Parser::new();
                let lang: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
                if parser.set_language(&lang).is_err() {
                    continue;
                }

                let tree = match parser.parse(&source, None) {
                    Some(t) => t,
                    None => continue,
                };

                find_changed_methods(&tree, source.as_bytes(), &file_hunks, &mut symbols);
            }

            symbols.sort();
            symbols.dedup();
            symbols
        }
        _ => fallback_extract_symbols(plan_files),
    }
}

/// Parses `grep -rnw` output into `CallerFact` entries.
///
/// Public for testing.
pub fn parse_grep_output(
    output: &str,
    symbol: &str,
    exclude_files: &[PathBuf],
    max_results: usize,
) -> Vec<CallerFact> {
    let exclude_set: HashSet<String> = exclude_files
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let mut results = Vec::new();

    for line in output.lines() {
        if results.len() >= max_results {
            break;
        }

        let Some(caps) = RE_GREP_LINE.captures(line) else {
            continue;
        };

        let file = &caps[1];
        let line_no_str = &caps[2];
        let context = caps[3].trim();

        // Skip excluded files (compare by path suffix)
        if exclude_set.iter().any(|ex| file.ends_with(ex.as_str()) || ex.ends_with(file)) {
            continue;
        }

        // Skip comment lines
        if RE_COMMENT.is_match(context) {
            continue;
        }

        // Skip `use` statements
        if RE_USE.is_match(context) {
            continue;
        }

        // Skip function definitions that contain the symbol
        if RE_FUNC_DEF.is_match(context) && context.contains(symbol) {
            // This is likely the definition itself, not a caller
            if is_function_definition(context, symbol) {
                continue;
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        let line_no = line_no_str.parse::<u32>().unwrap_or(0);

        results.push(CallerFact {
            symbol: symbol.to_string(),
            caller_file: PathBuf::from(file),
            caller_line: line_no,
            context: context.to_string(),
        });
    }

    results
}

/// Parses unified diff output into a map of file path to diff hunks.
///
/// Public for testing.
pub fn parse_diff_hunks(diff: &str) -> HashMap<&str, Vec<DiffHunk>> {
    let mut result: HashMap<&str, Vec<DiffHunk>> = HashMap::new();
    let mut current_file: Option<&str> = None;

    for line in diff.lines() {
        if let Some(caps) = RE_DIFF_FILE.captures(line) {
            let m = caps.get(1).expect("group 1");
            // Slice from the original line using byte offsets to preserve lifetime
            current_file = Some(&line[m.start()..m.end()]);
        } else if let Some(caps) = RE_DIFF_HUNK.captures(line) {
            if let Some(file) = current_file {
                #[allow(clippy::cast_possible_truncation)]
                let new_start = caps[1].parse::<u32>().unwrap_or(0);
                #[allow(clippy::cast_possible_truncation)]
                let new_count = caps
                    .get(2)
                    .map_or(1, |m| m.as_str().parse::<u32>().unwrap_or(1));

                result
                    .entry(file)
                    .or_default()
                    .push(DiffHunk { new_start, new_count });
            }
        }
    }

    result
}

// ─── Private Helpers ───────────────────────────────────────────

/// Runs `grep -rnw` for a single symbol across search paths.
fn grep_symbol(
    symbol: &str,
    search_paths: &[PathBuf],
    exclude_files: &[PathBuf],
    max_results: usize,
) -> Vec<CallerFact> {
    let mut all_output = String::new();

    for search_path in search_paths {
        let output = Command::new("grep")
            .args([
                "-rnw",
                "--include=*.php",
                "--include=*.rs",
                "--include=*.ts",
                "--include=*.js",
                "--include=*.py",
                symbol,
            ])
            .arg(search_path)
            .output();

        match output {
            Ok(o) => {
                // Exit code 1 means "no match" — that's OK
                if o.status.success() || o.status.code() == Some(1) {
                    all_output.push_str(&String::from_utf8_lossy(&o.stdout));
                }
            }
            Err(e) => {
                tracing::warn!("grep failed for symbol {symbol}: {e}");
            }
        }
    }

    parse_grep_output(&all_output, symbol, exclude_files, max_results)
}

/// Checks if a line is a function definition (not just a call that happens
/// to start with a function keyword).
fn is_function_definition(context: &str, symbol: &str) -> bool {
    // Match patterns like `function symbolName(`, `fn symbol_name(`, `def symbol_name(`
    let pattern = format!(r"\b(?:function|fn|def)\s+{symbol}\s*\(");
    Regex::new(&pattern)
        .map(|re| re.is_match(context))
        .unwrap_or(false)
}

/// Fallback: extract all non-private function names from plan files using
/// tree-sitter.
fn fallback_extract_symbols(plan_files: &[PathBuf]) -> Vec<String> {
    let mut symbols = Vec::new();

    for file in plan_files {
        let source = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut parser = tree_sitter::Parser::new();
        let lang: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        if parser.set_language(&lang).is_err() {
            continue;
        }

        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => continue,
        };

        extract_all_function_names(&tree, source.as_bytes(), &mut symbols);
    }

    symbols.sort();
    symbols.dedup();
    symbols
}

/// Walks the tree-sitter AST to find `method_declaration` nodes whose
/// signature area overlaps with any diff hunk.
fn find_changed_methods(
    tree: &tree_sitter::Tree,
    source: &[u8],
    hunks: &[&DiffHunk],
    symbols: &mut Vec<String>,
) {
    let root = tree.root_node();
    let mut cursor = root.walk();
    find_methods_recursive(&mut cursor, source, hunks, symbols);
}

fn find_methods_recursive(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    hunks: &[&DiffHunk],
    symbols: &mut Vec<String>,
) {
    loop {
        let node = cursor.node();

        if node.kind() == "method_declaration" || node.kind() == "function_definition" {
            // Find the name child
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or_default();

                // Check if any hunk overlaps the signature area
                // Signature area: from method start to body `{` start
                #[allow(clippy::cast_possible_truncation)]
                let method_start = node.start_position().row as u32 + 1; // 1-based
                let body_start = node
                    .child_by_field_name("body")
                    .map_or(method_start, |b| {
                        #[allow(clippy::cast_possible_truncation)]
                        let s = b.start_position().row as u32 + 1;
                        s
                    });

                for hunk in hunks {
                    let hunk_end = hunk.new_start + hunk.new_count;
                    if hunk.new_start <= body_start && hunk_end >= method_start {
                        symbols.push(name.to_string());
                        break;
                    }
                }
            }
        }

        // Recurse into children
        if cursor.goto_first_child() {
            find_methods_recursive(cursor, source, hunks, symbols);
            cursor.goto_parent();
        }

        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// Extracts all non-private function/method names from a tree-sitter AST.
fn extract_all_function_names(
    tree: &tree_sitter::Tree,
    source: &[u8],
    symbols: &mut Vec<String>,
) {
    let root = tree.root_node();
    let mut cursor = root.walk();
    extract_names_recursive(&mut cursor, source, symbols);
}

fn extract_names_recursive(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    symbols: &mut Vec<String>,
) {
    loop {
        let node = cursor.node();

        if node.kind() == "method_declaration" || node.kind() == "function_definition" {
            // Check visibility: skip private methods
            let text = node.utf8_text(source).unwrap_or_default();
            if !text.trim_start().starts_with("private") {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or_default();
                    if !name.is_empty() {
                        symbols.push(name.to_string());
                    }
                }
            }
        }

        if cursor.goto_first_child() {
            extract_names_recursive(cursor, source, symbols);
            cursor.goto_parent();
        }

        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_grep_output_basic() {
        let output = "\
app/Services/BillingService.php:42:        $this->billingService->createMainBill($orderSerial);
app/Services/WalkinBetaService.php:100:    public function createMainBill($serial) {
app/Controllers/PaymentController.php:55:        $result = $billing->createMainBill($data);
";
        let exclude = vec![PathBuf::from("app/Services/BillingService.php")];
        let results = parse_grep_output(output, "createMainBill", &exclude, 10);

        // 3 lines: 1 excluded (BillingService), 1 definition (WalkinBeta), 1 caller (Payment)
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].caller_file,
            PathBuf::from("app/Controllers/PaymentController.php")
        );
        assert_eq!(results[0].caller_line, 55);
    }

    #[test]
    fn parse_grep_output_skips_comments() {
        let output = "\
src/main.rs:10:    // processPayment is called here
src/main.rs:11:    * processPayment documentation
src/main.rs:12:    # processPayment config
src/service.rs:20:    $this->processPayment($amount);
";
        let results = parse_grep_output(output, "processPayment", &[], 10);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].caller_file, PathBuf::from("src/service.rs"));
        assert_eq!(results[0].caller_line, 20);
    }

    #[test]
    fn parse_grep_output_max_results() {
        let mut lines = String::new();
        for i in 1..=30 {
            lines.push_str(&format!(
                "src/file{i}.rs:{i}:    call_target();\n"
            ));
        }

        let results = parse_grep_output(&lines, "call_target", &[], 5);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn parse_diff_hunks_basic() {
        let diff = "\
diff --git a/app/Services/Foo.php b/app/Services/Foo.php
--- a/app/Services/Foo.php
+++ b/app/Services/Foo.php
@@ -10,3 +10,5 @@ class Foo
@@ -30,0 +32,2 @@ class Foo
diff --git a/app/Models/Bar.php b/app/Models/Bar.php
--- a/app/Models/Bar.php
+++ b/app/Models/Bar.php
@@ -5,1 +5,1 @@ class Bar
";
        let hunks = parse_diff_hunks(diff);

        assert_eq!(hunks.len(), 2);

        let foo_hunks = &hunks["app/Services/Foo.php"];
        assert_eq!(foo_hunks.len(), 2);
        assert_eq!(foo_hunks[0], DiffHunk { new_start: 10, new_count: 5 });
        assert_eq!(foo_hunks[1], DiffHunk { new_start: 32, new_count: 2 });

        let bar_hunks = &hunks["app/Models/Bar.php"];
        assert_eq!(bar_hunks.len(), 1);
        assert_eq!(bar_hunks[0], DiffHunk { new_start: 5, new_count: 1 });
    }

    #[test]
    fn parse_grep_skips_function_definitions() {
        let output = "\
app/Services/PaymentService.php:42:    public function processPayment($amount) {
app/Services/PaymentService.php:43:        protected function processPayment($data) {
app/Controllers/Ctrl.php:10:    $svc->processPayment($total);
app/Services/Other.php:20:    fn processPayment(amount: f64) {
";
        let results = parse_grep_output(output, "processPayment", &[], 10);

        // All 3 definition lines should be skipped, only the call remains
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].caller_file,
            PathBuf::from("app/Controllers/Ctrl.php")
        );
    }

    #[test]
    fn parse_grep_output_skips_use_statements() {
        let output = "\
src/lib.rs:1:use crate::services::processPayment;
src/main.rs:10:    processPayment(42);
";
        let results = parse_grep_output(output, "processPayment", &[], 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].caller_file, PathBuf::from("src/main.rs"));
    }

    #[test]
    fn expand_blast_radius_empty_symbols() {
        let result = expand_blast_radius(&[], &[], &[], 10);
        assert!(result.call_graph.is_empty());
        assert_eq!(result.total_callers, 0);
        assert!(result.expanded_files.is_empty());
    }

    #[test]
    fn parse_diff_hunks_no_count() {
        // When count is omitted, it defaults to 1
        let diff = "\
+++ b/src/main.rs
@@ -5 +5 @@ fn main
";
        let hunks = parse_diff_hunks(diff);
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks["src/main.rs"][0], DiffHunk { new_start: 5, new_count: 1 });
    }
}
