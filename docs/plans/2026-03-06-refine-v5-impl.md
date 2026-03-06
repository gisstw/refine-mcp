# Refine v5 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add blast radius expansion (auto-find callers of changed functions) and migration schema extraction to refine-mcp, so red teams can catch "fix here, break there" bugs.

**Architecture:** Two new MCP tools (`expand_blast_radius`, `extract_migration_facts`) that run between `discover_and_extract` and `prepare_attack`. Blast radius uses `grep -rnw` + git diff for symbol detection. Migration parser reuses existing tree-sitter-php. Red team templates get new analysis sections for callers and schema.

**Tech Stack:** Rust, tree-sitter-php, rmcp, std::process::Command (grep/git)

---

### Task 1: Add new types to `facts/types.rs`

**Files:**
- Modify: `src/facts/types.rs`

**Step 1: Add CallerFact, SchemaSnapshot, and related structs**

Add after the existing `NullRiskFact` struct (line ~127):

```rust
// ─── Blast Radius Facts ─────────────────────────────────────

/// A caller of a function found via grep search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerFact {
    /// The function/method name being called
    pub symbol: String,
    /// File containing the call site
    pub caller_file: PathBuf,
    /// Line number of the call
    pub caller_line: u32,
    /// The source line (trimmed) for context
    pub context: String,
}

// ─── Schema Facts ───────────────────────────────────────────

/// Complete schema snapshot from migration files.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SchemaSnapshot {
    pub tables: Vec<SchemaTable>,
    #[serde(default)]
    pub type_warnings: Vec<String>,
}

/// Schema for a single database table.
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

/// A single column definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnFact {
    pub name: String,
    /// Laravel column type method name: "string", "integer", "increments", etc.
    pub col_type: String,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default)]
    pub has_default: bool,
    pub default_value: Option<String>,
}

/// A foreign key constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForeignKeyFact {
    pub column: String,
    pub references_table: String,
    pub references_column: String,
    pub on_delete: Option<String>,
}
```

**Step 2: Add `callers` field to `FactTable`**

In the existing `FactTable` struct, add after `warnings`:

```rust
pub struct FactTable {
    pub file: PathBuf,
    pub language: Language,
    #[serde(default)]
    pub functions: Vec<FunctionFact>,
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Callers of functions in this file, populated by expand_blast_radius
    #[serde(default)]
    pub callers: Vec<CallerFact>,
}
```

**Step 3: Add unit tests for new types**

Add at the end of the existing `mod tests` block:

```rust
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
    assert_eq!(restored.tables[0].foreign_keys[0].on_delete.as_deref(), Some("CASCADE"));
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
```

**Step 4: Run tests**

Run: `cd /home/www/refine-mcp && cargo test facts::types`
Expected: All tests pass

**Step 5: Commit**

```bash
cd /home/www/refine-mcp && git add src/facts/types.rs && git commit -m "feat(types): add CallerFact, SchemaSnapshot, and FactTable.callers"
```

---

### Task 2: Implement blast radius module (`facts/blast_radius.rs`)

**Files:**
- Create: `src/facts/blast_radius.rs`
- Modify: `src/facts/mod.rs` (add `pub mod blast_radius;`)

**Step 1: Write tests first**

Create `src/facts/blast_radius.rs` with test module:

```rust
use std::path::{Path, PathBuf};

use crate::facts::types::CallerFact;

// ─── Public API ────────────────────────────────────────────────

/// Result of a blast radius expansion.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlastRadiusResult {
    /// Callers grouped by symbol name
    pub call_graph: std::collections::HashMap<String, Vec<CallerFact>>,
    /// Deduplicated list of files that contain calls to any of the symbols
    pub expanded_files: Vec<String>,
    /// Total number of call sites found
    pub total_callers: usize,
}

/// Find all callers of the given symbols using `grep -rnw`.
///
/// - `symbols`: function/method names to search for
/// - `search_paths`: directories to search (e.g., `["app/", "routes/"]`)
/// - `exclude_files`: files to exclude from results (typically the source file itself)
/// - `max_per_symbol`: maximum results per symbol (prevents explosion)
pub fn expand_blast_radius(
    symbols: &[String],
    search_paths: &[String],
    exclude_files: &[String],
    max_per_symbol: usize,
) -> BlastRadiusResult {
    let mut call_graph = std::collections::HashMap::new();
    let mut all_files = std::collections::HashSet::new();
    let mut total_callers = 0;

    for symbol in symbols {
        let callers = grep_symbol(symbol, search_paths, exclude_files, max_per_symbol);
        for caller in &callers {
            all_files.insert(caller.caller_file.to_string_lossy().to_string());
        }
        total_callers += callers.len();
        call_graph.insert(symbol.clone(), callers);
    }

    let mut expanded_files: Vec<String> = all_files.into_iter().collect();
    expanded_files.sort();

    BlastRadiusResult {
        call_graph,
        expanded_files,
        total_callers,
    }
}

/// Extract function names whose **signatures** changed in `git diff HEAD`.
///
/// Strategy:
/// 1. Run `git diff HEAD` to get changed hunks with line numbers
/// 2. For each file in `plan_files`, find changed line ranges
/// 3. Use tree-sitter to find `method_declaration` nodes overlapping those ranges
/// 4. Check if the change touches the parameter list or return type (not just body)
///
/// Returns only function names where the signature (params/return) was modified.
/// Falls back to returning all public function names from plan files if git diff is unavailable.
pub fn extract_changed_symbols(plan_files: &[String]) -> Vec<String> {
    let diff_output = run_git_diff();
    if diff_output.is_empty() {
        // Fallback: extract all function names from plan files via tree-sitter
        return extract_all_function_names(plan_files);
    }

    let hunks = parse_diff_hunks(&diff_output);
    let mut symbols = Vec::new();

    for file_path in plan_files {
        let path = Path::new(file_path);
        if !path.exists() || path.extension().and_then(|e| e.to_str()) != Some("php") {
            continue;
        }

        let Some(file_hunks) = hunks.get(file_path.as_str()) else {
            // Also try without leading path components
            let short = file_path.trim_start_matches("./");
            if hunks.get(short).is_none() {
                continue;
            } else {
                // found via short path — fall through
                let file_hunks = &hunks[short];
                symbols.extend(find_signature_changes(path, file_hunks));
                continue;
            }
        };

        symbols.extend(find_signature_changes(path, file_hunks));
    }

    symbols.sort();
    symbols.dedup();
    symbols
}

// ─── grep helpers ──────────────────────────────────────────────

/// Run `grep -rnw` for a single symbol across search paths.
fn grep_symbol(
    symbol: &str,
    search_paths: &[String],
    exclude_files: &[String],
    max_results: usize,
) -> Vec<CallerFact> {
    let mut args = vec![
        "-rnw".to_string(),
        "--include=*.php".to_string(),
        "--include=*.rs".to_string(),
        "--include=*.ts".to_string(),
        "--include=*.js".to_string(),
        "--include=*.py".to_string(),
    ];

    // Add exclude patterns for source files
    for ef in exclude_files {
        args.push(format!("--exclude={}", Path::new(ef).file_name().unwrap_or_default().to_string_lossy()));
    }

    args.push(symbol.to_string());
    args.extend(search_paths.iter().cloned());

    let output = std::process::Command::new("grep")
        .args(&args)
        .output()
        .ok()
        .filter(|o| o.status.success() || o.status.code() == Some(1)) // 1 = no match
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    parse_grep_output(&output, symbol, exclude_files, max_results)
}

/// Parse `grep -rn` output lines: `file:line:context`
pub fn parse_grep_output(
    output: &str,
    symbol: &str,
    exclude_files: &[String],
    max_results: usize,
) -> Vec<CallerFact> {
    let mut results = Vec::new();

    for line in output.lines() {
        if results.len() >= max_results {
            break;
        }

        // Format: file_path:line_number:context
        let mut parts = line.splitn(3, ':');
        let Some(file) = parts.next() else { continue };
        let Some(line_str) = parts.next() else { continue };
        let Some(context) = parts.next() else { continue };

        let Ok(line_num) = line_str.parse::<u32>() else { continue };

        // Skip excluded files (compare by file name or full path)
        let file_path = Path::new(file);
        let should_exclude = exclude_files.iter().any(|ef| {
            let ef_path = Path::new(ef);
            file_path == ef_path
                || file_path.ends_with(ef)
                || ef_path.ends_with(file)
        });
        if should_exclude {
            continue;
        }

        // Skip definition lines (function declaration containing the symbol as name)
        let trimmed = context.trim();
        if trimmed.contains("function ") && trimmed.contains(symbol) {
            // Likely the function definition itself, not a call
            if trimmed.starts_with("public ") || trimmed.starts_with("protected ") || trimmed.starts_with("private ") || trimmed.starts_with("function ") {
                continue;
            }
        }

        // Skip comments and use/import statements
        if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("use ") || trimmed.starts_with('#') {
            continue;
        }

        results.push(CallerFact {
            symbol: symbol.to_string(),
            caller_file: PathBuf::from(file),
            caller_line: line_num,
            context: trimmed.to_string(),
        });
    }

    results
}

// ─── git diff helpers ──────────────────────────────────────────

/// A changed hunk: start line and line count in the new version.
#[derive(Debug, Clone)]
pub struct DiffHunk {
    pub new_start: u32,
    pub new_count: u32,
}

fn run_git_diff() -> String {
    std::process::Command::new("git")
        .args(["diff", "HEAD", "--unified=0"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Parse unified diff output into per-file hunk lists.
///
/// Looks for `--- a/file` and `@@ -old,count +new,count @@` lines.
pub fn parse_diff_hunks(diff: &str) -> std::collections::HashMap<&str, Vec<DiffHunk>> {
    use std::sync::LazyLock;
    use regex::Regex;

    static RE_FILE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\+\+\+ b/(.+)$").expect("valid regex")
    });
    static RE_HUNK: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@").expect("valid regex")
    });

    let mut result: std::collections::HashMap<&str, Vec<DiffHunk>> = std::collections::HashMap::new();
    let mut current_file: Option<&str> = None;

    for line in diff.lines() {
        if let Some(caps) = RE_FILE.captures(line) {
            let start = caps.get(1).unwrap().start();
            let end = caps.get(1).unwrap().end();
            current_file = Some(&line[start..end]);
            continue;
        }

        if let Some(caps) = RE_HUNK.captures(line) {
            if let Some(file) = current_file {
                let new_start: u32 = caps[1].parse().unwrap_or(0);
                let new_count: u32 = caps.get(2).map_or(1, |m| m.as_str().parse().unwrap_or(1));
                result.entry(file).or_default().push(DiffHunk { new_start, new_count });
            }
        }
    }

    result
}

/// Find functions in a PHP file whose signature overlaps with diff hunks.
fn find_signature_changes(path: &Path, hunks: &[DiffHunk]) -> Vec<String> {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_php::LANGUAGE_PHP.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }

    let tree = match parser.parse(&source, None) {
        Some(t) => t,
        None => return Vec::new(),
    };

    let mut symbols = Vec::new();
    collect_signature_changes(tree.root_node(), source.as_bytes(), hunks, &mut symbols);
    symbols
}

/// Walk AST for method_declaration nodes whose parameter list or return type
/// overlaps a diff hunk.
fn collect_signature_changes(
    node: tree_sitter::Node,
    source: &[u8],
    hunks: &[DiffHunk],
    symbols: &mut Vec<String>,
) {
    if node.kind() == "method_declaration" {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(String::from);

        if let Some(name) = name {
            // Check if any hunk overlaps the signature area (from method start to body start)
            #[allow(clippy::cast_possible_truncation)]
            let sig_start = node.start_position().row as u32 + 1;
            let sig_end = node
                .child_by_field_name("body")
                .map_or(sig_start + 1, |body| body.start_position().row as u32 + 1);

            for hunk in hunks {
                let hunk_end = hunk.new_start + hunk.new_count.saturating_sub(1);
                // Check overlap: hunk [new_start..hunk_end] overlaps [sig_start..sig_end]
                if hunk.new_start <= sig_end && hunk_end >= sig_start {
                    symbols.push(name);
                    break;
                }
            }
        }
        return; // Don't recurse into methods
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_signature_changes(child, source, hunks, symbols);
    }
}

/// Fallback: extract all public/protected function names from files using tree-sitter.
fn extract_all_function_names(plan_files: &[String]) -> Vec<String> {
    let mut names = Vec::new();
    for file_path in plan_files {
        let path = Path::new(file_path);
        if !path.exists() || path.extension().and_then(|e| e.to_str()) != Some("php") {
            continue;
        }
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_php::LANGUAGE_PHP.into();
        if parser.set_language(&language).is_err() {
            continue;
        }
        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => continue,
        };

        collect_all_method_names(tree.root_node(), source.as_bytes(), &mut names);
    }
    names.sort();
    names.dedup();
    names
}

fn collect_all_method_names(node: tree_sitter::Node, source: &[u8], names: &mut Vec<String>) {
    if node.kind() == "method_declaration" {
        // Skip private methods (less likely to have external callers)
        let text = node.utf8_text(source).unwrap_or_default();
        if !text.trim_start().starts_with("private") {
            if let Some(name) = node.child_by_field_name("name").and_then(|n| n.utf8_text(source).ok()) {
                names.push(name.to_string());
            }
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_all_method_names(child, source, names);
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_grep_output_basic() {
        let output = "app/Services/WalkinBetaService.php:142:        $this->billingService->createMainBill($orderSerial);\n\
                       app/Http/Controllers/ReservationController.php:387:        $bill = $this->billingService->createMainBill($serial);\n\
                       app/Services/BillingService.php:50:    public function createMainBill(string $orderSerial): array\n";

        let results = parse_grep_output(
            output,
            "createMainBill",
            &["app/Services/BillingService.php".to_string()],
            20,
        );

        // Should find 2 callers (exclude BillingService.php itself, skip the definition)
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].caller_file, PathBuf::from("app/Services/WalkinBetaService.php"));
        assert_eq!(results[0].caller_line, 142);
        assert_eq!(results[1].caller_file, PathBuf::from("app/Http/Controllers/ReservationController.php"));
    }

    #[test]
    fn parse_grep_output_skips_comments() {
        let output = "app/foo.php:10:// calls createMainBill\n\
                       app/foo.php:11:* createMainBill is used here\n\
                       app/foo.php:12:        $this->createMainBill($x);\n";

        let results = parse_grep_output(output, "createMainBill", &[], 20);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].caller_line, 12);
    }

    #[test]
    fn parse_grep_output_max_results() {
        let mut output = String::new();
        for i in 1..=30 {
            output.push_str(&format!("app/f{i}.php:{i}:$this->fn();\n"));
        }

        let results = parse_grep_output(&output, "fn", &[], 5);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn parse_diff_hunks_basic() {
        let diff = "\
diff --git a/app/Services/BillingService.php b/app/Services/BillingService.php
--- a/app/Services/BillingService.php
+++ b/app/Services/BillingService.php
@@ -48,3 +48,4 @@ class BillingService
@@ -100,0 +101,5 @@ class BillingService
";

        let hunks = parse_diff_hunks(diff);
        let file_hunks = hunks.get("app/Services/BillingService.php").unwrap();
        assert_eq!(file_hunks.len(), 2);
        assert_eq!(file_hunks[0].new_start, 48);
        assert_eq!(file_hunks[0].new_count, 4);
        assert_eq!(file_hunks[1].new_start, 101);
        assert_eq!(file_hunks[1].new_count, 5);
    }

    #[test]
    fn parse_diff_hunks_single_line() {
        let diff = "\
+++ b/app/test.php
@@ -10 +10 @@ fn
";
        let hunks = parse_diff_hunks(diff);
        let file_hunks = hunks.get("app/test.php").unwrap();
        assert_eq!(file_hunks[0].new_start, 10);
        assert_eq!(file_hunks[0].new_count, 1); // default for single-line
    }

    #[test]
    fn parse_grep_skips_function_definitions() {
        let output = "app/Services/Svc.php:50:    public function createMainBill(string $orderSerial): array\n\
                       app/Other.php:100:        $this->createMainBill($s);\n";

        let results = parse_grep_output(output, "createMainBill", &[], 20);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].caller_file, PathBuf::from("app/Other.php"));
    }
}
```

**Step 2: Register module in `facts/mod.rs`**

Add to `src/facts/mod.rs`:

```rust
pub mod blast_radius;
pub mod php;
pub mod python;
pub mod rust_lang;
pub mod types;
pub mod typescript;
```

**Step 3: Run tests**

Run: `cd /home/www/refine-mcp && cargo test facts::blast_radius`
Expected: All 5 tests pass

**Step 4: Commit**

```bash
cd /home/www/refine-mcp && git add src/facts/blast_radius.rs src/facts/mod.rs && git commit -m "feat(blast-radius): add grep-based caller search and git diff symbol detection"
```

---

### Task 3: Implement migration parser (`facts/migration.rs`)

**Files:**
- Create: `src/facts/migration.rs`
- Modify: `src/facts/mod.rs` (add `pub mod migration;`)

**Step 1: Write the module with tests**

Create `src/facts/migration.rs`:

```rust
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use tree_sitter::Parser;

use crate::facts::types::{ColumnFact, ForeignKeyFact, SchemaSnapshot, SchemaTable};

// ─── Pre-compiled Regexes ──────────────────────────────────────

/// Match `Schema::create('table_name', ...)` — capture table name
static RE_SCHEMA_CREATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Schema::create\(\s*['\"](\w+)['\"]").expect("valid regex")
});

/// Match `Schema::table('table_name', ...)` — capture table name for alterations
static RE_SCHEMA_TABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Schema::table\(\s*['\"](\w+)['\"]").expect("valid regex")
});

/// Match `$table->columnType('column_name', ...)` — capture type and name
/// Handles: string, integer, bigIncrements, unsignedInteger, tinyInteger, text, etc.
static RE_COLUMN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$table->(\w+)\(\s*['\"](\w+)['\"]").expect("valid regex")
});

/// Match `->nullable()` on the same line
static RE_NULLABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"->nullable\(\s*\)").expect("valid regex")
});

/// Match `->default(value)` — capture the value
static RE_DEFAULT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"->default\((.+?)\)").expect("valid regex")
});

/// Match `->unique()` on the same line
static RE_UNIQUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"->unique\(\s*\)").expect("valid regex")
});

/// Match `$table->foreign('col')->references('ref_col')->on('ref_table')`
static RE_FOREIGN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\$table->foreign\(\s*['\"](\w+)['\"]\s*\)->references\(\s*['\"](\w+)['\"]\s*\)->on\(\s*['\"](\w+)['\"]"
    ).expect("valid regex")
});

/// Match `->onDelete('cascade')` etc.
static RE_ON_DELETE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"->onDelete\(\s*['\"](\w+)['\"]").expect("valid regex")
});

/// Match `$table->index(...)` or `$table->index('name')` — capture index name/spec
static RE_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$table->(?:index|unique)\(\s*\[?['\"](\w+)['\"]").expect("valid regex")
});

/// Column type methods that create columns (vs. modifiers or schema methods)
const COLUMN_TYPES: &[&str] = &[
    "id", "increments", "bigIncrements", "tinyIncrements",
    "integer", "tinyInteger", "smallInteger", "mediumInteger", "bigInteger",
    "unsignedInteger", "unsignedTinyInteger", "unsignedSmallInteger", "unsignedBigInteger",
    "float", "double", "decimal", "unsignedDecimal",
    "string", "char", "text", "mediumText", "longText",
    "boolean", "date", "dateTime", "dateTimeTz", "time", "timeTz",
    "timestamp", "timestampTz", "timestamps", "timestampsTz",
    "json", "jsonb", "binary", "uuid", "enum",
    "foreignId", "morphs", "nullableMorphs", "rememberToken", "softDeletes",
];

// ─── Public API ────────────────────────────────────────────────

/// Parse all migration files in a directory and return a unified schema snapshot.
pub fn extract_migration_facts(migration_dir: &Path) -> anyhow::Result<SchemaSnapshot> {
    let mut tables: std::collections::HashMap<String, SchemaTable> = std::collections::HashMap::new();
    let mut type_warnings = Vec::new();

    let entries = std::fs::read_dir(migration_dir)
        .map_err(|e| anyhow::anyhow!("Failed to read migration dir: {e}"))?;

    let mut migration_files: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "php")
        })
        .map(|e| e.path())
        .collect();

    // Sort by filename to process in chronological order
    migration_files.sort();

    for path in &migration_files {
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        parse_migration_file(path, &source, &mut tables);
    }

    // Generate type warnings
    for table in tables.values() {
        detect_type_warnings(table, &mut type_warnings);
    }

    let mut tables_vec: Vec<SchemaTable> = tables.into_values().collect();
    tables_vec.sort_by(|a, b| a.table_name.cmp(&b.table_name));
    type_warnings.sort();

    Ok(SchemaSnapshot {
        tables: tables_vec,
        type_warnings,
    })
}

// ─── Internal Logic ────────────────────────────────────────────

fn parse_migration_file(
    path: &Path,
    source: &str,
    tables: &mut std::collections::HashMap<String, SchemaTable>,
) {
    // Find Schema::create or Schema::table calls
    for line in source.lines() {
        if let Some(caps) = RE_SCHEMA_CREATE.captures(line) {
            let table_name = caps[1].to_string();
            let table = tables.entry(table_name.clone()).or_insert_with(|| SchemaTable {
                table_name: table_name.clone(),
                columns: Vec::new(),
                foreign_keys: Vec::new(),
                indexes: Vec::new(),
                source_file: path.to_path_buf(),
            });
            // Parse the closure body for column definitions
            parse_table_body(source, &table_name, table);
        }
        if let Some(caps) = RE_SCHEMA_TABLE.captures(line) {
            let table_name = caps[1].to_string();
            let table = tables.entry(table_name.clone()).or_insert_with(|| SchemaTable {
                table_name: table_name.clone(),
                columns: Vec::new(),
                foreign_keys: Vec::new(),
                indexes: Vec::new(),
                source_file: path.to_path_buf(),
            });
            parse_table_body(source, &table_name, table);
        }
    }
}

fn parse_table_body(source: &str, _table_name: &str, table: &mut SchemaTable) {
    for line in source.lines() {
        // Parse column definitions
        if let Some(caps) = RE_COLUMN.captures(line) {
            let method = &caps[1];
            let col_name = caps[2].to_string();

            if !COLUMN_TYPES.contains(&method) {
                continue;
            }

            // Handle special cases
            if method == "id" || method == "timestamps" || method == "softDeletes" || method == "rememberToken" {
                // These are shorthand methods — add predefined columns
                match method {
                    "id" => {
                        table.columns.push(ColumnFact {
                            name: col_name,
                            col_type: "bigIncrements".to_string(),
                            nullable: false,
                            has_default: false,
                            default_value: None,
                        });
                    }
                    _ => {} // timestamps etc. handled by Laravel internally
                }
                continue;
            }

            let nullable = RE_NULLABLE.is_match(line);
            let default_match = RE_DEFAULT.captures(line);
            let has_default = default_match.is_some();
            let default_value = default_match.map(|c| c[1].trim().trim_matches('\'').trim_matches('"').to_string());

            // Skip if column already exists (Schema::table may re-add)
            if table.columns.iter().any(|c| c.name == col_name) {
                continue;
            }

            table.columns.push(ColumnFact {
                name: col_name,
                col_type: method.to_string(),
                nullable,
                has_default,
                default_value,
            });
        }

        // Parse foreign keys
        if let Some(caps) = RE_FOREIGN.captures(line) {
            let on_delete = RE_ON_DELETE.captures(line).map(|c| c[1].to_string());
            table.foreign_keys.push(ForeignKeyFact {
                column: caps[1].to_string(),
                references_table: caps[3].to_string(),
                references_column: caps[2].to_string(),
                on_delete,
            });
        }

        // Parse indexes
        if let Some(caps) = RE_INDEX.captures(line) {
            let idx_name = caps[1].to_string();
            if !table.indexes.contains(&idx_name) {
                table.indexes.push(idx_name);
            }
        }
    }
}

/// Detect risky column type patterns.
pub fn detect_type_warnings(table: &SchemaTable, warnings: &mut Vec<String>) {
    for col in &table.columns {
        // VARCHAR for price/amount columns
        if col.col_type == "string"
            && (col.name.contains("price")
                || col.name.contains("amount")
                || col.name.contains("total")
                || col.name.contains("fee")
                || col.name.contains("cost"))
        {
            warnings.push(format!(
                "{}.{}: VARCHAR('string') used for monetary column — arithmetic may produce wrong results",
                table.table_name, col.name
            ));
        }

        // ENUM with numeric string values
        if col.col_type == "enum" {
            warnings.push(format!(
                "{}.{}: ENUM column — values outside the defined set are silently rejected or truncated",
                table.table_name, col.name
            ));
        }

        // NOT NULL without default in create
        if !col.nullable && !col.has_default && col.col_type != "bigIncrements" && col.col_type != "increments" {
            // This is informational, not a warning — many columns legitimately require values
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_migration() {
        let source = r#"<?php
return new class extends Migration {
    public function up(): void {
        Schema::create('notifications', function (Blueprint $table) {
            $table->id();
            $table->string('code', 100)->unique();
            $table->string('name');
            $table->text('description')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();
            $table->index('is_active');
        });
    }
};
"#;
        let mut tables = std::collections::HashMap::new();
        parse_migration_file(Path::new("test.php"), source, &mut tables);

        let table = tables.get("notifications").unwrap();
        assert_eq!(table.table_name, "notifications");

        // Check columns
        let code = table.columns.iter().find(|c| c.name == "code").unwrap();
        assert_eq!(code.col_type, "string");
        assert!(!code.nullable);

        let desc = table.columns.iter().find(|c| c.name == "description").unwrap();
        assert!(desc.nullable);

        let active = table.columns.iter().find(|c| c.name == "is_active").unwrap();
        assert!(active.has_default);
        assert_eq!(active.default_value.as_deref(), Some("true"));
    }

    #[test]
    fn parse_foreign_key() {
        let source = r#"<?php
Schema::create('reservation_rooms', function (Blueprint $table) {
    $table->id();
    $table->unsignedInteger('reservation_id');
    $table->foreign('reservation_id')->references('id')->on('reservations')->onDelete('cascade');
});
"#;
        let mut tables = std::collections::HashMap::new();
        parse_migration_file(Path::new("test.php"), source, &mut tables);

        let table = tables.get("reservation_rooms").unwrap();
        assert_eq!(table.foreign_keys.len(), 1);
        assert_eq!(table.foreign_keys[0].column, "reservation_id");
        assert_eq!(table.foreign_keys[0].references_table, "reservations");
        assert_eq!(table.foreign_keys[0].references_column, "id");
        assert_eq!(table.foreign_keys[0].on_delete.as_deref(), Some("cascade"));
    }

    #[test]
    fn detect_varchar_price_warning() {
        let table = SchemaTable {
            table_name: "pricing_deposit".to_string(),
            columns: vec![ColumnFact {
                name: "price".to_string(),
                col_type: "string".to_string(),
                nullable: false,
                has_default: false,
                default_value: None,
            }],
            foreign_keys: vec![],
            indexes: vec![],
            source_file: PathBuf::from("test.php"),
        };

        let mut warnings = Vec::new();
        detect_type_warnings(&table, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("VARCHAR"));
        assert!(warnings[0].contains("pricing_deposit.price"));
    }

    #[test]
    fn detect_enum_warning() {
        let table = SchemaTable {
            table_name: "pricing_deposit".to_string(),
            columns: vec![ColumnFact {
                name: "type".to_string(),
                col_type: "enum".to_string(),
                nullable: false,
                has_default: false,
                default_value: None,
            }],
            foreign_keys: vec![],
            indexes: vec![],
            source_file: PathBuf::from("test.php"),
        };

        let mut warnings = Vec::new();
        detect_type_warnings(&table, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("ENUM"));
    }

    #[test]
    fn schema_table_alterations_merge() {
        let source1 = r#"Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('email');
        });"#;

        let source2 = r#"Schema::table('users', function (Blueprint $table) {
            $table->string('phone')->nullable();
        });"#;

        let mut tables = std::collections::HashMap::new();
        parse_migration_file(Path::new("001.php"), source1, &mut tables);
        parse_migration_file(Path::new("002.php"), source2, &mut tables);

        let table = tables.get("users").unwrap();
        assert!(table.columns.iter().any(|c| c.name == "email"));
        assert!(table.columns.iter().any(|c| c.name == "phone" && c.nullable));
    }
}
```

**Step 2: Add module to `facts/mod.rs`**

```rust
pub mod blast_radius;
pub mod migration;
pub mod php;
pub mod python;
pub mod rust_lang;
pub mod types;
pub mod typescript;
```

**Step 3: Run tests**

Run: `cd /home/www/refine-mcp && cargo test facts::migration`
Expected: All 5 tests pass

**Step 4: Commit**

```bash
cd /home/www/refine-mcp && git add src/facts/migration.rs src/facts/mod.rs && git commit -m "feat(migration): add Laravel migration schema parser with type warnings"
```

---

### Task 4: Add MCP tools to `server.rs`

**Files:**
- Modify: `src/server.rs`

**Step 1: Add parameter structs**

After the existing `DiscoverAndExtractParams` struct (~line 80):

```rust
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ExpandBlastRadiusParams {
    /// Function/method names to search for callers.
    /// If empty, auto-detects from git diff of plan files.
    pub symbols: Option<Vec<String>>,
    /// Directories to search (default: ["app/", "routes/"])
    pub search_paths: Option<Vec<String>>,
    /// Files to exclude from results (typically the source files being modified)
    pub exclude_files: Option<Vec<String>>,
    /// Plan file paths (used for auto-detecting changed symbols via git diff)
    pub plan_files: Option<Vec<String>>,
    /// Max grep results per symbol (default: 20)
    pub max_per_symbol: Option<usize>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ExtractMigrationFactsParams {
    /// Path to migration directory (default: database/migrations)
    pub migration_dir: Option<String>,
    /// Only include tables matching these names (default: all)
    pub table_filter: Option<Vec<String>>,
}
```

**Step 2: Add tool implementations**

Add these two new `#[tool]` methods inside the `#[tool_router] impl RefineServer` block, after `discover_and_extract`:

```rust
    // ── Tool 6: expand_blast_radius ────────────────────────────

    #[tool(
        description = "Find all callers of specified functions using grep. Auto-detects changed function signatures from git diff if symbols not provided. Returns call graph and expanded file list for feeding into extract_facts."
    )]
    async fn expand_blast_radius(
        &self,
        params: Parameters<ExpandBlastRadiusParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let search_paths = params.0.search_paths.unwrap_or_else(|| {
            vec!["app/".to_string(), "routes/".to_string()]
        });
        let exclude_files = params.0.exclude_files.unwrap_or_default();
        let max_per_symbol = params.0.max_per_symbol.unwrap_or(20);

        // Auto-detect symbols from git diff if not provided
        let symbols = if let Some(syms) = params.0.symbols {
            if syms.is_empty() {
                let plan_files = params.0.plan_files.unwrap_or_default();
                refine_mcp::facts::blast_radius::extract_changed_symbols(&plan_files)
            } else {
                syms
            }
        } else {
            let plan_files = params.0.plan_files.unwrap_or_default();
            refine_mcp::facts::blast_radius::extract_changed_symbols(&plan_files)
        };

        if symbols.is_empty() {
            let output = serde_json::json!({
                "call_graph": {},
                "expanded_files": [],
                "total_callers": 0,
                "symbols_searched": 0,
                "note": "No symbols to search. Provide symbols or ensure plan files have git changes."
            });
            return Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&output).unwrap_or_default(),
            )]));
        }

        let result = refine_mcp::facts::blast_radius::expand_blast_radius(
            &symbols,
            &search_paths,
            &exclude_files,
            max_per_symbol,
        );

        let output = serde_json::json!({
            "call_graph": result.call_graph,
            "expanded_files": result.expanded_files,
            "total_callers": result.total_callers,
            "symbols_searched": symbols,
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }

    // ── Tool 7: extract_migration_facts ────────────────────────

    #[tool(
        description = "Parse Laravel migration files to extract database schema: column types, nullable, defaults, foreign keys, indexes. Generates warnings for risky patterns (VARCHAR price columns, ENUM pitfalls). Feed the output into prepare_attack as schema_json."
    )]
    async fn extract_migration_facts(
        &self,
        params: Parameters<ExtractMigrationFactsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let migration_dir = params
            .0
            .migration_dir
            .unwrap_or_else(|| "database/migrations".to_string());

        let dir_path = validate_dir(&migration_dir)?;

        let snapshot = refine_mcp::facts::migration::extract_migration_facts(&dir_path)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("Migration parse failed: {e}"), None))?;

        // Apply table filter if provided
        let filtered = if let Some(filter) = params.0.table_filter {
            refine_mcp::facts::types::SchemaSnapshot {
                tables: snapshot
                    .tables
                    .into_iter()
                    .filter(|t| filter.iter().any(|f| t.table_name.contains(f)))
                    .collect(),
                type_warnings: snapshot
                    .type_warnings
                    .into_iter()
                    .filter(|w| filter.iter().any(|f| w.contains(f)))
                    .collect(),
            }
        } else {
            snapshot
        };

        let output = serde_json::json!({
            "schema": filtered,
            "table_count": filtered.tables.len(),
            "column_count": filtered.tables.iter().map(|t| t.columns.len()).sum::<usize>(),
            "warning_count": filtered.type_warnings.len(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&output).unwrap_or_default(),
        )]))
    }
```

**Step 3: Add `schema_json` to `PrepareAttackParams`**

Modify the existing struct:

```rust
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PrepareAttackParams {
    /// Path to the plan file
    pub plan_path: String,
    /// JSON-encoded fact tables from `extract_facts`
    pub facts_json: String,
    /// Refine mode: default, lite, or auto
    pub mode: Option<String>,
    /// Number of red teams (2-4), or omit for auto-selection based on fact signals.
    pub red_count: Option<u8>,
    /// JSON-encoded SchemaSnapshot from `extract_migration_facts` (optional)
    pub schema_json: Option<String>,
}
```

**Step 4: Update `prepare_attack` to inject schema into prompts**

In the `prepare_attack` method, after parsing `fact_tables`, add schema handling:

```rust
    // Parse schema if provided
    let schema_section = if let Some(ref schema_str) = params.0.schema_json {
        match serde_json::from_str::<refine_mcp::facts::types::SchemaSnapshot>(schema_str) {
            Ok(schema) => {
                // Only include tables referenced by state_mutations in fact tables
                let mutation_targets: std::collections::HashSet<String> = fact_tables.iter()
                    .flat_map(|t| t.functions.iter())
                    .flat_map(|f| f.state_mutations.iter())
                    .map(|m| m.target.to_lowercase())
                    .collect();

                let relevant_tables: Vec<_> = schema.tables.iter()
                    .filter(|t| mutation_targets.iter().any(|mt| mt.contains(&t.table_name.to_lowercase())))
                    .collect();

                if relevant_tables.is_empty() && schema.type_warnings.is_empty() {
                    String::new()
                } else {
                    let filtered = serde_json::json!({
                        "tables": relevant_tables,
                        "type_warnings": schema.type_warnings,
                    });
                    format!("\n### Database Schema\n\n{}\n", serde_json::to_string_pretty(&filtered).unwrap_or_default())
                }
            }
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };
```

Then modify the prompt building to inject `schema_section` — update the `build_red_team_prompts_selected` call site or add `.replace("{schema_section}", &schema_section)` in the prompt building.

**Step 5: Run full test suite**

Run: `cd /home/www/refine-mcp && cargo test`
Expected: All existing + new tests pass

**Step 6: Commit**

```bash
cd /home/www/refine-mcp && git add src/server.rs && git commit -m "feat(server): add expand_blast_radius and extract_migration_facts MCP tools"
```

---

### Task 5: Update prompts to inject callers + schema

**Files:**
- Modify: `src/prompts/mod.rs`
- Modify: `templates/rt_a_single_op.md`
- Modify: `templates/rt_b_multi_op.md`
- Modify: `templates/rt_c_data_integrity.md`

**Step 1: Add `{schema_section}` placeholder to prompt builder**

In `src/prompts/mod.rs`, update `build_red_team_prompts_selected` to accept optional schema:

```rust
/// Build red team prompts, optionally injecting schema section.
#[must_use]
pub fn build_red_team_prompts_with_schema(
    mode: RefineMode,
    plan_content: &str,
    fact_tables: &[FactTable],
    teams: &[RedTeamId],
    schema_section: &str,
) -> Vec<RedTeamPrompt> {
    let facts_json = serde_json::to_string_pretty(fact_tables).unwrap_or_else(|_| "[]".to_string());

    teams
        .iter()
        .map(|id| {
            let template = template_for(*id);
            let prompt = template
                .replace("{plan_content}", plan_content)
                .replace("{fact_tables}", &facts_json)
                .replace("{schema_section}", schema_section);
            RedTeamPrompt {
                id: *id,
                prompt,
                recommended_model: mode.red_model().to_string(),
            }
        })
        .collect()
}
```

Keep the old functions for backward compatibility — they call the new one with empty schema.

**Step 2: Add blast radius and schema sections to RT-A template**

Append to `templates/rt_a_single_op.md` before the `## Rules` section:

```markdown
### Blast Radius (Caller Impact)
9. `callers` in fact tables — if a function's signature (parameters, return type) changed, check every caller:
   - Does the caller pass the correct argument types in the correct order?
   - Does the caller handle the new return semantics? (e.g., function changed from throw to return error array)
   - Is the caller aware of new nullable returns or removed parameters?

### Schema Constraints
10. Cross-reference `state_mutations` targets with `schema_tables`:
    - Is a VARCHAR column used for arithmetic (price, amount)?
    - Does a Create mutation provide values for all NOT NULL columns without defaults?
    - Is an ENUM column being set to a value outside its defined set?
{schema_section}
```

**Step 3: Add cross-caller section to RT-B template**

Append to `templates/rt_b_multi_op.md` before `## Rules`:

```markdown
### Cross-Caller Conflicts
9. `callers` — can two different callers invoke the same function concurrently with conflicting assumptions?
   - Caller A uses old behavior, Caller B uses new behavior — race during deployment?
   - Multiple callers in the same request chain — is the function idempotent?

### Schema Race Conditions
10. FK constraints + concurrent deletes — does deleting a parent row cascade-delete children that another request is reading?
{schema_section}
```

**Step 4: Add schema section to RT-C template**

Append to `templates/rt_c_data_integrity.md` before `## Rules`:

```markdown
### Schema Validation
10. Cross-reference `state_mutations` with `schema_tables.type_warnings`:
    - VARCHAR price columns: string concatenation instead of addition?
    - ENUM columns: writing values outside the defined set?
    - Foreign key cascades: does deleting a parent silently remove child records?
{schema_section}
```

**Step 5: Run tests**

Run: `cd /home/www/refine-mcp && cargo test`
Expected: All tests pass (template changes don't break existing tests since `{schema_section}` is replaced with empty string when not provided)

**Step 6: Commit**

```bash
cd /home/www/refine-mcp && git add src/prompts/mod.rs templates/ && git commit -m "feat(prompts): inject blast radius and schema sections into red team templates"
```

---

### Task 6: Update `prepare_attack` to wire everything together

**Files:**
- Modify: `src/server.rs` (the `prepare_attack` method)

**Step 1: Update prepare_attack to use new prompt builder**

Replace the prompt building logic in `prepare_attack` to use the schema-aware version:

```rust
    // In prepare_attack method, replace the prompt building block:

    let schema_section = if let Some(ref schema_str) = params.0.schema_json {
        match serde_json::from_str::<refine_mcp::facts::types::SchemaSnapshot>(schema_str) {
            Ok(schema) => {
                let mutation_targets: std::collections::HashSet<String> = fact_tables.iter()
                    .flat_map(|t| t.functions.iter())
                    .flat_map(|f| f.state_mutations.iter())
                    .map(|m| m.target.to_lowercase())
                    .collect();

                let relevant_tables: Vec<_> = schema.tables.iter()
                    .filter(|t| mutation_targets.iter().any(|mt| mt.contains(&t.table_name.to_lowercase())))
                    .collect();

                if relevant_tables.is_empty() && schema.type_warnings.is_empty() {
                    String::new()
                } else {
                    let filtered = serde_json::json!({
                        "relevant_tables": relevant_tables,
                        "type_warnings": schema.type_warnings,
                    });
                    format!("\n```json\n{}\n```\n", serde_json::to_string_pretty(&filtered).unwrap_or_default())
                }
            }
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };

    let prompts = if let Some(n) = params.0.red_count {
        let ids: Vec<refine_mcp::types::RedTeamId> = [
            refine_mcp::types::RedTeamId::RtA,
            refine_mcp::types::RedTeamId::RtB,
            refine_mcp::types::RedTeamId::RtC,
            refine_mcp::types::RedTeamId::RtD,
        ][..n.clamp(2, 4) as usize].to_vec();
        refine_mcp::prompts::build_red_team_prompts_with_schema(
            mode, &plan_content, &fact_tables, &ids, &schema_section,
        )
    } else {
        let teams = refine_mcp::prompts::auto_select_red_teams(&fact_tables);
        refine_mcp::prompts::build_red_team_prompts_with_schema(
            mode, &plan_content, &fact_tables, &teams, &schema_section,
        )
    };
```

**Step 2: Run tests**

Run: `cd /home/www/refine-mcp && cargo test`
Expected: All pass

**Step 3: Commit**

```bash
cd /home/www/refine-mcp && git add src/server.rs && git commit -m "feat(prepare-attack): wire schema_json into red team prompt generation"
```

---

### Task 7: Add test fixture and integration test

**Files:**
- Create: `tests/fixtures/sample_migration.php`
- Modify: existing test infrastructure

**Step 1: Create migration fixture**

```php
<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void {
        Schema::create('pricing_deposit', function (Blueprint $table) {
            $table->increments('id');
            $table->string('price');
            $table->enum('type', ['1', '2', '3']);
            $table->unsignedInteger('reservation_id');
            $table->boolean('fail')->default(false);
            $table->foreign('reservation_id')->references('id')->on('reservations')->onDelete('cascade');
            $table->timestamps();
        });
    }
};
```

**Step 2: Run full test suite one more time**

Run: `cd /home/www/refine-mcp && cargo test`
Expected: All tests pass

**Step 3: Commit**

```bash
cd /home/www/refine-mcp && git add tests/fixtures/ && git commit -m "test: add migration fixture for pricing_deposit"
```

---

### Task 8: Build and deploy

**Step 1: Build release binary**

Run: `cd /home/www/refine-mcp && cargo build --release`
Expected: Compiles without errors or warnings

**Step 2: Verify binary works**

Run: `echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}' | /home/www/refine-mcp/target/release/refine-mcp 2>/dev/null | head -1`
Expected: JSON response with server info including the new tools

**Step 3: Commit everything and tag**

```bash
cd /home/www/refine-mcp && git add -A && git commit -m "build: refine-mcp v5 release" && git tag v0.5.0
```

---

### Task 9: Update refine-plan skill

**Files:**
- Modify: `/var/www/pms/.claude/skills/refine-plan.md`

**Step 1: Update the flow diagram and step descriptions**

Add Steps 1.5 and 1.6 to the skill, update the flow chart, and add the new tool usage instructions. The key changes:

- After `discover_and_extract`, call `expand_blast_radius` with auto-detected symbols
- Call `extract_migration_facts` to get schema
- Pass `expanded_files` to `extract_facts`
- Pass `schema_json` to `prepare_attack`

**Step 2: Commit**

```bash
cd /var/www/pms && git add .claude/skills/refine-plan.md && git commit -m "feat(skill): update refine-plan for v5 blast radius + schema"
```

---

## Summary

| Task | What | Files | Tests |
|------|------|-------|-------|
| 1 | New types | `facts/types.rs` | 3 unit |
| 2 | Blast radius grep+diff | `facts/blast_radius.rs` | 5 unit |
| 3 | Migration parser | `facts/migration.rs` | 5 unit |
| 4 | MCP tool endpoints | `server.rs` | existing |
| 5 | Prompt templates | `prompts/mod.rs` + templates | existing |
| 6 | Wire prepare_attack | `server.rs` | existing |
| 7 | Test fixture | `tests/fixtures/` | 1 fixture |
| 8 | Build + deploy | — | smoke test |
| 9 | Update skill | `refine-plan.md` | — |
