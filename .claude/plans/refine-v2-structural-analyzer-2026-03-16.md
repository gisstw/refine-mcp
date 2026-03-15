# Refine v2: Structural Change Impact Analyzer

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform refine-mcp from a red-blue adversarial review tool into a structural change impact analyzer that uses tree-sitter to detect breaking changes, analyze blast radius, and measure code health.

**Architecture:** Keep the existing tree-sitter fact extraction infrastructure (4 language parsers + migration parser). Remove the red-blue team pipeline (prompts, parser, dedup, state). Replace with three new tools: `structural_diff` (before/after AST comparison), `impact_analysis` (tree-sitter-enhanced caller search), and `health_snapshot` (per-function complexity metrics). The MCP server shell (`rmcp` + stdio transport) stays identical.

**Tech Stack:** Rust, rmcp 0.16, tree-sitter 0.25, serde_json, schemars

---

## File Structure

### Files to DELETE (red-blue pipeline)
| File | Lines | Reason |
|------|-------|--------|
| `src/prompts/mod.rs` | 565 | Red/blue team prompt templates — no longer needed |
| `src/parser/mod.rs` | 345 | Red team markdown report parser — no longer needed |
| `src/dedup/mod.rs` | 237 | Finding deduplication — no longer needed |
| `src/state.rs` | 290 | Persistent finding state — no longer needed |
| `tests/parser_test.rs` | ~100 | Tests for deleted parser |
| `tests/dedup_test.rs` | ~100 | Tests for deleted dedup |

### Files to KEEP as-is
| File | Lines | Purpose |
|------|-------|---------|
| `src/main.rs` | 22 | Entry point — no changes needed |
| `src/facts/php.rs` | 487 | PHP tree-sitter extraction |
| `src/facts/rust_lang.rs` | 435 | Rust tree-sitter extraction |
| `src/facts/typescript.rs` | 624 | TypeScript tree-sitter extraction |
| `src/facts/python.rs` | 602 | Python tree-sitter extraction |
| `src/facts/migration.rs` | 446 | Laravel migration schema parser |
| `src/facts/mod.rs` | 7 | Module re-exports |
| `tests/extract_php_test.rs` | — | Keep existing tests |
| `tests/extract_rust_test.rs` | — | Keep existing tests |
| `tests/self_analysis_test.rs` | — | Keep existing tests |
| `tests/fixtures/` | — | Test fixtures |

### Files to REWRITE
| File | Action | Purpose |
|------|--------|---------|
| `src/types.rs` | Rewrite | New v2 types: `SignatureChange`, `StructuralDiff`, `FunctionHealth` |
| `src/server.rs` | Rewrite | New MCP handlers for 5 v2 tools |
| `src/lib.rs` | Modify | Remove deleted modules, add new ones |
| `src/facts/types.rs` | Minor modify | Add `Eq`/`Hash` derives for diff comparison |

### Files to CREATE
| File | Purpose |
|------|---------|
| `src/diff.rs` | `structural_diff` — compare before/after `Vec<FunctionFact>` |
| `src/health.rs` | `health_snapshot` — cyclomatic complexity + nesting depth via tree-sitter |
| `tests/diff_test.rs` | Tests for structural diff logic |
| `tests/health_test.rs` | Tests for health metrics |

### Files to REFACTOR
| File | Action | Purpose |
|------|--------|---------|
| `src/facts/blast_radius.rs` | Refactor | Keep `expand_blast_radius` + `extract_changed_symbols` + `parse_diff_hunks`. Remove nothing — this module is already clean. Rename grep-based search to `impact_analysis` at the MCP level only (internal function names stay). |

---

## Chunk 1: Cleanup — Remove Red-Blue Pipeline

### Task 1: Delete red-blue modules and update lib.rs

**Files:**
- Delete: `src/prompts/mod.rs`
- Delete: `src/parser/mod.rs`
- Delete: `src/dedup/mod.rs`
- Delete: `src/state.rs`
- Delete: `tests/parser_test.rs`
- Delete: `tests/dedup_test.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Delete the red-blue pipeline files**

```bash
rm src/prompts/mod.rs src/parser/mod.rs src/dedup/mod.rs src/state.rs
rmdir src/prompts src/parser src/dedup
rm tests/parser_test.rs tests/dedup_test.rs
```

- [ ] **Step 2: Update lib.rs to remove deleted modules**

```rust
// src/lib.rs — v2: only facts + new modules
pub mod facts;
pub mod types;
```

Note: `diff` and `health` modules will be added in later tasks.

- [ ] **Step 3: Verify it compiles (lib only, server.rs will break)**

```bash
# server.rs imports the deleted modules, so full build will fail.
# Just verify lib compiles:
cargo check --lib 2>&1 | head -20
```

Expected: lib compiles clean. Binary will fail (server.rs still references old types).

- [ ] **Step 4: Commit cleanup**

```bash
git add -A
git commit -m "refactor: remove red-blue pipeline modules (prompts, parser, dedup, state)"
```

---

## Chunk 2: New Types

### Task 2: Rewrite types.rs for v2

**Files:**
- Rewrite: `src/types.rs`
- Modify: `src/facts/types.rs` (add derives)

- [ ] **Step 1: Add PartialEq + Eq to FunctionFact and ParamFact for diff comparison**

In `src/facts/types.rs`, add `PartialEq, Eq` derives to these structs:
- `FunctionFact` — needed for detecting unchanged functions
- `ParamFact` — nested in FunctionFact
- `Language` — already has PartialEq, Eq ✓

```rust
// src/facts/types.rs — add PartialEq, Eq to these structs:

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionFact { ... }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParamFact { ... }
```

Note: `TransactionFact`, `LockFact`, `CatchFact`, `ExternalCallFact`, `MutationFact`, `NullRiskFact` — these are inside FunctionFact but we compare by **signature** (name + params + return_type), not by body details. So we do NOT need Eq on all sub-structs. We'll implement a custom signature comparison instead.

- [ ] **Step 2: Write the new types.rs**

```rust
// src/types.rs — v2 types
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

use crate::facts::types::FunctionFact;

// ─── Structural Diff ────────────────────────────────────────

/// A function signature (name + params + return type) for comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionSignature {
    pub name: String,
    pub params: Vec<ParamSignature>,
    pub return_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParamSignature {
    pub name: String,
    pub type_hint: Option<String>,
    pub nullable: bool,
}

/// A change in a function's signature between two versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureChange {
    pub name: String,
    pub file: PathBuf,
    pub before: FunctionSignature,
    pub after: FunctionSignature,
    pub breaking: bool,
    pub reasons: Vec<String>,
}

/// Result of comparing two sets of FunctionFacts (before vs after).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StructuralDiff {
    pub file: PathBuf,
    pub added: Vec<FunctionSummary>,
    pub removed: Vec<FunctionSummary>,
    pub changed: Vec<SignatureChange>,
    pub unchanged_count: usize,
}

/// Lightweight summary of a function (for added/removed lists).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub name: String,
    pub line_range: (u32, u32),
    pub params: Vec<ParamSignature>,
    pub return_type: Option<String>,
}

/// Aggregated diff across multiple files.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StructuralDiffReport {
    pub files: Vec<StructuralDiff>,
    pub total_added: usize,
    pub total_removed: usize,
    pub total_changed: usize,
    pub breaking_changes: usize,
}

// ─── Health Snapshot ────────────────────────────────────────

/// Per-function health metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionHealth {
    pub name: String,
    pub file: PathBuf,
    pub line_range: (u32, u32),
    pub lines: u32,
    pub param_count: usize,
    pub max_nesting_depth: u32,
    pub branch_count: u32,
}

/// Health report for a set of files.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HealthReport {
    pub functions: Vec<FunctionHealth>,
    pub warnings: Vec<String>,
}

// ─── Conversion helpers ─────────────────────────────────────

impl FunctionSignature {
    /// Extract signature from a FunctionFact.
    pub fn from_fact(fact: &FunctionFact) -> Self {
        Self {
            name: fact.name.clone(),
            params: fact.parameters.iter().map(|p| ParamSignature {
                name: p.name.clone(),
                type_hint: p.type_hint.clone(),
                nullable: p.nullable,
            }).collect(),
            return_type: fact.return_type.clone(),
        }
    }
}

impl FunctionSummary {
    /// Extract summary from a FunctionFact.
    pub fn from_fact(fact: &FunctionFact) -> Self {
        Self {
            name: fact.name.clone(),
            line_range: fact.line_range,
            params: fact.parameters.iter().map(|p| ParamSignature {
                name: p.name.clone(),
                type_hint: p.type_hint.clone(),
                nullable: p.nullable,
            }).collect(),
            return_type: fact.return_type.clone(),
        }
    }
}
```

- [ ] **Step 3: Update lib.rs**

```rust
// src/lib.rs
pub mod facts;
pub mod types;
```

- [ ] **Step 4: Verify lib compiles**

```bash
cargo check --lib
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/types.rs src/facts/types.rs src/lib.rs
git commit -m "refactor: rewrite types.rs for v2 structural analyzer"
```

---

## Chunk 3: Structural Diff Engine

### Task 3: Implement diff.rs

**Files:**
- Create: `src/diff.rs`
- Create: `tests/diff_test.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the failing test**

```rust
// tests/diff_test.rs
use std::path::PathBuf;
use refine_mcp::diff::compute_structural_diff;
use refine_mcp::facts::types::{FunctionFact, ParamFact};

fn make_func(name: &str, params: Vec<(&str, Option<&str>)>, ret: Option<&str>) -> FunctionFact {
    FunctionFact {
        name: name.to_string(),
        line_range: (1, 10),
        return_type: ret.map(String::from),
        parameters: params.into_iter().map(|(n, t)| ParamFact {
            name: n.to_string(),
            type_hint: t.map(String::from),
            nullable: false,
        }).collect(),
        transaction: None,
        locks: vec![],
        catch_blocks: vec![],
        external_calls: vec![],
        state_mutations: vec![],
        null_risks: vec![],
    }
}

#[test]
fn detects_added_function() {
    let before = vec![];
    let after = vec![make_func("newFunc", vec![], None)];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].name, "newFunc");
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
}

#[test]
fn detects_removed_function() {
    let before = vec![make_func("oldFunc", vec![], None)];
    let after = vec![];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert!(diff.added.is_empty());
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0].name, "oldFunc");
}

#[test]
fn detects_signature_change_return_type() {
    let before = vec![make_func("process", vec![], Some("bool"))];
    let after = vec![make_func("process", vec![], Some("PaymentResult"))];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert_eq!(diff.changed.len(), 1);
    assert!(diff.changed[0].breaking);
    assert!(diff.changed[0].reasons.iter().any(|r| r.contains("return type")));
}

#[test]
fn detects_signature_change_param_added() {
    let before = vec![make_func("save", vec![("$id", Some("int"))], None)];
    let after = vec![make_func("save", vec![
        ("$id", Some("int")),
        ("$force", Some("bool")),
    ], None)];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert_eq!(diff.changed.len(), 1);
    // Adding a param is breaking (callers need to pass it) unless it has a default
    assert!(diff.changed[0].breaking);
}

#[test]
fn unchanged_function_not_reported() {
    let func = make_func("helper", vec![("$x", Some("int"))], Some("string"));
    let before = vec![func.clone()];
    let after = vec![func];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
    assert_eq!(diff.unchanged_count, 1);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --test diff_test 2>&1 | tail -5
```

Expected: FAIL — `refine_mcp::diff` module not found.

- [ ] **Step 3: Write the implementation**

```rust
// src/diff.rs
use std::collections::HashMap;
use std::path::Path;

use crate::facts::types::FunctionFact;
use crate::types::{FunctionSignature, FunctionSummary, SignatureChange, StructuralDiff};

/// Compare before/after function lists for a single file.
/// Matches functions by name, then compares signatures.
pub fn compute_structural_diff(
    file: &Path,
    before: &[FunctionFact],
    after: &[FunctionFact],
) -> StructuralDiff {
    let before_map: HashMap<&str, &FunctionFact> =
        before.iter().map(|f| (f.name.as_str(), f)).collect();
    let after_map: HashMap<&str, &FunctionFact> =
        after.iter().map(|f| (f.name.as_str(), f)).collect();

    let mut diff = StructuralDiff {
        file: file.to_path_buf(),
        ..Default::default()
    };

    // Find removed and changed
    for (name, before_fact) in &before_map {
        match after_map.get(name) {
            None => {
                diff.removed.push(FunctionSummary::from_fact(before_fact));
            }
            Some(after_fact) => {
                let before_sig = FunctionSignature::from_fact(before_fact);
                let after_sig = FunctionSignature::from_fact(after_fact);
                if before_sig == after_sig {
                    diff.unchanged_count += 1;
                } else {
                    let (breaking, reasons) = detect_breaking_change(&before_sig, &after_sig);
                    diff.changed.push(SignatureChange {
                        name: name.to_string(),
                        file: file.to_path_buf(),
                        before: before_sig,
                        after: after_sig,
                        breaking,
                        reasons,
                    });
                }
            }
        }
    }

    // Find added
    for (name, after_fact) in &after_map {
        if !before_map.contains_key(name) {
            diff.added.push(FunctionSummary::from_fact(after_fact));
        }
    }

    diff
}

/// Determine if a signature change is breaking and why.
fn detect_breaking_change(before: &FunctionSignature, after: &FunctionSignature) -> (bool, Vec<String>) {
    let mut reasons = Vec::new();
    let mut breaking = false;

    // Return type changed
    if before.return_type != after.return_type {
        reasons.push(format!(
            "return type changed: {:?} → {:?}",
            before.return_type, after.return_type
        ));
        breaking = true;
    }

    // Params removed
    let before_names: Vec<&str> = before.params.iter().map(|p| p.name.as_str()).collect();
    let after_names: Vec<&str> = after.params.iter().map(|p| p.name.as_str()).collect();

    for name in &before_names {
        if !after_names.contains(name) {
            reasons.push(format!("parameter removed: {name}"));
            breaking = true;
        }
    }

    // Params added (breaking — callers need to pass them)
    for name in &after_names {
        if !before_names.contains(name) {
            reasons.push(format!("parameter added: {name}"));
            breaking = true;
        }
    }

    // Param type changed
    for before_param in &before.params {
        if let Some(after_param) = after.params.iter().find(|p| p.name == before_param.name) {
            if before_param.type_hint != after_param.type_hint {
                reasons.push(format!(
                    "parameter {} type changed: {:?} → {:?}",
                    before_param.name, before_param.type_hint, after_param.type_hint
                ));
                breaking = true;
            }
            if before_param.nullable != after_param.nullable {
                reasons.push(format!(
                    "parameter {} nullability changed: {} → {}",
                    before_param.name, before_param.nullable, after_param.nullable
                ));
                // Nullable → non-nullable is breaking; reverse is not
                if before_param.nullable && !after_param.nullable {
                    breaking = true;
                }
            }
        }
    }

    // Param order changed (even with same set)
    if before_names.len() == after_names.len()
        && before_names.iter().all(|n| after_names.contains(n))
        && before_names != after_names
    {
        reasons.push("parameter order changed".to_string());
        breaking = true;
    }

    (breaking, reasons)
}

/// Aggregate diffs from multiple files into a report.
pub fn aggregate_diffs(diffs: Vec<StructuralDiff>) -> crate::types::StructuralDiffReport {
    let mut report = crate::types::StructuralDiffReport::default();
    for d in &diffs {
        report.total_added += d.added.len();
        report.total_removed += d.removed.len();
        report.total_changed += d.changed.len();
        report.breaking_changes += d.changed.iter().filter(|c| c.breaking).count();
    }
    report.files = diffs;
    report
}
```

- [ ] **Step 4: Add `diff` module to lib.rs**

```rust
// src/lib.rs
pub mod diff;
pub mod facts;
pub mod types;
```

- [ ] **Step 5: Run tests**

```bash
cargo test --test diff_test -v
```

Expected: All 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/diff.rs src/lib.rs tests/diff_test.rs
git commit -m "feat: add structural diff engine (before/after function signature comparison)"
```

---

## Chunk 4: Health Snapshot

### Task 4: Implement health.rs

**Files:**
- Create: `src/health.rs`
- Create: `tests/health_test.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the failing test**

```rust
// tests/health_test.rs
use std::path::PathBuf;
use refine_mcp::health::compute_health;

#[test]
fn health_for_php_file() {
    // Use an inline PHP snippet
    let source = r#"<?php
class Foo {
    public function simple($x) {
        return $x + 1;
    }

    public function complex($a, $b, $c) {
        if ($a > 0) {
            if ($b > 0) {
                foreach ($c as $item) {
                    if ($item->valid) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
"#;
    let report = compute_health(source, &PathBuf::from("test.php"), "php");
    assert_eq!(report.functions.len(), 2);

    let simple = report.functions.iter().find(|f| f.name == "simple").unwrap();
    assert_eq!(simple.param_count, 1);
    assert!(simple.max_nesting_depth <= 1);

    let complex = report.functions.iter().find(|f| f.name == "complex").unwrap();
    assert_eq!(complex.param_count, 3);
    assert!(complex.max_nesting_depth >= 3); // if > if > foreach > if
    assert!(complex.branch_count >= 3); // 3 if + 1 foreach
}

#[test]
fn health_warns_on_long_function() {
    // A function with many lines should trigger a warning
    let mut lines = String::from("<?php\nfunction longFunc() {\n");
    for i in 0..60 {
        lines.push_str(&format!("    $x{i} = {i};\n"));
    }
    lines.push_str("}\n");

    let report = compute_health(&lines, &PathBuf::from("test.php"), "php");
    assert_eq!(report.functions.len(), 1);
    assert!(report.functions[0].lines > 50);
    assert!(report.warnings.iter().any(|w| w.contains("longFunc")));
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --test health_test 2>&1 | tail -5
```

Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```rust
// src/health.rs
use std::path::Path;

use tree_sitter::Parser;

use crate::types::{FunctionHealth, HealthReport};

/// Compute health metrics for all functions in a source file.
pub fn compute_health(source: &str, file: &Path, lang: &str) -> HealthReport {
    let mut parser = Parser::new();
    let language = match lang {
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "rust" => tree_sitter_rust::LANGUAGE_RUST.into(),
        "typescript" | "tsx" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "python" => tree_sitter_python::LANGUAGE_PYTHON.into(),
        _ => return HealthReport::default(),
    };

    if parser.set_language(&language).is_err() {
        return HealthReport::default();
    }

    let Some(tree) = parser.parse(source, None) else {
        return HealthReport::default();
    };

    let mut report = HealthReport::default();
    let root = tree.root_node();
    let mut cursor = root.walk();

    collect_health_recursive(&mut cursor, source.as_bytes(), file, &mut report);

    // Generate warnings
    for func in &report.functions {
        if func.lines > 50 {
            report.warnings.push(format!(
                "{}: {} is {} lines (consider splitting)",
                file.display(), func.name, func.lines
            ));
        }
        if func.param_count > 5 {
            report.warnings.push(format!(
                "{}: {} has {} parameters (consider a params struct)",
                file.display(), func.name, func.param_count
            ));
        }
        if func.max_nesting_depth > 4 {
            report.warnings.push(format!(
                "{}: {} has nesting depth {} (consider early returns)",
                file.display(), func.name, func.max_nesting_depth
            ));
        }
    }

    report
}

fn collect_health_recursive(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    file: &Path,
    report: &mut HealthReport,
) {
    loop {
        let node = cursor.node();
        let kind = node.kind();

        // Match function/method declarations across languages
        let is_function = matches!(
            kind,
            "function_definition"
                | "method_declaration"
                | "function_item"       // Rust
                | "function_declaration" // TypeScript
                | "arrow_function"      // TypeScript
        );

        if is_function {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or_default();
                if !name.is_empty() {
                    let start_row = node.start_position().row as u32 + 1;
                    let end_row = node.end_position().row as u32 + 1;
                    let lines = end_row.saturating_sub(start_row) + 1;

                    // Count parameters
                    let param_count = node
                        .child_by_field_name("parameters")
                        .or_else(|| node.child_by_field_name("formal_parameters"))
                        .map_or(0, |params| {
                            count_named_children(&params, &[
                                "simple_parameter",
                                "parameter",
                                "formal_parameter",
                                "typed_parameter",
                                "default_parameter",
                                "required_parameter",
                                "optional_parameter",
                            ])
                        });

                    // Compute nesting depth and branch count from body
                    let (max_depth, branch_count) = node
                        .child_by_field_name("body")
                        .map_or((0, 0), |body| compute_complexity(&body));

                    report.functions.push(FunctionHealth {
                        name: name.to_string(),
                        file: file.to_path_buf(),
                        line_range: (start_row, end_row),
                        lines,
                        param_count,
                        max_nesting_depth: max_depth,
                        branch_count,
                    });
                }
            }
        }

        // Recurse (but not into function bodies — we handle those separately)
        if !is_function && cursor.goto_first_child() {
            collect_health_recursive(cursor, source, file, report);
            cursor.goto_parent();
        }

        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// Count named children matching any of the given node kinds.
fn count_named_children(node: &tree_sitter::Node, kinds: &[&str]) -> usize {
    let mut count = 0;
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if kinds.contains(&cursor.node().kind()) {
                count += 1;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    count
}

/// Compute max nesting depth and branch count for a subtree.
fn compute_complexity(node: &tree_sitter::Node) -> (u32, u32) {
    let mut max_depth: u32 = 0;
    let mut branch_count: u32 = 0;
    walk_complexity(node, 0, &mut max_depth, &mut branch_count);
    (max_depth, branch_count)
}

fn walk_complexity(
    node: &tree_sitter::Node,
    current_depth: u32,
    max_depth: &mut u32,
    branch_count: &mut u32,
) {
    let kind = node.kind();

    // Branching constructs that increase nesting
    let is_branch = matches!(
        kind,
        "if_statement"
            | "else_clause"
            | "elseif_clause"
            | "for_statement"
            | "foreach_statement"
            | "while_statement"
            | "do_statement"
            | "switch_statement"
            | "match_expression"
            | "try_statement"
            | "for_expression"      // Rust
            | "while_expression"    // Rust
            | "loop_expression"     // Rust
            | "if_expression"       // Rust
            | "match_arm"           // Rust — each arm is a branch
            | "for_in_statement"    // TS/JS
            | "for_of_statement"    // TS/JS
    );

    let depth = if is_branch {
        *branch_count += 1;
        current_depth + 1
    } else {
        current_depth
    };

    if depth > *max_depth {
        *max_depth = depth;
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            walk_complexity(&cursor.node(), depth, max_depth, branch_count);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}
```

- [ ] **Step 4: Add `health` module to lib.rs**

```rust
// src/lib.rs
pub mod diff;
pub mod facts;
pub mod health;
pub mod types;
```

- [ ] **Step 5: Run tests**

```bash
cargo test --test health_test -v
```

Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/health.rs src/lib.rs tests/health_test.rs
git commit -m "feat: add health snapshot (nesting depth, branch count, line count)"
```

---

## Chunk 5: New MCP Server

### Task 5: Rewrite server.rs with v2 tools

**Files:**
- Rewrite: `src/server.rs`

The new server exposes 5 MCP tools:

| Tool | Description |
|------|------------|
| `structural_diff` | Extract before (git stash) / after facts, compute diff |
| `impact_analysis` | Find callers of changed functions (wraps existing blast_radius) |
| `extract_facts` | Keep as-is — general-purpose tree-sitter extraction |
| `extract_schema` | Keep as-is — Laravel migration parser (renamed from `extract_migration_facts`) |
| `health_snapshot` | Compute per-function health metrics |

- [ ] **Step 1: Write the new server.rs**

```rust
// src/server.rs
use std::path::{Path, PathBuf};

use rmcp::{
    ServerHandler,
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use refine_mcp::diff::{aggregate_diffs, compute_structural_diff};
use refine_mcp::facts::blast_radius;
use refine_mcp::facts::types::FactTable;
use refine_mcp::health::compute_health;

// ─── Tool Parameter Structs ────────────────────────────────────

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct StructuralDiffParams {
    /// File paths to analyze.
    pub file_paths: Vec<String>,
    /// Git ref for "before" version (default: "HEAD")
    pub base_ref: Option<String>,
    /// Git ref for "after" version. If omitted, uses working tree.
    pub compare_ref: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ImpactAnalysisParams {
    /// Function/method names to search for callers.
    /// If empty, auto-detects changed symbols from git diff.
    pub symbols: Option<Vec<String>>,
    /// Directories to search (default: ["app/", "routes/", "src/"])
    pub search_paths: Option<Vec<String>>,
    /// Files to exclude from results
    pub exclude_files: Option<Vec<String>>,
    /// Source files for auto-detecting changed symbols via git diff
    pub source_files: Option<Vec<String>>,
    /// Max results per symbol (default: 20)
    pub max_per_symbol: Option<usize>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ExtractFactsParams {
    /// List of file paths to analyze
    pub file_paths: Vec<String>,
    /// If true, filter to only files changed in git diff HEAD
    pub diff_only: Option<bool>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ExtractSchemaParams {
    /// Path to migration directory (default: database/migrations)
    pub migration_dir: Option<String>,
    /// Only include tables matching these names
    pub table_filter: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct HealthSnapshotParams {
    /// File paths to analyze
    pub file_paths: Vec<String>,
}

// ─── Server ────────────────────────────────────────────────────

pub struct RefineServer;

impl RefineServer {
    pub fn new() -> Self {
        Self
    }
}

#[tool_router]
impl RefineServer {
    /// Compare function signatures between git HEAD and working tree.
    /// Returns added, removed, and changed functions with breaking change detection.
    #[tool]
    async fn structural_diff(
        &self,
        #[tool(params)] params: Parameters<StructuralDiffParams>,
    ) -> CallToolResult {
        let params = params.inner();
        let base_ref = params.base_ref.as_deref().unwrap_or("HEAD");
        let mut all_diffs = Vec::new();

        for file_path in &params.file_paths {
            let path = PathBuf::from(file_path);

            // Get "before" version from git
            let before_source = get_git_file_content(file_path, base_ref);
            // Get "after" version from working tree
            let after_source = std::fs::read_to_string(&path).unwrap_or_default();

            if before_source.is_empty() && after_source.is_empty() {
                continue;
            }

            let lang = detect_language(file_path);
            let before_facts = extract_functions(&before_source, lang);
            let after_facts = extract_functions(&after_source, lang);

            let diff = compute_structural_diff(&path, &before_facts, &after_facts);
            if !diff.added.is_empty() || !diff.removed.is_empty() || !diff.changed.is_empty() {
                all_diffs.push(diff);
            }
        }

        let report = aggregate_diffs(all_diffs);
        let json = serde_json::to_string_pretty(&report).unwrap_or_default();
        CallToolResult::success(vec![Content::text(json)])
    }

    /// Find callers of specified functions across the codebase.
    /// Auto-detects changed function names from git diff if symbols not provided.
    #[tool]
    async fn impact_analysis(
        &self,
        #[tool(params)] params: Parameters<ImpactAnalysisParams>,
    ) -> CallToolResult {
        let params = params.inner();

        let symbols = if let Some(syms) = &params.symbols {
            if syms.is_empty() {
                auto_detect_symbols(&params.source_files)
            } else {
                syms.clone()
            }
        } else {
            auto_detect_symbols(&params.source_files)
        };

        if symbols.is_empty() {
            return CallToolResult::success(vec![Content::text(
                "{\"error\": \"No symbols to analyze. Provide symbols or source_files with git changes.\"}",
            )]);
        }

        let search_paths: Vec<PathBuf> = params
            .search_paths
            .as_deref()
            .unwrap_or(&["app/".to_string(), "routes/".to_string(), "src/".to_string()])
            .iter()
            .map(PathBuf::from)
            .collect();

        let exclude: Vec<PathBuf> = params
            .exclude_files
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(PathBuf::from)
            .collect();

        let max = params.max_per_symbol.unwrap_or(20);

        let result = blast_radius::expand_blast_radius(&symbols, &search_paths, &exclude, max);
        let json = serde_json::to_string_pretty(&result).unwrap_or_default();
        CallToolResult::success(vec![Content::text(json)])
    }

    /// Extract structured facts from source files using tree-sitter.
    /// Returns function signatures, parameters, transactions, locks, catch blocks, etc.
    #[tool]
    async fn extract_facts(
        &self,
        #[tool(params)] params: Parameters<ExtractFactsParams>,
    ) -> CallToolResult {
        let params = params.inner();
        let mut file_paths: Vec<String> = params.file_paths.clone();

        if params.diff_only.unwrap_or(false) {
            file_paths = filter_to_changed_files(&file_paths);
        }

        let mut tables: Vec<FactTable> = Vec::new();
        for path_str in &file_paths {
            let path = Path::new(path_str);
            let Ok(source) = std::fs::read_to_string(path) else {
                continue;
            };
            let lang = detect_language(path_str);
            if let Some(table) = extract_fact_table(path, &source, lang) {
                tables.push(table);
            }
        }

        let json = serde_json::to_string_pretty(&tables).unwrap_or_default();
        CallToolResult::success(vec![Content::text(json)])
    }

    /// Parse Laravel migration files to extract database schema.
    /// Returns column types, nullable, defaults, foreign keys, indexes.
    #[tool]
    async fn extract_schema(
        &self,
        #[tool(params)] params: Parameters<ExtractSchemaParams>,
    ) -> CallToolResult {
        let params = params.inner();
        let migration_dir = params.migration_dir.as_deref().unwrap_or("database/migrations");
        let table_filter = params.table_filter.as_deref().unwrap_or(&[]);

        let snapshot =
            refine_mcp::facts::migration::extract_migration_facts(migration_dir, table_filter);
        let json = serde_json::to_string_pretty(&snapshot).unwrap_or_default();
        CallToolResult::success(vec![Content::text(json)])
    }

    /// Compute per-function health metrics: line count, parameter count,
    /// nesting depth, and branch count. Generates warnings for functions
    /// exceeding thresholds.
    #[tool]
    async fn health_snapshot(
        &self,
        #[tool(params)] params: Parameters<HealthSnapshotParams>,
    ) -> CallToolResult {
        let params = params.inner();
        let mut all_functions = Vec::new();
        let mut all_warnings = Vec::new();

        for path_str in &params.file_paths {
            let path = PathBuf::from(path_str);
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            let lang_str = detect_language(path_str);
            let report = compute_health(&source, &path, lang_str);
            all_functions.extend(report.functions);
            all_warnings.extend(report.warnings);
        }

        let report = refine_mcp::types::HealthReport {
            functions: all_functions,
            warnings: all_warnings,
        };
        let json = serde_json::to_string_pretty(&report).unwrap_or_default();
        CallToolResult::success(vec![Content::text(json)])
    }
}

impl ServerHandler for RefineServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Structural change impact analyzer. Use structural_diff to detect \
                 breaking changes, impact_analysis to find affected callers, \
                 health_snapshot for code complexity metrics, extract_facts for \
                 tree-sitter analysis, and extract_schema for Laravel migrations."
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ─── Helpers ───────────────────────────────────────────────────

fn detect_language(path: &str) -> &str {
    if path.ends_with(".php") {
        "php"
    } else if path.ends_with(".rs") {
        "rust"
    } else if path.ends_with(".ts") || path.ends_with(".tsx") {
        "typescript"
    } else if path.ends_with(".py") {
        "python"
    } else {
        "unknown"
    }
}

fn get_git_file_content(path: &str, git_ref: &str) -> String {
    let output = std::process::Command::new("git")
        .args(["show", &format!("{git_ref}:{path}")])
        .output();

    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => String::new(), // File doesn't exist in git (new file)
    }
}

fn extract_functions(source: &str, lang: &str) -> Vec<refine_mcp::facts::types::FunctionFact> {
    if source.is_empty() {
        return Vec::new();
    }
    let path = Path::new("temp");
    extract_fact_table(path, source, lang)
        .map(|t| t.functions)
        .unwrap_or_default()
}

fn extract_fact_table(
    path: &Path,
    source: &str,
    lang: &str,
) -> Option<FactTable> {
    match lang {
        "php" => Some(refine_mcp::facts::php::extract_php_facts(path, source)),
        "rust" => Some(refine_mcp::facts::rust_lang::extract_rust_facts(path, source)),
        "typescript" => Some(refine_mcp::facts::typescript::extract_typescript_facts(path, source)),
        "python" => Some(refine_mcp::facts::python::extract_python_facts(path, source)),
        _ => None,
    }
}

fn filter_to_changed_files(paths: &[String]) -> Vec<String> {
    let output = std::process::Command::new("git")
        .args(["diff", "HEAD", "--name-only"])
        .output();

    let changed: Vec<String> = match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(String::from)
                .collect()
        }
        _ => return paths.to_vec(),
    };

    paths
        .iter()
        .filter(|p| changed.iter().any(|c| p.ends_with(c) || c.ends_with(p.as_str())))
        .cloned()
        .collect()
}

fn auto_detect_symbols(source_files: &Option<Vec<String>>) -> Vec<String> {
    let files: Vec<PathBuf> = source_files
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(PathBuf::from)
        .collect();

    blast_radius::extract_changed_symbols(&files)
}
```

- [ ] **Step 2: Verify the public API of fact extractors matches**

The server calls these functions — verify they exist with the right signatures:
- `refine_mcp::facts::php::extract_php_facts(path: &Path, source: &str) -> FactTable`
- `refine_mcp::facts::rust_lang::extract_rust_facts(path: &Path, source: &str) -> FactTable`
- `refine_mcp::facts::typescript::extract_typescript_facts(path: &Path, source: &str) -> FactTable`
- `refine_mcp::facts::python::extract_python_facts(path: &Path, source: &str) -> FactTable`
- `refine_mcp::facts::migration::extract_migration_facts(dir: &str, filter: &[String]) -> SchemaSnapshot`

```bash
grep "^pub fn extract_" src/facts/php.rs src/facts/rust_lang.rs src/facts/typescript.rs src/facts/python.rs src/facts/migration.rs
```

If any signatures don't match, adjust the server.rs calls accordingly.

- [ ] **Step 3: Build and fix any compilation errors**

```bash
cargo build 2>&1
```

Fix any issues. Common ones:
- Import paths may need adjustment
- `migration::extract_migration_facts` signature may differ (check actual params)

- [ ] **Step 4: Run all existing tests to verify nothing broke**

```bash
cargo test 2>&1
```

Expected: All existing extract_php, extract_rust, self_analysis tests still pass.

- [ ] **Step 5: Commit**

```bash
git add src/server.rs
git commit -m "feat: rewrite MCP server with v2 tools (structural_diff, impact_analysis, health_snapshot)"
```

---

## Chunk 6: Update Cargo.toml and README

### Task 6: Update project metadata

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Update Cargo.toml description and keywords**

Change:
```toml
description = "Grounded red-blue adversarial plan refinement via MCP — tree-sitter fact extraction + LLM red/blue team analysis"
keywords = ["mcp", "code-review", "security", "tree-sitter", "red-team"]
```
To:
```toml
description = "Structural change impact analyzer via MCP — tree-sitter powered diff, blast radius, and code health"
keywords = ["mcp", "code-analysis", "tree-sitter", "structural-diff", "code-health"]
```

- [ ] **Step 2: Remove unused dependencies**

`strsim` was only used by `dedup/mod.rs`. Remove it:
```toml
# Remove this line:
strsim = "0.11"
# Also remove if no longer needed:
time = { version = "0.3", features = ["formatting"] }
```

Check if `time` is still used anywhere:
```bash
grep -r "use time" src/ --include="*.rs"
```

- [ ] **Step 3: Build to verify**

```bash
cargo build
cargo test
```

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml
git commit -m "chore: update project metadata and remove unused dependencies"
```

---

## Chunk 7: Update Claude Code Integration

### Task 7: Update CLAUDE.md refine rules

**Files:**
- Modify: `/home/www/.claude/CLAUDE.md` (section 13)

- [ ] **Step 1: Replace section 13 with v2 usage**

Replace the entire "Refine MCP" section with:

```markdown
## 13. Refine MCP — 結構變更影響分析

完成程式碼修改後，可使用 refine 工具分析結構變更：

### 工具一覽

| 工具 | 用途 | 何時使用 |
|------|------|---------|
| `structural_diff` | AST 級 before/after 比對 | 改完 code 想知道破壞了什麼 |
| `impact_analysis` | 找出所有 callers | 改了 function signature 後 |
| `health_snapshot` | 函數複雜度指標 | 重構前後比對 |
| `extract_facts` | 通用 tree-sitter 分析 | 需要結構化 code metadata |
| `extract_schema` | Laravel migration 解析 | DB schema 變更分析 |

### 使用時機

- **改了 function signature** → `structural_diff` + `impact_analysis`
- **重構** → `health_snapshot`（前後比對）
- **不確定影響範圍** → `impact_analysis`

### 不需要使用的場景

- 純 UI/CSS 調整
- 文件/註解修改
- 不改 signature 的 bug fix
```

- [ ] **Step 2: Commit**

```bash
git add /home/www/.claude/CLAUDE.md
git commit -m "docs: update CLAUDE.md refine section for v2 structural analyzer"
```

---

## Post-Implementation Verification

After all tasks complete:

```bash
# Full test suite
cargo test

# Verify binary starts
echo '{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{}},"id":1}' | cargo run 2>/dev/null | head -1

# Verify tool list includes v2 tools
echo '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}' | cargo run 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -o '"name": "[^"]*"'
```

Expected output should show: `structural_diff`, `impact_analysis`, `extract_facts`, `extract_schema`, `health_snapshot`
