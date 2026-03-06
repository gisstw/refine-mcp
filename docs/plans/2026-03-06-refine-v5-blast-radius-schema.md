# Refine v5 Design: Blast Radius + Schema Facts

> Date: 2026-03-06 | Status: Approved

## Problem

Refine v4 only analyzes files explicitly listed in the plan. Hidden callers and DB schema constraints are invisible to red teams, causing "fix here, break there" to slip through.

## Solution: 2 New MCP Tools

### Tool A: `expand_blast_radius`

Given modified function names (auto-detected from `git diff`), find all callers via `grep -rn`.

**Input:**
```json
{
  "symbols": ["createMainBill", "processPayment"],
  "search_paths": ["app/", "routes/"],
  "exclude_files": ["app/Services/BillingService.php"],
  "max_results_per_symbol": 20
}
```

**Output:**
```json
{
  "call_graph": {
    "createMainBill": [
      {"file": "app/Services/WalkinBetaService.php", "line": 142, "context": "$this->billingService->createMainBill($orderSerial)"}
    ]
  },
  "expanded_files": ["app/Services/WalkinBetaService.php"],
  "total_callers": 3
}
```

**Symbol auto-detection strategy:**
1. Run `git diff HEAD` to get changed hunks
2. From changed hunks, extract function names using tree-sitter (match `method_declaration` nodes whose line range overlaps the diff)
3. Only track functions whose **signature** changed (params, return type) — body-only changes don't break callers
4. Fallback: if no git diff available, extract all public function names from plan-referenced files

**Implementation:** Spawn `grep -rnw` for each symbol. Parse `file:line:context` output. Deduplicate files. ~200ms for 5 symbols across 2K files.

### Tool B: `extract_migration_facts`

Parse all Laravel migration files to build a schema snapshot.

**Input:**
```json
{
  "migration_dir": "database/migrations"
}
```

**Output:**
```json
{
  "schema": {
    "reservations": {
      "columns": [
        {"name": "id", "type": "increments", "nullable": false},
        {"name": "status", "type": "tinyInteger", "nullable": false, "default": "1"},
        {"name": "arrival", "type": "date", "nullable": false}
      ],
      "foreign_keys": [
        {"column": "Rt_id", "references_table": "room_type", "references_column": "id"}
      ],
      "indexes": ["idx_status_arrival"],
      "source_file": "2024_01_01_000000_create_reservations_table.php"
    }
  },
  "type_warnings": [
    "pricing_deposit.price: VARCHAR used for price column (arithmetic risk)",
    "pricing_deposit.type: ENUM('1','2','3') — writing '5' is silently invalid"
  ],
  "table_count": 35,
  "column_count": 280
}
```

**Implementation:**
- tree-sitter PHP parse each migration file
- Walk AST for `Schema::create`/`Schema::table` calls
- Extract `$table->string('name')`, `$table->integer('count')` etc.
- Generate type_warnings for known risky patterns (VARCHAR for price, ENUM with numeric strings)
- Cache result in memory (same process lifetime) — migrations rarely change mid-session

## Data Flow Changes

### New types in `facts/types.rs`

```rust
pub struct CallerFact {
    pub symbol: String,
    pub caller_file: PathBuf,
    pub caller_line: u32,
    pub context: String,
}

pub struct SchemaSnapshot {
    pub tables: Vec<SchemaTable>,
    pub type_warnings: Vec<String>,
}

pub struct SchemaTable {
    pub table_name: String,
    pub columns: Vec<ColumnFact>,
    pub foreign_keys: Vec<ForeignKeyFact>,
    pub indexes: Vec<String>,
    pub source_file: PathBuf,
}

pub struct ColumnFact {
    pub name: String,
    pub col_type: String,
    pub nullable: bool,
    pub has_default: bool,
    pub default_value: Option<String>,
}

pub struct ForeignKeyFact {
    pub column: String,
    pub references_table: String,
    pub references_column: String,
    pub on_delete: Option<String>,
}
```

### FactTable extension

```rust
pub struct FactTable {
    // ...existing...
    #[serde(default)]
    pub callers: Vec<CallerFact>,  // NEW: populated by expand_blast_radius
}
```

### prepare_attack changes

The `prepare_attack` tool accepts an optional `schema_json` parameter:

```rust
pub struct PrepareAttackParams {
    // ...existing...
    pub schema_json: Option<String>,  // NEW: from extract_migration_facts
}
```

Schema is injected into red team prompts as a new section: `### Database Schema`.

### Red team template additions

RT-A gets:
```markdown
### Blast Radius
9. `callers` — if a function signature changes, do all callers handle the new signature?
   - Parameter type/count changes → callers passing wrong args
   - Return semantics change (throw→return error) → callers not checking

### Schema Constraints
10. `schema_tables` — do mutations match column types?
    - VARCHAR column used in arithmetic?
    - NOT NULL column without value in create()?
    - ENUM column with value outside allowed set?
```

RT-B gets:
```markdown
### Cross-Caller Conflicts
9. `callers` — can two callers invoke the same function concurrently with conflicting expectations?
   - Caller A expects old return type, Caller B expects new

### Schema Race Conditions
10. FK constraints + concurrent deletes → integrity violation?
```

## Token Budget

| Component | Tokens added to prompt | Notes |
|-----------|----------------------|-------|
| CallerFacts (5 symbols × 4 callers avg) | ~400 | 1 line context each |
| SchemaSnapshot (10 relevant tables) | ~800 | Only tables referenced in mutations |
| Template additions | ~200 | 2 new sections per RT |
| **Total** | **~1,400** | <10% increase over current ~15K prompt |

Key optimization: `prepare_attack` only injects schema tables that are referenced by `state_mutations.target` in the fact tables, not the full 35-table schema.

## Workflow (refine-plan.md skill update)

```
Step 1:   discover_and_extract(plan_dir, diff_only)
Step 1.5: expand_blast_radius(auto-detected symbols)     ← NEW
Step 1.6: extract_migration_facts(migration_dir)          ← NEW
Step 2:   extract_facts(original_files + expanded_files)   ← EXPANDED
Step 3:   prepare_attack(plan, facts, schema, mode)        ← SCHEMA ADDED
Step 4-6: (unchanged)
```

## File Changes Summary

| File | Change |
|------|--------|
| `src/facts/types.rs` | Add CallerFact, SchemaSnapshot, SchemaTable, ColumnFact, ForeignKeyFact |
| `src/facts/mod.rs` | Add `pub mod migration;` and `pub mod blast_radius;` |
| `src/facts/blast_radius.rs` | NEW: grep-based caller search + git diff symbol detection |
| `src/facts/migration.rs` | NEW: migration file parser |
| `src/server.rs` | Add expand_blast_radius + extract_migration_facts tools |
| `src/prompts/mod.rs` | Inject callers + schema into prompts |
| `templates/rt_a_single_op.md` | Add Blast Radius + Schema sections |
| `templates/rt_b_multi_op.md` | Add Cross-Caller + Schema Race sections |
| `Cargo.toml` | No new deps needed (grep via std::process, tree-sitter-php already present) |
| `.claude/skills/refine-plan.md` | Add Steps 1.5 and 1.6 |

## Test Plan

1. Unit: `blast_radius::parse_grep_output` with sample grep output
2. Unit: `blast_radius::extract_changed_symbols` with sample git diff
3. Unit: `migration::parse_migration` with sample Laravel migration
4. Unit: `migration::detect_type_warnings` for VARCHAR price, ENUM pitfalls
5. Integration: `expand_blast_radius` tool with PMS `app/Services/BillingService.php`
6. Integration: `extract_migration_facts` with PMS `database/migrations/`
7. E2E: Full refine run with blast radius — verify callers appear in red team findings
