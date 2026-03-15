English | [繁體中文](README_zh-TW.md)

# refine-mcp

**Know exactly what you broke — before you commit.**

Tree-sitter extracts structural facts from your code (function signatures, parameters, return types). When you change code, refine-mcp compares before/after AST structures to detect breaking changes, find affected callers, and measure code health. All orchestrated through the [Model Context Protocol](https://modelcontextprotocol.io/).

## How It Works

```
 Your Code Changes
       │
       ▼
┌─────────────────┐     ┌──────────────────┐
│   tree-sitter   │────▶│  structural_diff  │──▶ Breaking changes
│   (4 languages) │     │  (before/after)   │    (signature changes,
└─────────────────┘     └──────────────────┘     added/removed funcs)
       │
       ├──────────────▶ ┌──────────────────┐
       │                │ impact_analysis   │──▶ Affected callers
       │                │ (blast radius)    │    (who calls what you changed)
       │                └──────────────────┘
       │
       └──────────────▶ ┌──────────────────┐
                        │ health_snapshot   │──▶ Complexity metrics
                        │ (per-function)    │    (nesting, branches, params)
                        └──────────────────┘
```

**Key insight**: LLMs read code like humans — they can miss structural changes in large files. Tree-sitter parses the AST (free, 100% accurate) and catches every signature change, removed function, and added parameter that an LLM might overlook.

## Why This Tool?

| Capability | LLM (1M context) | grep/ripgrep | refine-mcp |
|-----------|------------------|-------------|------------|
| Detect signature change | May miss in large files | Can't (text-level) | **100% accurate (AST)** |
| Find all callers | May miss some | String match (false positives) | Grep + definition filtering |
| Measure complexity | Estimates | Can't | **Precise tree-sitter metrics** |
| Compare git refs | Must read both versions | Text diff only | **AST-level structural diff** |
| Speed | Seconds (reads files) | Fast | **Instant (tree-sitter)** |

## Supported Languages

| Language | Extractor | Grammar |
|----------|-----------|---------|
| PHP | `extract_php_facts` | tree-sitter-php 0.24 |
| Rust | `extract_rust_facts` | tree-sitter-rust 0.23 |
| TypeScript/JavaScript | `extract_ts_facts` | tree-sitter-typescript 0.23 |
| Python | `extract_python_facts` | tree-sitter-python 0.23 |

## Installation

### From source

```bash
git clone https://github.com/gisstw/refine-mcp.git
cd refine-mcp
cargo build --release
# Binary at target/release/refine-mcp
```

### With cargo

```bash
cargo install refine-mcp
```

## Quick Start

### Claude Code MCP configuration

Add to your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "refine": {
      "command": "/path/to/refine-mcp"
    }
  }
}
```

### Typical workflow

```
1. Change some code
2. structural_diff   → What signatures changed? Any breaking changes?
3. impact_analysis   → Who calls the functions I changed?
4. health_snapshot   → Did the code get more complex?
5. Fix issues, commit with confidence
```

## MCP Tools

### structural_diff

Compare function signatures between two git refs (or git ref vs working tree). Detects added, removed, and changed functions with breaking change classification.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_paths` | string[] | Yes | Files to analyze |
| `base_ref` | string | No | Git ref for "before" (default: `HEAD`) |
| `compare_ref` | string | No | Git ref for "after" (default: working tree) |

**Breaking change detection:**
- Return type changed
- Parameter added/removed
- Parameter type changed
- Parameter order changed
- Nullable → non-nullable

### impact_analysis

Find callers of specified functions across the codebase. Auto-detects changed symbols from git diff if not provided.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `symbols` | string[] | No | Function names to search. Auto-detected from git diff if omitted |
| `search_paths` | string[] | No | Directories to search (default: `["app/", "routes/", "src/"]`) |
| `exclude_files` | string[] | No | Files to exclude from results |
| `source_files` | string[] | No | Source files for auto-detecting changed symbols |
| `max_per_symbol` | number | No | Max results per symbol (default: 20) |

### extract_facts

Run tree-sitter analysis on source files. Returns per-function structured facts:

- **Transactions** — DB transaction boundaries and lock-for-update usage
- **Locks** — Concurrency locks (DB locks, cache locks, shared locks)
- **Catch blocks** — Exception handling with action classification
- **External calls** — API/network calls, especially those inside transactions
- **State mutations** — Create/Update/Delete operations with targets
- **Null risks** — Potential null dereference / unwrap / panic sites
- **Parameters** — Function parameters with type hints and nullability

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_paths` | string[] | Yes | Paths to source files |
| `diff_only` | bool | No | If true, only analyze git-changed files |

### extract_schema

Parse Laravel migration files to extract database schema.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `migration_dir` | string | No | Path to migrations (default: `database/migrations`) |

### health_snapshot

Compute per-function health metrics with automatic warnings.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_paths` | string[] | Yes | Files to analyze |

**Metrics per function:**
- Line count (warns > 50)
- Parameter count (warns > 5)
- Max nesting depth (warns > 4)
- Branch count (if/for/while/match/switch)

## Example Output

### structural_diff

```json
{
  "files": [{
    "file": "app/Services/BillingService.php",
    "added": [],
    "removed": [{"name": "legacyProcess", "line_range": [42, 60]}],
    "changed": [{
      "name": "processPayment",
      "breaking": true,
      "reasons": [
        "return type changed: Some(\"bool\") → Some(\"PaymentResult\")",
        "parameter added: $note"
      ],
      "before": {"name": "processPayment", "params": [{"name": "$order", "type_hint": "Order"}], "return_type": "bool"},
      "after": {"name": "processPayment", "params": [{"name": "$order", "type_hint": "Order"}, {"name": "$note", "type_hint": "?string"}], "return_type": "PaymentResult"}
    }],
    "unchanged_count": 8
  }],
  "total_added": 0,
  "total_removed": 1,
  "total_changed": 1,
  "breaking_changes": 1
}
```

### health_snapshot

```json
{
  "functions": [{
    "name": "processPayment",
    "file": "app/Services/BillingService.php",
    "line_range": [42, 98],
    "lines": 57,
    "param_count": 2,
    "max_nesting_depth": 4,
    "branch_count": 6
  }],
  "warnings": [
    "app/Services/BillingService.php: processPayment is 57 lines (consider splitting)"
  ]
}
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
