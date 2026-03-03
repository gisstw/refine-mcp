# refine-mcp

**Grounded red-blue adversarial plan refinement via MCP.**

[繁體中文說明](docs/README_zh-TW.md)

Tree-sitter extracts structured facts from your code. LLM red teams find vulnerabilities in those facts. A blue team cross-analyzes and filters false positives. All orchestrated through the [Model Context Protocol](https://modelcontextprotocol.io/).

## How It Works

```
Source Code                    LLM Red Teams (2-4)
    │                               │
    ▼                               ▼
┌─────────────┐  fact tables  ┌───────────────┐  raw findings
│ tree-sitter │──────────────▶│  RT-A  RT-B   │─────────────┐
│  extractor  │               │  RT-C  RT-D   │             │
└─────────────┘               └───────────────┘             │
                                                            ▼
Plan File ─────────────────────────────────────▶ ┌─────────────────┐
                                                 │    Synthesize    │
                                                 │ dedup + validate │
                                                 │  + rank + score  │
                                                 └────────┬────────┘
                                                          │
                                                          ▼
                                                 ┌─────────────────┐
                                                 │    Blue Team     │
                                                 │ cross-analysis + │
                                                 │  false positive  │
                                                 └────────┬────────┘
                                                          │
                                                          ▼
                                                   Final Report
```

**Key insight**: LLMs are good at *reasoning* about code but expensive at *reading* it. Tree-sitter reads the code (free, 100% accurate), then LLMs only reason about the structured facts (small input, focused output). This cuts red team tokens by ~66% and blue team tokens by ~80%.

## Supported Languages

| Language | Extractor | Grammar |
|----------|-----------|---------|
| PHP | `extract_php_facts` | tree-sitter-php 0.24 |
| Rust | `extract_rust_facts` | tree-sitter-rust 0.23 |
| TypeScript/JavaScript | `extract_ts_facts` | tree-sitter-typescript 0.23 |
| Python | `extract_python_facts` | tree-sitter-python 0.23 |

Each extractor produces a `FactTable` containing per-function analysis:
- **Transactions** — DB transaction boundaries and lock-for-update usage
- **Locks** — Concurrency locks (DB locks, cache locks, shared locks)
- **Catch blocks** — Exception handling with action classification (rethrow, log, silent swallow)
- **External calls** — API/network calls, especially those inside transactions
- **State mutations** — Create/Update/Delete operations with targets
- **Null risks** — Potential null dereference / unwrap / panic sites
- **Parameters** — Function parameters with type hints and nullability

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

### Basic workflow

The typical refinement pipeline has 5 steps (or 4 with the combined tool):

```
1. discover_plan        → Find plan file, extract file references
2. extract_facts        → Run tree-sitter on referenced files
3. prepare_attack       → Generate red team prompts from facts
   (run 2-4 LLM agents with the generated prompts)
4. synthesize_findings  → Parse red team output, dedup, rank, generate blue prompt
   (run 1 LLM agent with the blue prompt)
5. finalize_refinement  → Append findings to plan file
```

Or use `discover_and_extract` to combine steps 1+2 into a single call.

## MCP Tools

### discover_plan

Find the most recently modified plan file and extract source file references.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `plan_dir` | string | No | Directory to search (default: `.claude/plans/`) |

### extract_facts

Run tree-sitter analysis on source files.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_paths` | string[] | Yes | Absolute paths to source files |
| `diff_only` | bool | No | If true, only analyze git-changed files |

### discover_and_extract

Combined discover + extract in one call.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `plan_dir` | string | No | Directory to search |
| `diff_only` | bool | No | Only analyze git-changed files |

### prepare_attack

Generate red team prompts from plan content and fact tables.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `plan_path` | string | Yes | Path to the plan file |
| `facts_json` | string | Yes | JSON-encoded fact tables from extract_facts |
| `mode` | string | No | `default` (opus), `lite` (sonnet), or `auto` (haiku) |
| `red_count` | u8 | No | Number of red teams (2-4). If omitted, auto-selected from facts |

### synthesize_findings

Parse red team markdown output, deduplicate, validate, rank, and generate blue team prompt.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `raw_reports` | string[] | Yes | Raw markdown output from each red team agent |
| `plan_path` | string | No | Plan file path (for persistent state) |
| `plan_summary` | string | No | Brief plan summary for blue team context |
| `mode` | string | No | Cost mode for blue team model recommendation |

### finalize_refinement

Backup the plan file and append a refinement section with findings.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `plan_path` | string | Yes | Plan file to append to |
| `blue_result` | string | No | Blue team analysis output |
| `findings_json` | string | Yes | JSON-encoded findings from synthesize |
| `mode` | string | No | Cost mode |

## Red Team Roles

| ID | Name | Focus | When Auto-Selected |
|----|------|-------|--------------------|
| RT-A | Single-Op | Silent failure, type safety, idempotency | Always |
| RT-B | Multi-Op | Concurrency races, TOCTOU, behavioral change | Always |
| RT-C | Data Integrity | Schema drift, constraint violations, partial writes | Mutations without transaction, external calls in TX, silent swallows |
| RT-D | Auth Boundary | Permission checks, IDOR, privilege escalation | File paths contain auth/permission/middleware/login/session/guard/policy/role/access/token |

When `red_count` is omitted from `prepare_attack`, the tool automatically selects which red teams to run based on signals in the extracted facts. RT-A and RT-B always run; RT-C and RT-D are added only when the facts suggest they would find real issues.

## Modes

| Mode | Red Team Model | Blue Team Model | Use Case |
|------|---------------|-----------------|----------|
| `default` | opus | opus | Maximum accuracy |
| `lite` | sonnet | sonnet | Good balance of cost and quality |
| `auto` | haiku | haiku | Quick screening, lowest cost |

## Deduplication & Scoring

Findings are deduplicated by:
- **Same file + overlapping line ranges** → merged
- **Same file + similar titles** (≥85% Levenshtein similarity) → merged

Impact score = `severity_weight × domain_weight / 10 + source_bonus`

- Severity: Fatal=100, High=60
- Domain weight: Payment/Billing (30) > Services (20) > Controllers (15) > Models (12) > Default (10) > Views (5) > Config/Test (3)
- Source bonus: +20 if confirmed by multiple red teams

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
