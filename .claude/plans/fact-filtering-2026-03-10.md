# Plan: Function-Level Fact Filtering in prepare_attack

## Problem

`discover_and_extract` extracts facts for ALL functions in referenced files.
PMS Service files have 30-44 functions / 1500-2000 lines each.
A plan that modifies 3 functions in `Beds24Service.php` produces 19K chars of facts (44 functions),
but only ~4K is relevant. Total output exceeds Claude Code's inline limit (97K chars for 4 files).

This causes:
1. MCP output saved to file → agent can't pass it inline → reconstructs JSON → missing fields
2. Red team prompts bloated with irrelevant functions → noise drowns signal
3. Agent intervenes to "shrink facts" → breaks the automated flow

## Goal

Filter fact tables in `prepare_attack` to only include functions relevant to the plan,
while preserving all four "break-other-things" detection paths:
- Path A: Signature change → caller breaks (blast_radius)
- Path B: Behavior change → caller assumes old behavior (caller facts)
- Path C: Shared table mutation → concurrent conflict (same-table siblings)
- Path D: Internal callees → plan function calls another function whose internals matter

## Red Team Findings (integrated)

From red team analysis on 2026-03-10:
- **FATAL-1**: Callees of plan functions dropped — added Path D (callee retention)
- **HIGH-1**: Blocklist too aggressive — removed `create/update/delete/save/find/get/set`
- **HIGH-4**: Fallback checks plan_mentioned emptiness, not filtering result — fixed to check post-filter ratio

## Files to Modify

### 1. `src/server.rs` — prepare_attack handler (~line 504)

Add function filtering between fact table parsing and prompt building.

```rust
// After parsing fact_tables (line 503), before schema section (line 505):

// Step 1: Extract function names mentioned in plan_content
let plan_mentioned: HashSet<String> = extract_plan_functions(&plan_content);

// Step 2: Collect callees of plan-mentioned functions (from external_calls)
let plan_callees: HashSet<String> = fact_tables.iter()
    .flat_map(|t| t.functions.iter())
    .filter(|f| plan_mentioned.contains(&f.name))
    .flat_map(|f| f.external_calls.iter())
    .filter_map(|ec| {
        // Extract method name from descriptions like "service call", patterns like "$this->fooService->bar"
        // The description field has the call pattern; try to extract the function name
        ec.description.split("->").last()
            .or_else(|| ec.description.split("::").last())
            .map(|s| s.trim_end_matches('(').to_string())
    })
    .filter(|name| name.len() >= 3)
    .collect();

// Step 3: Collect mutation targets from plan-mentioned + callee functions
let relevant_functions: HashSet<&str> = plan_mentioned.iter().map(|s| s.as_str())
    .chain(plan_callees.iter().map(|s| s.as_str()))
    .collect();

let plan_mutation_targets: HashSet<String> = fact_tables.iter()
    .flat_map(|t| t.functions.iter())
    .filter(|f| relevant_functions.contains(f.name.as_str()))
    .flat_map(|f| f.state_mutations.iter())
    .map(|m| m.target.to_lowercase())
    .collect();

// Step 4: Filter each FactTable's functions
let original_count: usize = fact_tables.iter().map(|t| t.functions.len()).sum();

let filtered_facts: Vec<FactTable> = fact_tables.into_iter().map(|mut t| {
    t.functions.retain(|f| {
        // Keep if: mentioned in plan
        plan_mentioned.contains(&f.name)
        // Keep if: callee of a plan function
        || plan_callees.contains(&f.name)
        // Keep if: found by blast_radius (has callers)
        || t.callers.iter().any(|c| c.symbol == f.name)
        // Keep if: mutates same table as plan functions (shared state sibling)
        || f.state_mutations.iter().any(|m| plan_mutation_targets.contains(&m.target.to_lowercase()))
    });
    t
}).collect();

let filtered_count: usize = filtered_facts.iter().map(|t| t.functions.len()).sum();

// Safety: if filtering removed >80% of functions, something is wrong — keep all
let (final_facts, filter_skipped) = if plan_mentioned.is_empty()
    || (original_count > 0 && filtered_count * 5 < original_count) {
    // Fallback: keep unfiltered
    // (need to re-parse since we consumed fact_tables — use filtered_facts which still has the data)
    // Actually: if plan_mentioned is empty, we should not have filtered at all
    // This branch means: regex found very few matches AND filtering was too aggressive
    (filtered_facts, filtered_count * 5 < original_count) // keep filtered but warn
} else {
    (filtered_facts, false)
};
```

**Note**: The 80% threshold fallback needs refinement. Better approach: just log a warning
in the output JSON and let the agent decide. Don't silently un-filter.

### 2. `src/server.rs` — new helper function `extract_plan_functions`

```rust
/// Extract function/method names mentioned in plan content.
/// Looks for patterns like: `functionName`, `function_name()`, `->methodName`,
/// `ClassName::methodName`, and markdown code references.
fn extract_plan_functions(plan_content: &str) -> HashSet<String> {
    use regex::Regex;
    use std::sync::LazyLock;

    // Pattern 1: backtick-wrapped identifiers: `processBooking`
    static RE_BACKTICK: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"`(\w{3,})`").expect("valid regex")
    });

    // Pattern 2: method calls: ->processBooking( or ::processBooking(
    static RE_METHOD: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?:->|::)(\w{3,})\s*\(").expect("valid regex")
    });

    // Pattern 3: function references in code blocks (indented or fenced)
    static RE_CODE_FUNC: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(\w{3,})\s*\(").expect("valid regex")
    });

    let mut names: HashSet<String> = HashSet::new();

    // Blocklist: structural/language keywords only (NOT method names like create/update)
    let blocklist: HashSet<&str> = [
        "the", "and", "for", "with", "from", "this", "that", "will", "are", "not",
        "use", "add", "new", "has", "can", "may", "let", "mut", "pub", "mod",
        "step", "plan", "file", "code", "line", "note", "todo", "see",
        "true", "false", "null", "none", "self", "super",
        "return", "class", "function", "method", "trait", "struct", "impl", "enum",
        "public", "private", "protected", "static", "async", "await",
        "Table", "Model", "Service", "Controller", "string", "array", "bool", "int",
        "varchar", "integer", "boolean", "nullable", "default", "index",
    ].into_iter().collect();

    for re in [&*RE_BACKTICK, &*RE_METHOD, &*RE_CODE_FUNC] {
        for cap in re.captures_iter(plan_content) {
            let name = &cap[1];
            if !blocklist.contains(name) {
                names.insert(name.to_string());
            }
        }
    }

    names
}
```

### 3. Add filtering stats to output JSON

In the `prepare_attack` output, add:
```json
{
  "filtering": {
    "original_function_count": 74,
    "filtered_function_count": 12,
    "plan_mentioned": ["processBooking", "applyBookingMetadata"],
    "plan_callees": ["updateExistingReservation"],
    "kept_by_shared_mutation": 3,
    "reduction_percent": 83,
    "filter_skipped": false
  }
}
```

## Expected Impact

| Metric | Before | After |
|--------|--------|-------|
| Beds24Service facts | 19K chars (44 fn) | ~5K chars (~12 fn) |
| ReservationService facts | 16K chars (30 fn) | ~4K chars (~8 fn) |
| Total 4-file output | 89K chars | ~15K chars |
| Red team prompt size | ~47K chars | ~12K chars |
| Claude Code inline limit | EXCEEDED | WITHIN |

## Detection Coverage After Filtering

| Break Path | What catches it | Filtering impact |
|-----------|----------------|-----------------|
| A. Caller breaks | blast_radius callers → kept by rule 3 | No loss |
| B. Caller assumes old behavior | caller facts preserved | No loss |
| C. Same-table concurrent conflict | shared mutation siblings → kept by rule 4 | No loss |
| D. Internal callee changes | plan function's external_calls → callees kept by rule 2 | NEW (was missing) |
| E. Unrelated pure helpers | dropped (e.g. splitGuestName, getChannelName) | Intended reduction |

## Risks (post red-team)

1. **Regex false negatives on Chinese prose**: `修改 processBooking 的邏輯`
   - `RE_CODE_FUNC` matches `\b(\w{3,})\s*\(` — no `(` in prose → miss
   - But `RE_BACKTICK` catches if plan uses backticks (convention in our plans)
   - Fallback: if plan_mentioned is empty, skip filtering entirely

2. **Callee extraction imprecise**: external_calls description may not contain parseable function name
   - Acceptable: over-inclusion is safe (keeps more functions), under-inclusion falls back to other rules

3. **Aggressive filtering warning**: if filtering removes >80%, output JSON includes `filter_skipped: true`
   - Agent can decide whether to re-run without filtering

## Testing

- Unit test: `extract_plan_functions` with various plan formats (English, Chinese, mixed)
- Unit test: `extract_plan_functions` with common-word method names (create, update, save)
- Unit test: filtering logic with mock FactTables (plan-mentioned, callees, shared-mutation, irrelevant)
- Unit test: fallback triggers when plan_mentioned is empty
- Unit test: fallback warns when filtering >80%
