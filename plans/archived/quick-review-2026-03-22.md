# Quick Review — 輕量化日常守衛

## 目標

新增 `quick_review` MCP 工具，讓 refine 能在**沒有 plan file** 的情況下使用。
從 git diff 自動擷取 facts + blast radius，產生單一紅隊 prompt，一個 subagent 就能完成審查。

## Before vs After

```
Full pipeline (7 steps, 3-4 Opus subagents):
  discover_plan → extract_facts → prepare_attack → spawn 2-4 RT → synthesize → spawn blue → finalize

Quick review (2 steps, 1 subagent):
  quick_review → spawn 1 agent with combined prompt
```

## 設計

### 工具參數

```rust
pub struct QuickReviewParams {
    /// Files to review. If empty, auto-detects from git diff.
    pub file_paths: Option<Vec<String>>,
    /// Git ref to diff against (default: "HEAD")
    pub base_ref: Option<String>,
    /// Directories to search for callers (default: app/, routes/, src/)
    pub search_paths: Option<Vec<String>>,
    /// Review mode: "default" (Opus), "lite" (Sonnet)
    pub mode: Option<String>,
}
```

### 工具流程

1. 取得 changed files（從 git diff 或 `file_paths` 參數）
2. tree-sitter extract facts
3. blast_radius 找 callers
4. `auto_select_red_teams` 判斷需要哪些攻擊角度
5. `build_quick_review_prompt` — 合併相關 RT 角度到單一 prompt
6. 回傳 `{ prompt, facts_summary, dispatch, recommended_model }`

### 回傳格式

```json
{
  "prompt": "You are a code reviewer...(combined template with facts injected)...",
  "recommended_model": "opus",
  "facts_summary": {
    "files_analyzed": 3,
    "functions_found": 12,
    "callers_found": 8,
    "signals": ["2 mutations without tx", "silent swallow in X"]
  },
  "dispatch": {
    "angles": ["silent-failure", "concurrency", "data-integrity"],
    "reasoning": ["RT-A: always", "RT-C: 2 mutations without tx in BillingService::create"]
  }
}
```

### 合併模板（templates/quick_review.md）

跟 4 個獨立 RT 模板不同，quick_review 用一個合併模板，動態插入相關的攻擊角度。

結構：
1. Context（changed files 列表）
2. Fact tables（tree-sitter 100% 精確）
3. Caller facts（blast radius）
4. Schema（optional）
5. **Attack angles**（從 RT-A/B/C/D 中選取相關的 patterns 段落）
6. Rules + JSON output format

### Output format 改進

不再用 markdown（parser 容易壞），改要求 JSON array：
```json
[
  {
    "severity": "fatal",
    "title": "...",
    "file": "...",
    "line_range": [10, 20],
    "problem": "...",
    "attack_scenario": "...",
    "suggested_fix": "..."
  }
]
```

## 實作步驟

- [x] Step 1: 建立 `templates/quick_review.md` 合併模板
- [x] Step 2: `src/prompts/mod.rs` 加入 `build_quick_review_prompt()`
- [x] Step 3: `src/server.rs` 加入 `QuickReviewParams` + `quick_review` 工具
- [x] Step 4: 測試 + 編譯 (全部通過)
- [x] Step 5: 更新 `.claude/rules/refine-tools.md`
- [x] Step 6: 建置 release binary (commit 7a771b2)

## 不做的事

- 不動現有的 8 個 v1 工具（完整紅藍流程仍保留）
- 不做 state persistence（quick_review 是 stateless）
- 不做 blue team synthesis（直接回傳 findings）
