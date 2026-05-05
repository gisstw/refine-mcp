# refine-mcp Agent-First Evolution

**日期**: 2026-05-05
**目標**: 把 refine-mcp 從「人工輔助工具」進化成 agent-first 工具，把所有「靠 agent 記得做」的環節變成 tool 強制邏輯。
**範圍**: P1 → P5 全做（依賴順序 P1→P2→P3→P4→P5，可漸進交付）

---

## 0. 決策摘要（一錘定音）

| 決策 | 選擇 | 理由 |
|------|------|------|
| 相容性策略 | **B. 漸進升級** | 新增欄位以 `#[serde(default)]` 處理；舊 state 檔讀得到，下次 run 自動補 fingerprint |
| Fingerprint 設計 | **c. symbol_path + content_hash** | refine 已有 tree-sitter，能拿到 enclosing function 的 symbol path；content_hash 含 enclosing scope ± 3 行，行數 shift 容忍 |
| 紅隊輸出格式 | **JSON-only schema** | synthesize 不再 regex 解析；schema validate 失敗直接 reject |
| Domain Pack 位置 | **`<project>/.refine/packs/*.md`** | 專案自治；refine-mcp 內附 `templates/packs/{laravel,beds24,axum-pms}.md` 作預設 |
| 不支援格式處理 | **textual fallback + 強制顯示** | `extract_method` 欄位標記精度；`skipped_files` 一定回報 |
| 格式擴充優先級 | blade.php → sql → yml → sh → toml → json → vue | PMS-first，blade/sql 是日常剛需 |

---

## 0.5 Tier 2 紅藍審查補強（2026-05-05）

審查結果：3 fatal + 4 high。整體判定 **YELLOW**，需先補以下 6 條才能執行。詳細 finding 見檔尾 `## Refinement Iterations`。

| ID | 補丁範圍 | 套用位置 |
|----|----------|---------|
| RT-A1 | silent_swallow → log_and_return_error | §1.0（新增）+ §3.2 |
| RT-A2 | fingerprint 首次保護期（schema_version） | §2.1 |
| RT-A3 | pack 注入錯誤不能被吞 | §4.3 |
| RT-B1 | Blade 預處理保留每行字元數 | §2.3 |
| RT-B2 | run_review 順序：blast_radius 在全庫 grep | §5.1 |
| RT-B3 | JSON 降級語意改為單 call 內三段式 | §3.2 |
| RT-B4 | plan step regex 支援 `### 2.1` 格式 | §3.3 |

**核心原則新增**：P1-P5 任何新邏輯**禁止使用 `unwrap_or_default()` / `Err(_) => default` / `.ok()` 來吞錯**。所有失敗必須走 `log_and_return_error`，或結構化 warning 上浮到 MCP response top-level。

---

## 1. 共通基礎建設（P1 動工前先做）

### 1.0 Pre-flight: 清理現有 Silent Failure（**新增，動工第一步**）

**動機**: 紅隊發現 `server.rs:446`、`server.rs:683-695`、`parser/mod.rs` 多處 silent fallback 會把 P1-P5 新增的錯誤吞掉。動工前先清乾淨，否則新邏輯白做。

**Audit 清單**（必修，commit 前 grep 確認）:
```bash
# 1. 不允許 unwrap_or_default() 在 critical path
grep -n 'unwrap_or_default()' src/server.rs
# 期待結果：≤ 5 處（且都是顯示用的 to_string_pretty fallback，非業務邏輯）

# 2. 不允許 Err(_) => empty
grep -n 'Err(_) =>' src/server.rs

# 3. 不允許 .ok() 吞掉 critical 錯誤
grep -n '\.ok()' src/server.rs | grep -v writeln
```

**改動**:
1. `server.rs:446` `Err(_) => String::new()` 改成 `Err(e) => return Err(annotate(e, "facts JSON serialization failed"))`
2. `synthesize_findings` 的 `parse_errors` 從「埋進 output JSON」改成「output 頂層 `warnings: [{kind, message}]`」並在數量 > 0 時 caller 必須看見的位置（response 最上方）
3. `parse_red_team_output`（parser/mod.rs）若回傳 `Ok(vec![])` 但輸入非空 → 改成 `Err("parser produced 0 findings from non-empty input")`，禁止靜默零結果

**驗收**: 跑 `cargo test parser_empty_input_must_error` 確認非空輸入永遠不會 silent 0 findings。

---

### 1.1 Facts Registry 解耦
**現況**: `src/server.rs:1306` 寫死 match（`Some("php") => ...`）。
**改成**: 新增 `src/facts/registry.rs`，把 dispatch 抽出來。

**新檔 `src/facts/registry.rs`**:
```rust
use std::path::Path;
use anyhow::Result;
use crate::facts::types::FactTable;

pub enum ExtractMethod {
    TreeSitter,
    Textual,        // unsupported 走純 diff
    Json,           // serde_json 走 schema 檢查
    BladePreproc,   // .blade.php 預處理後丟 PHP
}

pub struct ExtractResult {
    pub facts: FactTable,
    pub method: ExtractMethod,
}

pub fn extract(path: &Path, source: &str) -> Result<ExtractResult> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "php" => php(path, source),
        "blade.php" | _ if path.to_string_lossy().ends_with(".blade.php") => blade(path, source),
        "rs" => rust_lang(path, source),
        "ts" | "tsx" | "js" | "jsx" => typescript(path, source),
        "py" => python(path, source),
        "md" => markdown(path, source),
        "sql" => sql(path, source),                  // P1
        "yml" | "yaml" => yaml(path, source),        // P2
        "sh" | "bash" => bash(path, source),         // P2
        "toml" => toml_lang(path, source),           // P4
        "json" => json_lang(path, source),           // P4
        "vue" => vue(path, source),                  // P5
        _ => textual_fallback(path, source),
    }
}
```

**`src/server.rs:1306` 改成**:
```rust
let result = refine_mcp::facts::registry::extract(&path, &source);
```

**陷阱**: `path.extension()` 對 `.blade.php` 只回 `php`，要用 `path.to_string_lossy().ends_with(".blade.php")` 先攔截。

### 1.2 FactTable 新欄位
**`src/facts/types.rs:7`** 加：
```rust
pub struct FactTable {
    // ... 既有欄位
    /// 新增：哪種方法擷取的，紅隊 prompt 可見
    #[serde(default)]
    pub extract_method: ExtractMethod,
    /// 新增：fingerprint 索引（line_range → fingerprint）
    #[serde(default)]
    pub fingerprints: Vec<FingerprintEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ExtractMethod {
    #[default]
    TreeSitter,
    Textual,
    Json,
    BladePreproc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintEntry {
    pub line_range: (u32, u32),
    pub symbol_path: String,    // e.g., "CartService::charge"
    pub content_hash: String,   // sha256 of body ± 3 lines
}
```

### 1.3 `ExtractResult` 收集 skipped_files
**`src/server.rs` 的 `extract_facts` handler**: 改回傳結構：
```rust
pub struct ExtractFactsResponse {
    pub fact_tables: Vec<FactTable>,
    pub skipped_files: Vec<SkippedFile>,    // ← 新增
    pub errors: Vec<String>,
}

pub struct SkippedFile {
    pub path: PathBuf,
    pub reason: SkipReason,
    pub fallback_used: bool,
}

pub enum SkipReason {
    UnsupportedExtension(String),
    ParseError(String),
    BinaryFile,
    TooLarge { bytes: u64 },
}
```

`finalize_refinement` / `synthesize_findings` / `quick_review` 都要把 `skipped_files` 帶進輸出，prompt 開頭強制顯示：
```
⚠️ 本次 review 跳過 N 檔（textual fallback: M 檔，完全失明: K 檔）
最常見原因: .blade.php parse_error × 12
```

---

## 2. Phase 1：堵住燃眉之急（5-6 天）

### 2.1 Fingerprint 系統 + Auto-fix Marking
**新檔 `src/fingerprint.rs`**:
```rust
use sha2::{Sha256, Digest};
use crate::facts::types::FingerprintEntry;

pub fn compute(symbol_path: &str, body_with_context: &str) -> String {
    let mut h = Sha256::new();
    h.update(symbol_path.as_bytes());
    h.update(b"\n");
    // 正規化：tab→space、trim 行尾、移除空白行
    let normalized = normalize(body_with_context);
    h.update(normalized.as_bytes());
    format!("{:x}", h.finalize())
}

fn normalize(src: &str) -> String {
    src.lines()
        .map(|l| l.replace('\t', "    ").trim_end().to_string())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}
```

**`src/state.rs:65 merge_findings`** 改：
```rust
pub fn merge_findings(&mut self, new_findings: Vec<Finding>, current_fingerprints: &HashMap<PathBuf, Vec<FingerprintEntry>>) {
    // Phase 1: 對既有 findings 自動回標 fixed
    for existing in self.findings.iter_mut() {
        if existing.status != FindingStatus::New { continue; }
        if let Some(fp) = &existing.fingerprint {
            let still_present = current_fingerprints
                .get(&existing.file_path)
                .map(|v| v.iter().any(|e| &e.content_hash == fp))
                .unwrap_or(false);
            if !still_present {
                existing.status = FindingStatus::Fixed;
                existing.auto_marked = Some("fingerprint not found in latest run".into());
            }
        }
    }
    // Phase 2: 既有 merge 邏輯不變
    for new in new_findings { /* ... */ }
}
```

**`src/types.rs:64 Finding`** 加：
```rust
pub struct Finding {
    // ... 既有欄位
    #[serde(default)]
    pub fingerprint: Option<String>,        // content_hash
    #[serde(default)]
    pub symbol_path: Option<String>,
    #[serde(default)]
    pub auto_marked: Option<String>,        // 自動標記原因
}
```

**`finalize_refinement` 收尾印一行**:
```
✅ Auto-marked fixed: 3 findings (RT-001, RT-005, RT-007)
🔍 New findings: 2
⏸ Pending (awaiting confirmation): 4
```

**新增 MCP tool `mark_finding`**（手動補救用）:
```rust
// src/server.rs 工具列表加：
ToolDef {
    name: "mark_finding",
    description: "Manually update a finding's status (fixed / false_positive / confirmed)",
    schema: { plan_path, finding_id, status, note? }
}
```

**陷阱**:
- `current_fingerprints` 必須由本次 `extract_facts` 計算後傳入，不可從 state 讀（state 是上次的）。
- 第一次跑（舊 state，`fingerprint` 全 None） → 不能誤標 fixed。要在 merge 前先檢查 `existing.fingerprint.is_some()`。

**Tier 2 補強（RT-A2）— 首次保護期**:

state 加 `schema_version: u8`（default 0）：
```rust
pub struct RefineState {
    #[serde(default)]
    pub schema_version: u8,
    // ...
}
```

`merge_findings` auto-mark 條件改成：
```rust
let auto_mark_enabled = self.schema_version >= 2 && !current_fingerprints.is_empty();
if auto_mark_enabled {
    // ...auto-mark fixed 邏輯
}
// 每次 run 結束 bump version：v0→v1（補 fingerprint）→v2（auto-mark 啟用）
self.schema_version = (self.schema_version + 1).min(2);
```

**保護機制**:
- v0 → v1：首次 run，補 fingerprint，**不**啟用 auto-mark
- v1 → v2：第二次 run，正式啟用 auto-mark
- `current_fingerprints` 為空時（extract_facts 失敗）絕不 auto-mark

**測試（必加）**:
- `test_v0_to_v1_no_auto_mark`：舊 state（無 fingerprint）首次跑，0 findings 被標 fixed
- `test_empty_fingerprint_map_no_auto_mark`：HashMap 空時不誤標
- `test_v2_normal_auto_mark`：第三次 run 正常 auto-mark

### 2.2 Skipped Files 強制顯示
參考 §1.3，已含實作。**測試重點**: 製造一個 `.foo` 檔丟給 `quick_review`，確認 prompt 開頭出現警告。

### 2.3 Blade-aware 預處理
**新檔 `src/facts/blade.rs`**:
```rust
use crate::facts::php;

pub fn extract_blade_facts(path: &Path, source: &str) -> Result<ExtractResult> {
    let preprocessed = preprocess(source);
    let mut result = php::extract_php_facts(path, &preprocessed)?;
    result.method = ExtractMethod::BladePreproc;
    Ok(result)
}

fn preprocess(src: &str) -> String {
    // @directive(...) → /* @directive(...) */
    // {{ $expr }} → <?= $expr ?>
    // {!! $raw !!} → <?= $raw ?>
    // @if / @endif / @foreach 等 → // @if ... 註解
    // 注意：保留行號（不要刪行，只替換）
    let re_directive = regex::Regex::new(r"@(\w+)\s*\(").unwrap();
    let re_echo = regex::Regex::new(r"\{\{\s*(.+?)\s*\}\}").unwrap();
    let re_raw = regex::Regex::new(r"\{!!\s*(.+?)\s*!!\}").unwrap();
    // ... 實作
}
```

**測試樣本**: `templates/test_fixtures/sample.blade.php`（含 `@if`、`{{ }}`、`@foreach`）。

**陷阱**: 行號必須保留（紅隊回報 file:line 要對得上原檔）。預處理是「替換 in-place」不是「移除」。

**Tier 2 補強（RT-B1）— 必須保留每行字元數**:

`{{ $expr }}`（4 byte wrapper）→ `<?= $expr ?>`（7 byte wrapper）長度不同會造成行內 column offset 漂移，雖然行號 OK 但 tree-sitter 的 line/col 對應原檔失準。

**修正策略（兩擇一）**:

**策略 A（推薦）— 等寬替換**:
```rust
// {{ $x }} → <?=$x;?>  （兩者都是 8 chars wrapper + content）
// 用最短 PHP 等價式，並 pad 空白到原長度
fn replace_echo_eq_width(orig: &str) -> String {
    re_echo.replace_all(orig, |caps: &Captures| {
        let inner = &caps[1];
        let original_len = caps[0].len();
        let replacement = format!("<?={};?>", inner);
        if replacement.len() <= original_len {
            format!("{:width$}", replacement, width = original_len)  // pad
        } else {
            // truncate inner 並 warning（罕見：超長 expression）
            log_format_issue("blade_truncate", ".blade.php", path, &caps[0]);
            replacement.chars().take(original_len).collect()
        }
    }).into_owned()
}
```

**策略 B — 附帶 offset map**:
```rust
pub struct ExtractResult {
    pub facts: FactTable,
    pub method: ExtractMethod,
    pub line_offset_map: Option<Vec<(u32, i32)>>,  // (line, column_delta)
}
```
紅隊 prompt 顯示 line:col 時用 map 修正回原檔。

**選 A**（簡單、無新欄位、tree-sitter 直接看到對齊好的源碼）。

**測試（必加）**:
```rust
#[test]
fn blade_preprocess_preserves_line_lengths() {
    let orig = include_str!("fixtures/sample.blade.php");
    let preprocessed = preprocess(orig);
    let orig_lens: Vec<_> = orig.lines().map(|l| l.len()).collect();
    let new_lens: Vec<_> = preprocessed.lines().map(|l| l.len()).collect();
    assert_eq!(orig_lens, new_lens, "Each line must have identical byte length");
}
```

### 2.4 SQL Parser
**Cargo.toml** 加：
```toml
tree-sitter-sequel = "0.3"  # 確認版本
```

**新檔 `src/facts/sql.rs`**: 擷取
- `CREATE TABLE` / `ALTER TABLE` 動作 → `SchemaChange` fact
- `DROP COLUMN` / `DROP TABLE` → 高危 mutation
- `NOT NULL` 加在已存在 column → migration warning
- Foreign key 變動

```rust
pub struct SqlFacts {
    pub schema_changes: Vec<SchemaChange>,
    pub destructive_ops: Vec<DestructiveOp>,
}

pub enum DestructiveOp {
    DropColumn { table: String, column: String, line: u32 },
    DropTable { table: String, line: u32 },
    TruncateTable { table: String, line: u32 },
}
```

整合到 `FactTable`: 新增 `sql_facts: Option<SqlFacts>` 欄位。

### 2.5 Textual Fallback
**新檔 `src/facts/textual.rs`**:
```rust
pub fn textual_fallback(path: &Path, source: &str) -> Result<ExtractResult> {
    // 不做語意分析，只擷取：
    // - 行數統計
    // - TODO/FIXME/HACK 註解
    // - 看起來像函數定義的 pattern (heuristic)
    // - 可疑字串 (api_key, password, token, secret)
    let mut warnings = vec![];
    if source.lines().count() > 1000 {
        warnings.push("Large file, textual review may miss issues".into());
    }
    Ok(ExtractResult {
        facts: FactTable { warnings, /* ... */ },
        method: ExtractMethod::Textual,
    })
}
```

**紅隊 prompt 看到 `extract_method: "textual"` 時自動加註**:
> 「⚠️ 此檔以純文字方式分析，精度低於 tree-sitter，請特別仔細檢查 diff」

---

## 3. Phase 2：紅隊輸出規範化（3 天）

### 3.1 JSON Schema 強制
**`src/prompts/`** 下找出紅隊 prompt template，末尾改成：
```
**OUTPUT FORMAT (MANDATORY)**

Return ONLY a JSON array (no markdown, no prose). Schema:
```json
[
  {
    "title": "string, ≤80 chars",
    "severity": "fatal" | "high",
    "file_path": "relative path",
    "line_range": [start, end],
    "problem": "what is wrong",
    "attack_scenario": "concrete attack/failure path",
    "suggested_fix": "specific fix",
    "affected_plan_steps": ["Step 2", "Step 5"],   // REQUIRED, never empty
    "category": "silent_failure" | "concurrency" | "schema_drift" | "auth" | "other"
  }
]
```

If you cannot map a finding to a plan step, set `affected_plan_steps: ["OUT_OF_SCOPE"]`.
EMPTY ARRAY IS FORBIDDEN.
```

### 3.2 Synthesize 端 Schema Validate
**`src/parser/mod.rs`** 加：
```rust
pub fn parse_red_team_output(raw: &str) -> Result<Vec<Finding>> {
    // 1. 嘗試 JSON parse
    let json = strip_markdown_fences(raw);
    let raw_findings: Vec<RawFinding> = serde_json::from_str(&json)
        .context("Red team output is not valid JSON")?;

    // 2. Validate 每筆
    let mut errors = vec![];
    for (i, f) in raw_findings.iter().enumerate() {
        if f.affected_plan_steps.is_empty() {
            errors.push(format!("Finding #{i} has empty affected_plan_steps"));
        }
        if f.title.len() > 80 {
            errors.push(format!("Finding #{i} title too long"));
        }
    }
    if !errors.is_empty() {
        return Err(anyhow!("Schema validation failed:\n{}", errors.join("\n")));
    }

    // 3. 轉換成 Finding，計算 fingerprint
    Ok(raw_findings.into_iter().map(into_finding).collect())
}
```

**保留向後相容**: 若 `serde_json::from_str` 失敗，**降級**走舊 markdown parser（`parse_findings_markdown`），但加 warning「LLM 未遵守 JSON 格式，請更新 prompt」。

**Tier 2 補強（RT-A1 + RT-B3）— 三段式單 call 降級 + 錯誤上浮**:

**錯誤語意精確化**：「兩次失敗才降級」是錯的（synthesize_findings 是單 call，無跨 call 狀態）。改成**單 call 內三段式 fallback**:

```rust
pub fn parse_red_team_output(raw: &str) -> Result<(Vec<Finding>, ParseMethod)> {
    // Stage 1: 嚴格 JSON
    if let Ok(parsed) = serde_json::from_str::<Vec<RawFinding>>(raw) {
        validate_schema(&parsed)?;
        return Ok((to_findings(parsed), ParseMethod::StrictJson));
    }
    // Stage 2: strip markdown fences 後再試 JSON
    let stripped = strip_markdown_fences(raw);
    if let Ok(parsed) = serde_json::from_str::<Vec<RawFinding>>(&stripped) {
        validate_schema(&parsed)?;
        return Ok((to_findings(parsed), ParseMethod::JsonAfterStrip));
    }
    // Stage 3: 降級 markdown parser（warning，不靜默）
    let findings = parse_findings_markdown(raw)?;
    if findings.is_empty() && !raw.trim().is_empty() {
        return Err(anyhow!("Parser produced 0 findings from non-empty input — likely format mismatch"));
    }
    Ok((findings, ParseMethod::LegacyMarkdown))
}
```

**錯誤上浮（必改）**:

`synthesize_findings` 的 response 結構：
```rust
pub struct SynthesizeResponse {
    pub findings: Vec<Finding>,
    pub blue_prompt: String,
    pub stats: SynthesisStats,
    /// **新增**: 頂層 warnings（不是埋在 errors[]）
    pub warnings: Vec<Warning>,
    pub parse_method_per_report: Vec<ParseMethod>,  // 哪份 report 走哪段
}

pub struct Warning {
    pub kind: WarningKind,    // ParseDegraded / EmptyResult / SchemaMismatch
    pub message: String,
    pub severity: WarningSeverity,
}
```

caller（agent）看到 `warnings` 非空時必須回報使用者，不可埋掉。

**測試（必加）**:
- `test_synthesize_empty_input_does_not_silent_zero`：非空 raw → 0 findings 必須回 Err 或 Warning，不可靜默成功
- `test_three_stage_fallback`：分別餵 strict JSON / fenced JSON / markdown，確認都能 parse 且 method 正確

### 3.3 Plan Step 預先注入
**`prepare_attack`** 改：讀 plan file，抽出 step list，注入紅隊 prompt：
```
This plan has the following steps:
- §2.1: Fingerprint 系統
- §2.3: Blade-aware 預處理
- §3.2: Synthesize Schema Validate

When reporting findings, ONLY use these step IDs in `affected_plan_steps`,
or "OUT_OF_SCOPE" if it doesn't fit any step.
```

**Tier 2 補強（RT-B4）— regex 多格式支援**:

舊 regex `^##\s+Step\s+(\d+)` 只抓英文 Step，本計畫用 `### 2.1`、`## 3. Phase 2` 格式 → 一筆都抓不到。

**新版抽取邏輯（多策略 fallback）**:
```rust
pub fn extract_plan_steps(plan_md: &str) -> Vec<PlanStep> {
    // Strategy 1: H2-H4 + 編號（支援 1, 1.1, 1.1.1）
    let re_numbered = Regex::new(r"^(#{2,4})\s+(?:Step\s+|Phase\s+)?(\d+(?:\.\d+){0,2})[\s.:：](.*?)$").unwrap();
    let steps: Vec<_> = plan_md.lines().enumerate()
        .filter_map(|(i, line)| {
            re_numbered.captures(line).map(|c| PlanStep {
                id: format!("§{}", &c[2]),  // §2.1 / §3.3 / Step 1
                title: c[3].trim().to_string(),
                line: i as u32,
            })
        })
        .collect();
    if steps.len() >= 3 { return steps; }

    // Strategy 2: 找明確的 Steps / Phases 區塊
    if let Some(block) = find_section(plan_md, &["## Steps", "## Phases", "## 步驟"]) {
        return parse_list_items(block);
    }

    // Strategy 3: 抓所有 H2/H3 當 step（最後手段）
    Regex::new(r"^#{2,3}\s+(.+?)$").unwrap()
        .captures_iter(plan_md)
        .enumerate()
        .map(|(i, c)| PlanStep { id: format!("Step {}", i+1), title: c[1].into(), line: 0 })
        .collect()
}
```

**測試（必加）**:
- 用本計畫檔當 fixture，assert `extract_plan_steps` 至少抽出 §1.1 / §2.1 / §3.2 / §4.1 / §5.1 五個 step
- 用舊格式（`## Step 1: xxx`）測試向後相容

### 3.4 YAML / Bash Parser
**Cargo.toml**:
```toml
tree-sitter-yaml = "0.6"
tree-sitter-bash = "0.21"
```

**`src/facts/yaml.rs`** 重點擷取:
- `.github/workflows/*.yml` 的 `permissions:`、`secrets.`、`uses: actions/...@版本固定?`
- docker-compose: `privileged: true`、`network_mode: host`、port exposure

**`src/facts/bash.rs`** 重點擷取:
- `rm -rf $VAR`（變數展開）
- `curl ... | sh`（unsafe pipe）
- `sudo` without password check
- `chmod 777`

---

## 4. Phase 3：Domain Pack 機制（3-4 天）

### 4.1 Pack 載入
**新檔 `src/packs.rs`**:
```rust
pub struct DomainPack {
    pub name: String,           // "laravel"
    pub description: String,
    pub red_team_rules: Vec<DomainRule>,
}

pub struct DomainRule {
    pub target_red_team: Vec<RedTeamId>,    // 灌進哪幾個 RT
    pub trigger_patterns: Vec<String>,       // 看到這些 pattern 時提醒
    pub guidance: String,                    // 注入到 prompt 的文字
}

pub fn load_packs(project_root: &Path, requested: &[String]) -> Result<Vec<DomainPack>> {
    let mut packs = vec![];
    // 1. 先找 <project>/.refine/packs/<name>.md
    // 2. 找不到再找 refine-mcp 內附 templates/packs/<name>.md
    // 3. 都找不到 → warning 但不 fail
    for name in requested {
        if let Some(pack) = try_load_user(project_root, name)? {
            packs.push(pack);
        } else if let Some(pack) = try_load_builtin(name)? {
            packs.push(pack);
        } else {
            log::warn!("Domain pack '{name}' not found");
        }
    }
    Ok(packs)
}
```

### 4.2 內建 Packs
**新增**:
- `templates/packs/laravel.md` — mass assignment、unguarded model、Auth::user() in scheduled job、Eloquent N+1、policy bypass
- `templates/packs/beds24.md` — qty→numAvail 連動、timezone（Carbon→UTC 日期差）、numAdult unreliable in multi-room、priceLinking 陷阱
- `templates/packs/axum-pms.md` — Rc in handler state、tower-sessions cycle_id 時機、SQLx transaction not committed in handler

每個 pack 格式：
```markdown
# Laravel Domain Pack

## RT-A: Silent Failure
- Mass assignment without `$fillable` / `$guarded`
- `find()` vs `findOrFail()`
- `firstOrCreate` race condition

## RT-C: Schema Drift
- Migration without `down()` method
- `Schema::dropColumn` without checking foreign keys
...
```

### 4.3 Prompt 注入
**`prepare_attack` 末段**:
```rust
let mut prompt = base_prompt;
for pack in &packs {
    if pack.applies_to(red_team_id) {
        prompt.push_str(&format!("\n\n## Domain context: {}\n{}", pack.name, pack.guidance));
    }
}
```

**Tier 2 補強（RT-A3）— pack 載入錯誤不能被吞**:

`prepare_attack` 現有 `server.rs:446` 的 `Err(_) => String::new()` 會吃掉錯誤。pack 注入必須走獨立路徑：

```rust
// ❌ FORBIDDEN（會被外層 silent_swallow 吞）:
let pack_text = match load_packs(&project_root, &requested) {
    Ok(packs) => render(packs),
    Err(_) => String::new(),
};

// ✅ CORRECT:
let pack_load_result = load_packs(&project_root, &requested);
let mut warnings = vec![];
let pack_text = match pack_load_result {
    Ok(packs) => {
        for name in &requested {
            if !packs.iter().any(|p| &p.name == name) {
                warnings.push(Warning::new(
                    WarningKind::PackNotFound,
                    format!("Pack '{name}' not found, red team will lack domain context"),
                ));
            }
        }
        render(packs)
    }
    Err(e) => {
        return Err(annotate(e, "Domain pack loading failed"));
    }
};
// warnings 進入 PrepareAttackResponse.warnings 頂層欄位
```

**規則**:
- pack 不存在 → warning（紅隊仍會跑，但用戶知道缺 context）
- pack 損毀（YAML/MD parse error） → **hard error**（fail-fast，避免靜默劣化）
- requested 但找不到任何 pack → warning（不 fail）

### 4.4 MCP Tool 介面
`prepare_attack` 加參數 `domain_packs: Vec<String>`（預設 `[]`）:
```json
{ "plan_path": "...", "domain_packs": ["laravel", "beds24"] }
```

---

## 5. Phase 4：一鍵 + Incremental（2 天）

### 5.1 `run_review` MCP Tool
**新檔 `src/tools/run_review.rs`**:
```rust
pub struct RunReviewParams {
    pub plan_path: PathBuf,
    pub tier: Tier,                  // Quick / Tier2 / Tier3
    pub base_ref: Option<String>,    // None = auto-detect
    pub domain_packs: Vec<String>,
    pub mode: RefineMode,
}

pub enum Tier { Quick, Two, Three }

pub async fn run_review(params: RunReviewParams) -> Result<ReviewReport> {
    // 1. 自動偵測 base_ref
    let base = params.base_ref.unwrap_or_else(detect_base);
    // 2. extract_facts (incremental, 只看 git diff 影響的檔案)
    let facts = extract_facts_incremental(&base)?;
    // 3. expand_blast_radius
    let radius = expand_blast_radius(&facts)?;
    // 4. prepare_attack (含 domain packs)
    let attacks = prepare_attack(&radius, &params.domain_packs)?;
    // 5. 回傳 attacks 給 caller dispatch (因為 MCP server 不能 spawn subagent)
    //    → caller 收到後跑 subagent，再 call synthesize/finalize
    Ok(ReviewReport { attacks, facts_summary, .. })
}
```

**注意**: MCP server 自己不能 spawn subagent（那是 Claude Code 的事）。`run_review` 只能把流程串起來、預備好 prompts，agent 還是要自己 dispatch subagent。但減少 MCP tool call 次數從 6 次 → 1 次（再加 1 次 finalize）。

**Tier 2 補強（RT-B2）— blast_radius 必須跑在全庫上**:

紅隊指出原流程「先 extract_facts_incremental → 再 expand_blast_radius」的順序，會讓 blast_radius 只在 diff 內找 caller，漏掉 diff 外但會被影響的 caller。

**修正後正確順序**:
```rust
pub async fn run_review(params: RunReviewParams) -> Result<ReviewReport> {
    let base = params.base_ref.unwrap_or_else(detect_base);

    // Step 1: 找 diff 影響的檔案（候選清單）
    let diff_files = git_diff_files(&base)?;

    // Step 2: 對 diff 檔做 facts extract（找出改了 signature 的函數）
    let diff_facts = extract_facts(&diff_files)?;
    let changed_signatures = identify_changed_signatures(&diff_facts, &base)?;

    // Step 3: blast_radius 在「全庫 search_paths」上 grep 這些 signature
    //         （不是只在 diff_files 內找！）
    let radius = expand_blast_radius_global(
        &changed_signatures,
        &project_search_paths(),  // 全庫，例：["src/", "app/", "tests/"]
        &diff_files,                // exclude（避免重複）
    )?;

    // Step 4: 把 caller 檔加進來，重跑 facts
    let mut all_files = diff_files.clone();
    all_files.extend(radius.caller_files.iter().cloned());
    let full_facts = extract_facts(&all_files)?;

    // Step 5: prepare_attack
    let attacks = prepare_attack(&full_facts, &params.domain_packs, plan_path)?;

    Ok(ReviewReport { attacks, facts_summary, blast_radius_stats, .. })
}
```

**關鍵差異**:
- ❌ 原版：`expand_blast_radius(&facts)` — 只在 diff 內找
- ✅ 修正：`expand_blast_radius_global(&signatures, &full_search_paths, &exclude)` — 全庫 grep，stateless（每次 fresh grep，不快取 symbol index）

**文件化此限制**: blast_radius 是純 grep 操作，**不依賴**任何 symbol index 快取。每次 run 都從零 grep，慢但正確。

**測試（必加）**:
- fixture：建一個 `caller.rs` 在 diff 外，import diff 內改了的函數 → assert caller.rs 被 expand_blast_radius 抓到

### 5.2 Auto-detect base_ref
```rust
fn detect_base() -> String {
    // 1. 試 `git merge-base HEAD origin/main`
    // 2. 失敗試 `git merge-base HEAD main`
    // 3. 失敗 fallback "HEAD~1"
}
```

### 5.3 Incremental Mode
`extract_facts` 加參數 `only_changed: bool`（預設 true 當有 base_ref）:
```rust
if only_changed {
    let changed = git_diff_files(&base_ref)?;
    file_paths.retain(|p| changed.contains(p));
}
```

### 5.4 TOML / JSON Parser
- `tree-sitter-toml`：擷取 dependency 變動（version bump、新增/移除 crate、feature flag 變動）
- `serde_json`：不用 tree-sitter，直接 parse；擷取 schema 結構，diff 兩個版本看欄位增減

---

## 6. Phase 5：長尾體驗（2-3 天）

### 6.1 False Positive 學習
**`src/state.rs`** 加：
```rust
pub struct RefineState {
    // ...
    #[serde(default)]
    pub false_positive_history: Vec<FalsePositiveEntry>,
}

pub struct FalsePositiveEntry {
    pub fingerprint: String,
    pub title: String,
    pub category: String,
    pub note: Option<String>,    // 為何是誤報
}
```

**`prepare_attack`** 注入：
```
The following N findings have been confirmed FALSE POSITIVE in past runs.
Do NOT report similar patterns:
- "Mass assignment in CartService::charge" (laravel/mass_assignment) — note: $guarded set in parent
- ...
```

### 6.2 空殼歸檔
**`finalize_refinement`** 結尾：
```rust
if state.findings.is_empty() && new_findings.is_empty() {
    // 不寫 plans/refine-state-*.json
    // 改寫 ~/.cache/refine-mcp/clean-runs.log
    append_clean_run_log(plan_name, run_count)?;
    return Ok(report_with_note("Clean run, no state file written"));
}
```

**TTL**: 啟動時掃 `plans/refine-state-*.json`，`last_run` 超過 14 天且 `findings: []` → 移到 `plans/archived/`。

### 6.3 Vue SFC Parser
**`src/facts/vue.rs`**:
```rust
pub fn extract_vue_facts(path: &Path, source: &str) -> Result<ExtractResult> {
    // 1. 拆 <template> / <script> / <style>
    let blocks = split_sfc(source)?;
    // 2. <script> 段丟 typescript parser
    let script_facts = if let Some(script) = blocks.script {
        typescript::extract_ts_facts_from_str(path, &script.content, script.start_line)?
    } else { Default::default() };
    // 3. <template> 走 textual fallback（Vue template grammar 太重，先不做）
    // 4. 合併
    Ok(merged)
}
```

### 6.4 Parse Error 決策選項
**`src/facts/registry.rs`** 改 textual_fallback 與 parse_error 處理：
```rust
match php::extract_php_facts(path, source) {
    Ok(r) => Ok(r),
    Err(e) => {
        // 不直接 fail，回 ParseErrorResult 讓 caller 決定
        Ok(ExtractResult {
            facts: FactTable {
                warnings: vec![format!("Parse failed: {e}")],
                ..Default::default()
            },
            method: ExtractMethod::Textual,
            recovery_options: vec![
                "skip with warning",
                "textual fallback (current)",
                "split file at __halt_compiler__ markers",
            ],
        })
    }
}
```

---

## 7. 測試策略

| Phase | 測試重點 | 位置 |
|-------|---------|------|
| P1 | fingerprint stability (同 code 不同空白) / blade 預處理保留行號 / sql DROP 偵測 | `tests/p1_*.rs` |
| P1 | merge_findings 第一次跑（無 fingerprint）不誤標 fixed | `tests/state_backward_compat.rs` |
| P2 | JSON schema 缺欄位 reject / 降級 markdown parser 仍可用 | `tests/parser_json.rs` |
| P3 | Pack 載入優先級（user > builtin）/ Pack 注入 prompt | `tests/packs.rs` |
| P4 | run_review 串接正確 / auto-detect base_ref / incremental 真的只看 diff | `tests/run_review.rs` |
| P5 | FP history 注入 / 空殼不寫檔 / .vue script 段擷取正確 | `tests/p5_*.rs` |

**Backward compat 必跑**: 舊 state 檔（v0，無 fingerprint）丟進新版必須讀得進來，不能 panic。

---

## 8. Rollout 順序與 Commit 切分

每個 Phase 內按以下順序 commit：

```
P1:
  feat(facts): facts registry + ExtractMethod 解耦         [#registry]
  feat(facts): FactTable 加 fingerprints + extract_method  [#fact-fields]
  feat(state): fingerprint-based auto-fix marking          [#auto-fix]
  feat(server): skipped_files 強制顯示於 review output     [#skipped-display]
  feat(facts): blade.php 預處理走 PHP parser              [#blade]
  feat(facts): sql parser via tree-sitter-sequel          [#sql]
  feat(facts): textual fallback for unsupported          [#textual]
  feat(server): mark_finding MCP tool                    [#mark-tool]
  test(p1): backward compat with v0 state                [#p1-tests]

P2:
  feat(prompts): JSON-only schema for red team output    [#json-schema]
  feat(parser): JSON validate + markdown fallback        [#parser-json]
  feat(prompts): inject plan steps into prompt           [#step-inject]
  feat(facts): yaml + bash parsers                       [#yaml-bash]

P3:
  feat(packs): DomainPack loader + builtin templates     [#pack-loader]
  feat(packs): laravel + beds24 + axum-pms packs         [#builtin-packs]
  feat(prompts): inject pack rules into red team         [#pack-inject]

P4:
  feat(server): run_review one-shot tool                 [#run-review]
  feat(git): auto-detect base_ref + incremental mode     [#incremental]
  feat(facts): toml + json parsers                       [#toml-json]

P5:
  feat(state): false_positive_history + prompt injection [#fp-learning]
  feat(state): empty findings → clean-runs.log           [#empty-archive]
  feat(facts): vue SFC parser                            [#vue]
  feat(facts): parse_error returns recovery options      [#parse-recovery]
```

每個 commit 配 `cargo test` 必過 + `cargo clippy --all-targets` 無 warning。

---

## 9. 風險與陷阱（必讀）

1. **`.blade.php` 行號漂移**：預處理若刪行 → 紅隊回報的 line 對不上原檔。**對策**：預處理只替換不刪行（`@if` → `// @if`，保留原長度或多換行）。

2. **fingerprint false positive on rename**：使用者把 function 整個改名 → fingerprint 變但 code 邏輯沒變 → 自動標 fixed 後新 finding 出現 → 同一問題報兩次。**對策**：fingerprint 衝突時，比對 `symbol_path` 的 simple name（去掉 namespace），若 simple name 同 + line proximity ±20 → 視為 rename，沿用舊 status。

3. **JSON schema 太嚴格 LLM 跑不出來**：紅隊有時會夾 markdown / 解釋文字。**對策**：`strip_markdown_fences` 容錯（剝 ` ```json `）；連續兩次 schema validate 失敗才降級 markdown parser。

4. **Domain Pack 灌爆 prompt**：4 個 pack × 4 個 RT × 1KB = context 暴漲。**對策**：Pack 內標記 `target_red_team`，只灌進相關 RT 的 prompt；單個 pack 限制 ≤ 500 tokens。

5. **incremental 漏網**：A 檔改了，B 檔 caller 沒改但邏輯依賴 A → incremental 只看 diff 會漏 B。**對策**：`extract_facts_incremental` 仍跑 `expand_blast_radius`，把 caller chain 拉進來，不僅看 git diff。

6. **textual fallback 紅隊瞎猜**：精度太低時紅隊會生很多噪音。**對策**：textual 檔的 finding 強制 severity ≤ High（不允許 Fatal）；synthesize 對 textual finding 加 30% impact_score 折扣。

7. **MCP tool 不能 spawn subagent**：`run_review` 只是 prompt 編排器，agent 端仍要自己 dispatch。文件要寫清楚。

---

## 10. 驗收條件（每 Phase 完成判定）

- **P1 完成** = blade.php 不再 parse_error；同 plan 跑兩次，已修的 finding 自動標 fixed；skipped_files 出現在 review output。
- **P2 完成** = 紅隊 prompt 拿到 plan steps；synthesize_findings 拒收空 affected_plan_steps；.yml/.sh 可解析。
- **P3 完成** = `prepare_attack(domain_packs=["beds24"])` 後紅隊 prompt 包含 qty→numAvail 規則；測試專案 PMS 真實計畫跑一次驗證。
- **P4 完成** = `run_review` 一個 call 取代 6 個 call；不指定 base_ref 自動找 origin/main；只跑 diff 影響範圍。
- **P5 完成** = 標 false_positive 後下次同 fingerprint 不再被報；空 findings 不寫 plans/；.vue 的 `<script>` 區段能擷取 function。

---

## 11. 衍生待辦（不在本計畫範圍）

- LSP / rust-analyzer 整合（finding 加 quick-fix link）
- 對接 GitHub PR comment（finding 直接變 PR review comment）
- Web UI 看 state 檔（finding 視覺化、批次操作）
- 多語 plan file 支援（plan 用中文寫時 step 抽取要更穩）

寫入 `~/shared-backlog.md` 對應條目。

---

## 12. 計畫狀態追蹤

- [ ] §1 共通基礎建設
- [ ] §2 Phase 1（fingerprint + skipped + blade + sql + textual）
- [ ] §3 Phase 2（json schema + yaml + bash）
- [ ] §4 Phase 3（domain packs）
- [ ] §5 Phase 4（run_review + incremental + toml/json）
- [ ] §6 Phase 5（FP learning + 空殼歸檔 + vue + parse recovery）

執行時每完成一個 commit 回來打勾。


---
## 🔴 Refinement（紅藍對抗精鍊）
> Refined: 2026-05-05 | Mode: Lite | Agents: 2R+1B

### 發現摘要
- FATAL: 3 個
- HIGH: 4 個

### FATAL 問題
1. **synthesize_findings silent_swallow 吞掉紅隊解析錯誤** (src/server.rs:658-695)
   - 來源：RT-A
   - 問題：synthesize_findings 有兩個 catch_blocks[action=silent_swallow]。§3.2 把 JSON validate 失敗改成 return Err，但若 handler 仍用 silent_swallow 包著 parser 呼叫，parse_red_team_output 的 Err 會被吞、findings 為空、finalize 寫入空 state、真實問題消失
   - 攻擊場景：紅隊回 invalid JSON → schema validate 失敗 → silent_swallow 吞 → MCP 回成功 → state 寫 0 findings → 使用者以為 review 通過
   - 建議修復：§3.2 的 parse_red_team_output 錯誤必須 propagate 到 MCP response；或把 silent_swallow 改成 log_and_return_error
2. **merge_findings 簽名變更但 caller 未同步** (src/state.rs:65-94)
   - 來源：RT-A
   - 問題：§2.1 把 merge_findings 簽名加 &HashMap<PathBuf,Vec<FingerprintEntry>>。若 finalize_refinement 沒同步傳 current_fingerprints，第一次跑時 HashMap 為空，所有有 fingerprint 的 finding 都因 still_present=false 被誤標 fixed
   - 攻擊場景：v0→v1 升級首次跑，舊 state 有 finding（無 fingerprint）+ 新 run 給空 HashMap → 全部誤標 fixed → 用戶以為問題都解決
   - 建議修復：finalize_refinement 必須傳入本次 extract_facts 新算的 fingerprints；測試 fingerprint 為空 HashMap 時不觸發 auto-mark guard：existing.fingerprint.is_some() 才比對
3. **prepare_attack silent_swallow 吞掉 domain pack 注入錯誤** (src/server.rs:446-447)
   - 來源：RT-A
   - 問題：prepare_attack line 446 有 silent_swallow。§4.3 在末段注入 pack 內容，若 load_packs/applies_to() panic，會被吃掉、紅隊 prompt 靜默缺 domain context，函數仍回成功
   - 攻擊場景：使用者指定 domain_packs=[laravel,beds24] → pack 檔損毀 → silent_swallow 吃 → 紅隊不知有 pack → review 漏 PMS 領域陷阱
   - 建議修復：pack 注入邏輯放在 silent_swallow 範圍外；或 pack load 錯誤單獨回 warning 給 caller

### HIGH 問題
1. **Blade 預處理行號漂移** (src/facts/blade.rs:1)
   - 來源：RT-B
   - 問題：{{ $expr }} → <?= $expr ?> 字元數不同（4 bytes wrapper vs 7 bytes）。PHP parser 算出的 offset 對應回 .blade.php 行號會漂移
   - 攻擊場景：紅隊回報 sample.blade.php:42 的 mass assignment，使用者跳到 line 42 看不到問題（實際在 line 39）→ 信不過工具
   - 建議修復：預處理保留每行字元數（pad 到原長度），或在 ExtractResult 附 line offset map 供修正
2. **Incremental + blast_radius 順序錯漏 caller** (src/tools/run_review.rs:1)
   - 來源：RT-B
   - 問題：run_review 先 extract_facts_incremental（只看 diff），再 expand_blast_radius。但 blast_radius caller chain 依賴全庫 symbol index；若 index 未重建，已改 signature 函數的 caller 仍指向舊 index，漏網 caller 不被 review
   - 攻擊場景：改 ChargeService::charge signature，git diff 只有 ChargeService.php，blast_radius 用上次快取 index 找 caller → 漏掉新增加的 caller → 該檔案不在 review 範圍
   - 建議修復：expand_blast_radius 接收 diff 的函數列表並在全庫 index 上查 caller（非只在 diff 內查），確保 index 最新或文件化此限制
3. **JSON 兩次失敗才降級語意不清** (src/parser/mod.rs:65-162)
   - 來源：RT-B
   - 問題：計畫說『連續兩次 schema validate 失敗才降級 markdown parser』，但 synthesize_findings 是一次 MCP call。若無持久化 retry 欄位，第一次失敗 caller 以為成功（silent_swallow），第二次才降級
   - 攻擊場景：紅隊回介於 JSON/markdown 之間的格式 → 第一次 call 失敗但 silent → 第二次重跑才降級 → 中間狀態 state 已被部分寫入
   - 建議修復：語意改成『同一次 call 內 strip_markdown_fences 後仍失敗才降級』（不需跨 call 狀態），或明確定義 retry 持久化欄位位置
4. **plan step regex 抓不到本計畫的 heading 格式** (src/server.rs:430-470)
   - 來源：Blue
   - 問題：§3.3 的 plan step 抽取 regex `^##\s+Step\s+(\d+)` 只抓英文 Step；本計畫用 `### 2.1`、`## 3. Phase 2` 格式，regex 一筆都抓不到，affected_plan_steps 永遠 OUT_OF_SCOPE
   - 攻擊場景：P3 完成後跑 prepare_attack 預注入 plan steps → regex 不匹配 → 紅隊 prompt 沒拿到 step list → 全部標 OUT_OF_SCOPE → §3.1 schema 強制反而失效
   - 建議修復：regex 改支援多種 heading：`^#{2,4}\s+(?:Step\s+)?(\d+(?:\.\d+)?)`；或讓 plan author 明確標註 step list 區塊

### 交叉分析（藍隊）

## Cross-Analysis

### Combination Attacks

1. **Silent failure 串連：紅隊 → synthesize → finalize 全程靜默**（RT-A1 + RT-A3 + RT-B3）
   - 組合情境：`prepare_attack` 因 pack 錯吞 → 紅隊不知缺 context → 紅隊回不合格 JSON → `synthesize` 因 silent_swallow 吞解析錯 → JSON 兩次失敗降級語意不清 → finalize 寫空 state
   - 影響：整條 review pipeline 完全失明，使用者以為「乾淨」實際是「全程失敗」
   - 建議修：所有 silent_swallow 改 log_and_return_error，pipeline 任何一環錯都要冒泡

2. **Auto-fix 誤標 + 行號漂移 = 真問題消失**（RT-A2 + RT-B1）
   - 組合情境：v0→v1 首跑 fingerprint HashMap 空 → 舊 finding 全標 fixed；同時 Blade 預處理行號漂移 → 新 run 報出的 finding 對不上原檔 → 使用者驗證失敗以為誤報 → 標 false_positive
   - 影響：真實問題雙重消失（auto-marked fixed + 手動標 FP）
   - 建議修：v0→v1 升級加「首次保護期」（前 1-2 次 run 不啟用 auto-mark）+ Blade 預處理強制保留行長度

### False Positives

無。7 筆都是高信心 finding。

