# server.rs 瘦身重構

## 問題
server.rs 1486 行，有 3 處重複邏輯。

## 重複點

### 1. Plan discovery（~30 行 x2）
- `discover_plan` lines 147-163
- `discover_and_extract` lines 207-230
→ Extract `discover_latest_plan(dir: &Path) -> Result<(PathBuf, String), rmcp::ErrorData>`

### 2. File extraction dispatch（~40 行 x2）
- `extract_facts` lines 350-387
- `discover_and_extract` lines 254-287
→ Extract `run_extraction(file_paths: &[String]) -> (Vec<FactTable>, Vec<String>)`

### 3. Git diff filtering（~10 行 x2）
- `extract_facts` lines 335-345
- `discover_and_extract` lines 238-248
→ Fold into `run_extraction` with `diff_only` param

## 執行步驟

1. [x] 在 server.rs 底部 helpers section 加入 `discover_latest_plan()`
2. [x] 加入 `run_extraction()`
3. [x] 改寫 `discover_plan` 用新 helper
4. [x] 改寫 `discover_and_extract` 用新 helpers
5. [x] 改寫 `extract_facts` 用新 helper
6. [x] `cargo test` 確認全部通過 (123 tests, 0 failed)
7. [x] `cargo clippy` 確認乾淨 (0 warnings)
8. [x] `cargo build --release` 重建 binary
9. [x] Committed: a739852

## 預期結果
- 消除 ~80 行重複
- server.rs 降到 ~1400 行以下
- 測試全部綠燈
