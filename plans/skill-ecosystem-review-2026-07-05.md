# Skill 生態系體檢 + refine 迭代（2026-07-05, session d272211e）

目標（/goal）：review 自製 skills（特別是 refine）→ 迭代改善 → 上網找缺口 skill 安裝 → 測試到滿意。

## 範圍
- **refine-mcp**（`/home/www/refine-mcp`，Rust，MCP server `/home/www/bin/refine-mcp`）
  - 已知 bug：quick_review 自動偵測猜錯新建檔名靜默漏審（memory `refine-quick-review-file-detection-gap.md`，2026-07-02）
- **自製 harness skills**（`~/.claude/skills/`）：clarify-prompt, dispatching-workers, panel-review, design-roundtable, design-deepen, plan-html-output, capture-error, consolidate-lessons
- **自製 domain skills**：beds24-ops, elastix-pbx, playwright-ui-test, pms-usability, rust-pms, rust-style, openscad ＋ crate skills（askama/axum/sqlx/tower-sessions/rust_decimal/rustdoc/rust-analyzer-ss[r]）
- **外部缺口**：op-do 上網調查可安裝 skill collections（anthropics/skills、awesome lists、everything-claude-code 更新等）

## 步驟
- [x] 1. Explore 盤 refine-mcp：根因=get_changed_files 只跑 git diff/--cached 看不到 untracked（src/server.rs:1864-1905）；無漏審警告；git 無 current_dir；該區零測試
- [x] 2. Worker A review harness skills：6 需修（panel-review 正名×2 skill / OP_SKIP_GUARDRAILS 變數名錯 / clarify-prompt chrome-devtools 殘留 / capture-error 詞表過時 / consolidate-lessons 脫節）
- [x] 3. Worker B review domain skills：elastix-pbx namespace 少 Channels / playwright-ui-test 孤兒 skill.md+triggers 欄位 / rust-pms 定位過時 / openscad 只寫 brew / rust-analyzer-ss 空殼 / 5 crate skill 缺 reference（backlog）
- [x] 4. cargo test baseline：BASELINE: 217p/0f/0s
- [x] 5. op-do 上網查缺口：superpowers/example-skills 已最新已裝（本機複驗推翻其 2 條建議）；ECC 為主要來源
- [x] 6. refine 修復完成：`46b90d7`（untracked 偵測+repo_root+not_reviewed_warnings）→ §16.1 red-team 抓 2 HIGH（git diff vs ls-files 路徑基準不一致／repo_root 錯誤與無改動混淆，皆實驗佐證）→ 追修 `bec666b`（toplevel 正規化+明確錯誤）→ 親驗 222p/0f、clippy/fmt 綠 → 已部署 /home/www/bin/refine-mcp（mv 原子替換，2026-07-05 20:08）
- [x] 7. 自製 skills 迭代：commit `4faca44`（domain 批）+`b6842de`（harness 批+op-do wrapper OP_SKIP_GUARDRAILS 實測）+`4f0b773`（elastix namespace）
- [x] 8. 外部 skill：ECC 4 件抄入+在地化+主線程安全審查（commit `843ddcc`），frontmatter YAML 修復（`fb0b6f3`）後全部正常註冊（description+觸發詞已生效）；superpowers 6.1.1/example-skills 經查已裝最新免動作
- [x] 9. 總驗收（新 binary JSON-RPC stdio 實測）：untracked migration 進審查並標 `(untracked)` ✅／.txt 進 `⚠️ 未納入審查` ✅／repo_root=子目錄仍全庫掃+絕對路徑 ✅／無效 repo_root 回明確錯誤+warn log ✅；新 skill 4 件 YAML 解析+註冊+觸發詞全部生效（fb0b6f3 後 Skill 清單確認）
- [x] 10. 收尾：memory 改寫（gap→已修復+用法）+MEMORY.md 索引、lessons 3 筆（35ef337+NAS）、backlog 3 筆 TASK、HTML viewer 產出（第一次 op-do 沙箱讀不到模板半途而廢→workdir 改 /home/www 重跑成功 52.5K；踩點已回寫 dispatching-workers §6.1+plan-html-output）、handoff 全程滾動更新
- 附帶修復：confab-write-gate 誤擋真 refine-mcp commit → 已知 repo 補列（~/.claude `60e161f`）

## 已知事實
- chrome-devtools-mcp 政策上已停用（§16.2 改用 Playwright MCP）但 `claude mcp list` 顯示仍 Connected —— 待處理不一致
- refine-mcp git HEAD: 20c2e38（style: cargo fmt），working tree 乾淨
- op-do 後端見 `~/.config/opencode/op-default-model`
