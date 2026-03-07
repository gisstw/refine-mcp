[English](README.md) | 繁體中文

# refine-mcp

**別讓 AI 猜漏洞 — 讓它推理結構化事實。**

tree-sitter 從程式碼提取事實（交易、鎖、mutation、例外處理），LLM 紅隊只負責推理這些事實找漏洞，藍隊交叉分析過濾假陽性。全程透過 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 編排。

## 核心概念

> LLM 擅長**推理**，但讀程式碼又慢又貴。
>
> 讓 tree-sitter 讀程式碼（免費、100% 準確），LLM 只負責推理結構化事實。
> 紅隊 token 省 ~66%，藍隊 token 省 ~80%。

```
原始碼                          LLM 紅隊（2-4 支）
    │                               │
    ▼                               ▼
┌─────────────┐  事實表格    ┌───────────────┐  原始發現
│ tree-sitter │──────────────▶│  RT-A  RT-B   │─────────────┐
│  提取器     │               │  RT-C  RT-D   │             │
└─────────────┘               └───────────────┘             │
                                                            ▼
計畫檔案 ─────────────────────────────────────▶ ┌─────────────────┐
                                                │    合成引擎      │
                                                │ 去重 + 驗證      │
                                                │ + 排序 + 評分    │
                                                └────────┬────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────┐
                                                │    藍隊          │
                                                │ 交叉分析 +       │
                                                │ 假陽性過濾       │
                                                └────────┬────────┘
                                                         │
                                                         ▼
                                                   最終報告
```

## 為什麼用這種方法？

大多數 AI Code Review 工具（CodeRabbit、Sourcery 等）把程式碼當散文讀 — 把 raw diff 丟給 LLM，期待它能找到問題。結果是幻覺、漏掉並發 bug、浪費 token。

**refine-mcp 走不同的路：**

| 面向 | 傳統 AI Review | refine-mcp |
|------|---------------|------------|
| LLM 輸入 | 原始碼 / diff（數千行） | 結構化事實表（交易、鎖、mutations、catch blocks） |
| 分析基礎 | 「讀了猜一猜」 | 基於 AST 提取的硬事實 |
| 並發 bug | 通常漏掉（需多步推理） | 專門的 RT-B 團隊 + 鎖/交易事實 |
| 假陽性 | 高（無過濾） | 藍隊交叉分析 + 持久化狀態追蹤 |
| Token 成本 | 程式碼 100% 作為輸入 | ~34%（紅隊）/ ~20%（藍隊） |
| 多輪追蹤 | 無 | `.state.json` — 已修/假陽性不會重複出現 |

### 智慧紅隊分派

紅隊不是盲目丟給 LLM。每支紅隊有**專門的 prompt template** 聚焦特定漏洞類型，並根據**事實信號動態啟用**：

```
tree-sitter 提取的事實
    │
    ├─ 有無交易保護的 mutation？ ─────► 啟用 RT-C（資料完整性）
    ├─ 交易內有外部呼叫？ ───────────► 啟用 RT-C
    ├─ 檔案路徑含 auth/permission？ ─► 啟用 RT-D（權限邊界）
    └─ 永遠 ─────────────────────────► RT-A（單一操作）+ RT-B（多操作）
```

分派決策本身**零 LLM 成本** — 完全由 tree-sitter 事實驅動。

省略 `red_count` 時，`prepare_attack` 回傳 `dispatch` 欄位，解釋**為什麼**每支紅隊被啟用或跳過：

```json
{
  "dispatch": {
    "activated": ["RtA", "RtB", "RtC"],
    "reasoning": [
      "RT-A (single-op): always active",
      "RT-B (multi-op): always active",
      "RT-C (data integrity): 3 mutations without transaction in PaymentService.php::transferFunds",
      "RT-D (auth boundary): skipped (no signals)"
    ]
  }
}
```

### 兩個正交維度

1. **紅隊角色** = 攻擊什麼（prompt template 特化）
2. **模式** = 用多聰明的模型（opus / sonnet / haiku）

這兩者獨立。你可以用 haiku 跑 RT-A~D 做快速篩查，也可以用 opus 做深度分析。

## 支援語言

| 語言 | 提取器 | Grammar 版本 |
|------|--------|-------------|
| PHP | `extract_php_facts` | tree-sitter-php 0.24 |
| Rust | `extract_rust_facts` | tree-sitter-rust 0.23 |
| TypeScript / JavaScript | `extract_ts_facts` | tree-sitter-typescript 0.23 |
| Python | `extract_python_facts` | tree-sitter-python 0.23 |

### 提取的事實類型

每個函數會被分析以下面向：

| 事實 | 說明 |
|------|------|
| **Transaction** | 資料庫交易邊界、是否有 `lock for update` |
| **Locks** | 並發鎖（行鎖、快取鎖、共享鎖） |
| **Catch Blocks** | 例外處理分類（重拋、記錄後返回、靜默吞掉） |
| **External Calls** | API / 網路呼叫，特別是在交易內的 |
| **State Mutations** | Create / Update / Delete 操作及其目標 |
| **Null Risks** | 可能的空值解引用 / unwrap / panic 位置 |
| **Parameters** | 參數型別提示與可空性 |

## 安裝

### 從原始碼編譯

```bash
git clone https://github.com/gisstw/refine-mcp.git
cd refine-mcp
cargo build --release
# 二進位檔在 target/release/refine-mcp
```

### 用 cargo 安裝

```bash
cargo install refine-mcp
```

## 快速開始

### 1. 設定 Claude Code MCP

在 Claude Code 的 MCP 設定中加入：

```json
{
  "mcpServers": {
    "refine": {
      "command": "/path/to/refine-mcp"
    }
  }
}
```

### 2. 基本工作流程

完整的精煉流程有 5 步（或用合併工具 4 步）：

```
步驟 1: discover_plan        → 找到計畫檔，提取引用的原始碼路徑
步驟 2: extract_facts        → 對引用檔案執行 tree-sitter 分析
步驟 3: prepare_attack       → 從事實表產生紅隊 prompt
        （啟動 2-4 個 LLM agents 執行紅隊 prompt）
步驟 4: synthesize_findings  → 解析紅隊輸出、去重、排序、產生藍隊 prompt
        （啟動 1 個 LLM agent 執行藍隊 prompt）
步驟 5: finalize_refinement  → 將發現寫回計畫檔
```

也可以用 `discover_and_extract` 把步驟 1+2 合併成一次呼叫。

### 3. 一鍵使用（推薦）

如果你有設定 Claude Code 的 [refine skill](https://code.claude.com/docs)，只需要：

```
/refine           ← 使用預設模式（Opus）
/refine lite      ← 使用 Sonnet（更便宜）
/refine auto      ← 使用 Haiku（最便宜）
```

## MCP 工具一覽

### discover_plan

找到最近修改的計畫檔，提取其中引用的原始碼路徑。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `plan_dir` | string | 否 | 搜尋目錄（預設 `.claude/plans/`） |

### extract_facts

對原始碼檔案執行 tree-sitter 分析，產生 JSON 事實表。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `file_paths` | string[] | 是 | 原始碼檔案的絕對路徑 |
| `diff_only` | bool | 否 | 為 true 時只分析 git 有變更的檔案 |

### discover_and_extract

合併 discover + extract，一次呼叫完成。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `plan_dir` | string | 否 | 搜尋目錄 |
| `diff_only` | bool | 否 | 只分析 git 變更檔案 |

### prepare_attack

從計畫內容和事實表產生紅隊攻擊 prompt。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `plan_path` | string | 是 | 計畫檔路徑 |
| `facts_json` | string | 是 | extract_facts 回傳的 JSON |
| `mode` | string | 否 | `default`（Opus）/ `lite`（Sonnet）/ `auto`（Haiku） |
| `red_count` | u8 | 否 | 紅隊數量（2-4）。省略時根據事實自動選擇 |

### synthesize_findings

解析紅隊 markdown 輸出，去重、驗證、排序，產生藍隊 prompt。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `raw_reports` | string[] | 是 | 各紅隊的 markdown 原始輸出 |
| `plan_path` | string | 否 | 計畫檔路徑（用於持久化狀態） |
| `plan_summary` | string | 否 | 計畫概要（給藍隊的上下文） |
| `mode` | string | 否 | 成本模式 |

### finalize_refinement

備份計畫檔並附加精煉報告。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `plan_path` | string | 是 | 要附加報告的計畫檔 |
| `blue_result` | string | 否 | 藍隊分析輸出 |
| `findings_json` | string | 是 | synthesize 回傳的 JSON |
| `mode` | string | 否 | 成本模式 |

### expand_blast_radius

搜尋被修改函數的呼叫者，評估變更影響範圍。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `symbols` | string[] | 否 | 要搜尋的函數名稱。省略時從 git diff 自動偵測 |
| `search_paths` | string[] | 否 | 搜尋目錄（預設 `["app/", "routes/"]`） |
| `exclude_files` | string[] | 否 | 排除的檔案（通常是正在修改的源檔案） |
| `plan_files` | string[] | 否 | 計畫檔路徑（用於自動偵測變更的函數） |
| `max_per_symbol` | number | 否 | 每個 symbol 的最大搜尋結果數（預設 20） |

### extract_migration_facts

從資料庫 migration 檔案提取 schema 資訊，供紅隊參考。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `migration_dir` | string | 否 | Migration 目錄路徑（預設 `database/migrations`） |
| `table_filter` | string[] | 否 | 只包含指定的表名 |

## 紅隊角色

| ID | 名稱 | 攻擊角度 | 自動選擇條件 |
|----|------|----------|-------------|
| RT-A | 單一操作 | 靜默失敗、型別安全、冪等性 | 永遠啟用 |
| RT-B | 多操作 | 並發競態、TOCTOU、行為變更 | 永遠啟用 |
| RT-C | 資料完整性 | Schema 漂移、約束違規、部分寫入 | 偵測到：無交易的 mutation、交易內的外部呼叫、靜默吞掉例外 |
| RT-D | 權限邊界 | 權限檢查、IDOR、越權操作 | 偵測到：檔案路徑含 auth / permission / middleware / login / session / guard / policy / role / access / token |

當 `prepare_attack` 的 `red_count` 參數省略時，工具會根據事實表中的信號自動選擇啟用哪些紅隊。RT-A 和 RT-B 永遠啟用；RT-C 和 RT-D 僅在事實表有相關信號時才啟用。

## 成本模式

| 模式 | 紅隊模型 | 藍隊模型 | 適用場景 |
|------|---------|---------|---------|
| `default` | Opus | Opus | 最高準確度 |
| `lite` | Sonnet | Sonnet | 成本與品質平衡 |
| `auto` | Haiku | Haiku | 快速篩查，最低成本 |

## 去重與評分

發現的問題會被去重：
- **同一檔案 + 重疊行號範圍** → 合併
- **同一檔案 + 相似標題**（Levenshtein 相似度 ≥85%）→ 合併

**影響分數** = `嚴重度權重 × 領域權重 / 10 + 來源加分`

- 嚴重度：Fatal = 100, High = 60
- 領域權重：Payment/Billing（30）> Services（20）> Controllers（15）> Models（12）> 預設（10）> Views（5）> Config/Test（3）
- 來源加分：被多支紅隊同時發現 → +20

## 持久化狀態

每次精煉的結果會保存在 `.state.json` 檔案中，跨次執行追蹤：
- 已確認的問題不會重複報告
- 標記為「已修復」或「假陽性」的問題會被過濾
- 支援多輪迭代精煉

## 授權

本專案採用雙授權：

- Apache License, Version 2.0（[LICENSE-APACHE](LICENSE-APACHE)）
- MIT License（[LICENSE-MIT](LICENSE-MIT)）

您可自行選擇其一。
