[English](README.md) | 繁體中文

# refine-mcp

**改了什麼、破壞了誰 — commit 前就知道。**

tree-sitter 從程式碼提取結構化事實（函數簽名、參數、回傳型別）。當你修改程式碼，refine-mcp 比較修改前後的 AST 結構，偵測破壞性變更、找出受影響的呼叫者、測量程式碼健康度。全程透過 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 編排。

## 運作原理

```
 你的程式碼變更
       │
       ▼
┌─────────────────┐     ┌──────────────────┐
│   tree-sitter   │────▶│  structural_diff  │──▶ 破壞性變更
│   (4 種語言)     │     │  (前後比對)        │    (簽名變更、新增/移除函數)
└─────────────────┘     └──────────────────┘
       │
       ├──────────────▶ ┌──────────────────┐
       │                │ impact_analysis   │──▶ 受影響的呼叫者
       │                │ (影響範圍分析)      │    (誰呼叫了你改的東西)
       │                └──────────────────┘
       │
       └──────────────▶ ┌──────────────────┐
                        │ health_snapshot   │──▶ 複雜度指標
                        │ (逐函數分析)        │    (巢狀深度、分支數、參數數)
                        └──────────────────┘
```

**核心洞察**：LLM 讀程式碼像人類掃過去 — 大檔案中容易漏掉結構變更。tree-sitter 解析 AST（免費、100% 精確），能捕捉每一個 LLM 可能遺漏的簽名變更、移除函數和新增參數。

## 為什麼需要這個工具？

| 能力 | LLM (1M context) | grep/ripgrep | refine-mcp |
|------|------------------|-------------|------------|
| 偵測簽名變更 | 大檔案可能漏掉 | 做不到（文字級） | **100% 精確（AST）** |
| 找出所有呼叫者 | 可能漏掉 | 字串比對（有誤判） | grep + 定義過濾 |
| 測量複雜度 | 估算 | 做不到 | **精確 tree-sitter 指標** |
| 比較 git ref | 要讀兩個版本 | 只有文字 diff | **AST 級結構 diff** |

## 支援語言

| 語言 | 提取器 | Grammar |
|------|--------|---------|
| PHP | `extract_php_facts` | tree-sitter-php 0.24 |
| Rust | `extract_rust_facts` | tree-sitter-rust 0.23 |
| TypeScript/JavaScript | `extract_ts_facts` | tree-sitter-typescript 0.23 |
| Python | `extract_python_facts` | tree-sitter-python 0.23 |

## 安裝

### 從原始碼

```bash
git clone https://github.com/gisstw/refine-mcp.git
cd refine-mcp
cargo build --release
# Binary 在 target/release/refine-mcp
```

### 用 cargo

```bash
cargo install refine-mcp
```

## 快速開始

### Claude Code MCP 設定

加到 Claude Code 的 MCP 設定：

```json
{
  "mcpServers": {
    "refine": {
      "command": "/path/to/refine-mcp"
    }
  }
}
```

### 典型工作流

```
1. 修改程式碼
2. structural_diff   → 哪些簽名變了？有破壞性變更嗎？
3. impact_analysis   → 誰呼叫了我改的函數？
4. health_snapshot   → 程式碼有沒有變更複雜？
5. 修正問題，安心 commit
```

## MCP 工具

### structural_diff

比較兩個 git ref 之間的函數簽名（或 git ref vs 工作目錄）。偵測新增、移除、變更的函數並分類破壞性變更。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `file_paths` | string[] | 是 | 要分析的檔案 |
| `base_ref` | string | 否 | "之前"的 git ref（預設：`HEAD`） |
| `compare_ref` | string | 否 | "之後"的 git ref（預設：工作目錄） |

**破壞性變更偵測：**
- 回傳型別變更
- 參數新增/移除
- 參數型別變更
- 參數順序變更
- nullable → non-nullable

### impact_analysis

在整個 codebase 中找出指定函數的呼叫者。未提供 symbols 時自動從 git diff 偵測。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `symbols` | string[] | 否 | 要搜尋的函數名。未提供時從 git diff 自動偵測 |
| `search_paths` | string[] | 否 | 搜尋目錄（預設：`["app/", "routes/", "src/"]`） |
| `exclude_files` | string[] | 否 | 排除的檔案 |
| `source_files` | string[] | 否 | 用於自動偵測變更 symbols 的來源檔案 |
| `max_per_symbol` | number | 否 | 每個 symbol 最大結果數（預設：20） |

### extract_facts

對原始碼檔案執行 tree-sitter 分析，回傳逐函數的結構化事實。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `file_paths` | string[] | 是 | 原始碼路徑 |
| `diff_only` | bool | 否 | 為 true 時只分析 git 變更的檔案 |

### extract_schema

解析 Laravel migration 檔案，提取資料庫 schema。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `migration_dir` | string | 否 | migration 目錄路徑（預設：`database/migrations`） |

### health_snapshot

計算逐函數的健康度指標，自動生成警告。

| 參數 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `file_paths` | string[] | 是 | 要分析的檔案 |

**每個函數的指標：**
- 行數（> 50 警告）
- 參數數量（> 5 警告）
- 最大巢狀深度（> 4 警告）
- 分支數量（if/for/while/match/switch）

## 授權

以下任一授權：

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))
