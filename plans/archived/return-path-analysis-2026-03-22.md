# Direction B: Return Path Analysis

## 目標

增強 tree-sitter fact extraction，偵測函數的 return path 模式。
讓紅隊 prompt 能引用具體的 return path 問題，而不是靠 LLM 自己猜。

## 新增 Fact: `ReturnPathFact`

```rust
pub struct ReturnPathFact {
    pub line: u32,
    /// What kind of return this is
    pub kind: ReturnKind,
    /// The return expression (truncated)
    pub expression: String,
}

pub enum ReturnKind {
    /// return ['error' => ...] or return ['success' => false, ...]
    ErrorArray,
    /// return null
    Null,
    /// return value (normal success path)
    Value,
    /// bare return (void)
    Void,
    /// throw new Exception (not a return, but terminates)
    Throw,
}
```

## 新增 Fact: `SilentSkipFact`

偵測 null check → continue/return 而不是 throw 的模式。

```rust
pub struct SilentSkipFact {
    pub line: u32,
    /// What's being checked
    pub check_expression: String,
    /// What happens: "continue", "return null", "return []"
    pub action: String,
}
```

## 偵測邏輯（PHP extractor）

### Return path 分析
在 `method_declaration` 內掃描所有 `return_statement` 節點：
- `return ['error' => ...]` → ErrorArray
- `return null` → Null
- `return;` → Void
- `return $result` → Value

一個函數有 ErrorArray + Value 的混合 return = **mixed return** = 高風險
（caller 必須檢查但很多不會）

### Silent skip 偵測
掃描 `if_statement` 節點：
- condition 包含 `=== null` 或 `!$var`
- body 只有 `continue` 或 `return null` 或 `return`
- → SilentSkipFact

## Attack angle 更新

在 ANGLE_A (Silent Failure) 加入：
```
8. `return_paths` with mixed ErrorArray+Value — caller MUST check but often doesn't
9. `silent_skips` — null check leads to continue/return instead of throw, silently drops data
```

## 實作步驟

- [x] Step 1: types.rs 加入 ReturnPathFact, ReturnKind, SilentSkipFact
- [x] Step 2: PHP extractor 加入 return path 偵測
- [x] Step 3: PHP extractor 加入 silent skip 偵測
- [x] Step 4: FunctionFact 加入 return_paths + silent_skips 欄位
- [x] Step 5: 更新 prompts ANGLE_A 加入新的 attack patterns
- [x] Step 6: 測試 + 編譯 (125 tests, 0 failed)
- [x] Step 7: 建置 release binary (commit 9012138)
