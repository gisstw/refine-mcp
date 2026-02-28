## [RT-A] Concurrency and Silent Failures

### FATAL

1. **Race condition in session cleanup** (`watcher.rs:137`)
   - 問題：cleanup runs without lock, concurrent send may use stale handle
   - 攻擊場景：session cleanup + message send → use-after-free on handle
   - 建議修復：wrap cleanup in RwLock write guard

2. **Transcript write not atomic** (watcher.rs:L200-L215)
   - 問題：write_all + flush not in single lock scope
   - 攻擊場景：concurrent writes interleave → corrupted JSONL

### HIGH

1. **Stale route on reconnect** (handlers.rs, watcher.rs)
   - 問題：reconnect does not invalidate old watcher route
   - 攻擊場景：messages delivered to dead session

## [RT-B] Type Safety and Idempotency

### FATAL

1. **Format string injection** (format.rs:111)
   - 問題：user input interpolated into format template without escaping
   - 攻擊場景：crafted message with {} → runtime panic on fmt

### HIGH

1. **Config reload ignores parse errors** (config.rs, state.rs, handlers.rs)
   - 問題：toml::from_str error silently falls back to default config
   - 攻擊場景：typo in config file → silent behavior change
