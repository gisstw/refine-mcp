## [RT-A] 靜默失敗 + 型別安全 + 冪等性

### FATAL

1. **cancelAndRefund 外部 API 無補償** (app/Services/ReservationService.php:150-165)
   - 問題：refundPayment() 在 Transaction 內呼叫，失敗後 catch block 只 Log 不回滾
   - 攻擊場景：API 超時 → 金額已退但訂單未更新 → 雙重退款
   - 建議修復：將外部 API 呼叫移出 transaction，使用 saga pattern

2. **deposit FIFO 計算用 VARCHAR 轉數值** (app/Services/DepositService.php:89)
   - 問題：pricing_deposit.price 是 VARCHAR，直接 intval() 轉換無驗證
   - 攻擊場景：非數字字串 → intval() 回傳 0 → 押金計算錯誤

### HIGH

1. **createOnlineReservation 無 Transaction** (app/Services/ReservationService.php:78-95)
   - 問題：create reservation + create room 不在 transaction 內
   - 攻擊場景：DB 失敗 → 孤立的 reservation 記錄無對應房間

## [RT-B] 並發 + TOCTOU + 行為變更

### FATAL

1. **modifyReservation TOCTOU** (app/Services/ReservationService.php:200-220)
   - 問題：find() + update() 不在 transaction 內，無 lockForUpdate
   - 攻擊場景：兩個請求同時修改同一訂單 → 後者覆蓋前者 → 資料遺失

### HIGH

1. **checkout 狀態機無鎖** (app/Services/ReceptionService.php:340)
   - 問題：狀態檢查與更新非原子操作
   - 攻擊場景：雙重 checkout → 重複退押金
