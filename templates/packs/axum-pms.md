# axum + PMS Rust Stack Domain Pack

Domain pack for Rust services in the PMS rewrite (axum + sqlx + tower-sessions).

## RT-A: Silent Failure / Type Safety / Idempotency
- Storing `Rc<T>` in axum `State<...>` does not compile (handlers require `Send + Sync`); always use `Arc<T>`.
- `sqlx::query!` macro errors caught with `?` propagate but lose query context — wrap with `anyhow::context` for usable logs.
- `Option<T>` returned from handlers serializes to `null` — the API contract loses information unless `serde(skip_serializing_if = "Option::is_none")` is applied.
- `tower-sessions` `cycle_id` must be called on privilege change (login/logout); skipping it lets session fixation through.
- `tracing::warn!()` in an async block runs at log time, not statement time — context may have moved on.

## RT-B: Concurrency / TOCTOU / Behavioral Change
- `Arc<Mutex<T>>` across `await` causes the future to be `!Send`; wrong lock choice deadlocks tokio's multi-threaded runtime.
- `sqlx::Transaction<'a, MySql>` cannot escape the closure passed to `transaction(...)`; trying to return it gives lifetime errors.
- `tokio::spawn`-ed tasks must be `Send`; capturing non-`Send` state silently breaks parallel execution.
- `tower::Service::poll_ready` must be checked before every `call`; skipping it loses backpressure.

## RT-C: Schema Drift / Data Integrity
- `sqlx::query!` validates SQL at compile time against `DATABASE_URL` schema — a migration not yet applied locally compiles against stale schema.
- `BIGINT UNSIGNED` in MySQL maps to `u64` in sqlx, not `i64` — a type mismatch is a runtime error.
- `decimal` stored as `DECIMAL(10,2)` in DB but read as `f64` loses precision silently — use `rust_decimal::Decimal`.
- Soft-delete with a `deleted_at` column requires every query to filter — easy to forget; consider a view.

## RT-D: Authorization / Auth Boundary
- `axum::extract::Extension<User>` will panic if the middleware that injects it is missing — auth bypass via routing typo.
- `tower-sessions` cookie defaults: `secure: true` requires HTTPS; running locally over HTTP silently drops the cookie.
- CORS layers added at the wrong nesting level (`Router::merge` vs `Router::nest`) leak unintended origins.
- `axum::extract::Path<i64>` accepts any signed 64-bit integer — negative IDs slip past unless you parse `u64`.
