# Laravel Domain Pack

Production Laravel pitfalls — apply these even when the generic red team
analysis would not flag them, because they map to real incidents.

## RT-A: Silent Failure / Type Safety / Idempotency
- Mass assignment without `$fillable` or `$guarded` allows attacker-controlled fields.
- `find($id)` returns `null` silently; prefer `findOrFail($id)` when callers assume the row exists.
- `firstOrCreate` is **not** atomic; concurrent requests can race past the existence check.
- `Model::updateOrCreate` race: same as above; use a unique index + `insertOrIgnore`.
- `Auth::user()` inside a queued job / scheduled command returns `null` — the request user is gone.
- `dispatch(...)` swallows exceptions if the job class throws in `handle()` without `failed()` defined.

## RT-B: Concurrency / TOCTOU / Behavioral Change
- Eloquent updates without `lockForUpdate()` race with parallel writers; the lost-update is silent.
- `optimisticLock` (per-row version column) is opt-in; absence means concurrent edits clobber each other.
- Queue worker restarts during long jobs lose state if the job isn't idempotent (`tries` retry).
- Cache forget+set is not atomic; use `Cache::lock` or atomic operations.

## RT-C: Schema Drift / Data Integrity
- Migration without a `down()` method blocks rollback in production.
- `Schema::dropColumn` without a foreign-key check breaks referential integrity silently.
- Adding a `NOT NULL` column without `->default(...)` or a backfill migration breaks deployment.
- Renaming a column requires `doctrine/dbal` and is a breaking change for all consumers.
- Deferred constraints in MySQL aren't enforced until commit — partial-success still corrupts data.

## RT-D: Authorization / Auth Boundary
- `auth()->user()->id` instead of `Auth::id()` panics in tests where there's no user.
- Form Request `authorize()` returning `true` bypasses policy checks — easy to forget on new endpoints.
- `Gate::allows` / `Gate::check` skipped on routes lacking middleware (`auth` / `verified`).
- `policy() = scope_via_owner_id` checks but doesn't constrain the query — use `Scope` traits.
- Implicit route model binding (`Route::get('/posts/{post}')`) bypasses policy if the controller doesn't `authorize()`.
- Cookie scope: `secure`/`http_only`/`same_site` defaults are environment-dependent; check `config/session.php`.
