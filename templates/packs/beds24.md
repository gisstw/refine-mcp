# Beds24 Domain Pack

Channel-manager integration with Beds24 v2 API. These are real bugs that
have hit production — call them out aggressively even if the generic
analysis would let them pass.

## RT-A: Silent Failure / Type Safety / Idempotency
- Webhook handler must return 200 even on internal failure, otherwise Beds24 retries with same payload — leading to duplicate processing.
- `numAdult` in multi-room bookings is unreliable; iterate `rooms[]` for accurate guest counts.
- Carbon → UTC date push: a Carbon datetime in Asia/Taipei converted to UTC may shift the calendar date by 1 day. Always specify `->utc()->format('Y-m-d')` after `->copy()`.
- Beds24 `bookId` may be reused across properties — always scope by `propertyId` when looking up.

## RT-B: Concurrency / TOCTOU / Behavioral Change
- `qty` change in inventory push silently triggers `numAvail` recalculation downstream — never push them in separate calls.
- Webhook delivery is at-least-once; idempotency must be keyed on (`bookId`, `modifiedTime`) tuple.
- Two-way sync: the local update that triggered the API push will fire again as a webhook on success — guard with a "echo suppression" window or origin tag.
- `priceLinking` cascades: changing one room's price can update linked rooms; assertion that "I only edited room A" is wrong.

## RT-C: Schema Drift / Data Integrity
- `numAvail` is computed by Beds24, never stored locally — querying a stale local copy gives wrong availability.
- Cancelled bookings still count toward `numAdult` until status is reconciled — pricing reports overcount.
- Beds24's `Status` field has values like "BLACK", "REQUEST", "CONFIRMED", "CANCELLED" — do not assume a binary boolean.
- Multi-occupancy `priceN` (price for N guests) defaults to base rate when missing — silent under-pricing.

## RT-D: Authorization / Auth Boundary
- API tokens are property-scoped; using a Token from property A on property B silently returns empty / wrong data, no permission error.
- Webhook signing secret rotation requires both old and new secret accepted during the rollout window.
- `apiKey` vs `propertyApiKey` — different scopes; mixing them up gives unhelpful error messages.
