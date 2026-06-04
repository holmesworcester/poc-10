# TODO: Typed Row Codecs

This document records the work needed to replace hand-packed `rows.rs` byte
layouts with named, testable row codecs.

## Why The Current Code Exists

Core row mutations store protocol-owned rows as opaque `(table, key, value)`
bytes. That keeps core protocol-neutral: core can commit idempotent row writes,
delete rows, and enforce table allowlists without knowing whether a row belongs
to auth, connection, content, or sync.

The current `rows.rs` files therefore build `TableRow` values directly:

```rust
let mut value = vec![0; ROW_VALUE_BYTES];
value[0..32].copy_from_slice(&fact.from_endpoint);
value[32..64].copy_from_slice(&fact.to_endpoint);
```

This is correct but too low-level. The layout is fixed-width and deterministic,
but the offsets are invisible policy. Every added field requires synchronized
manual edits to `ROW_VALUE_BYTES`, encode offsets, decode offsets, and tests.

## Problems To Fix

- Offset arithmetic hides field names and makes reviews harder.
- Encode and decode can drift when fields are inserted or reordered.
- Length constants duplicate what the field list already implies.
- Row layouts look different from fact layouts even when they need the same
  fixed-width discipline.
- Simple row modules become noisy, which obscures the projector policy that
  decides when rows are written.

## Target Shape

Keep core's opaque `TableRow` boundary. Do not turn row tables into a generic
ORM or make core understand protocol fields.

Inside each protocol row module, replace manual offsets with a typed codec that
names fields once and provides:

- `encoded_len`
- `encode_value`
- `decode_value`
- row constructor helpers that still return `TableRow`
- golden round-trip tests for key and value bytes

The row module should still own table names, row keys, semantic constructor
names, and decode helpers. The improvement is local layout clarity, not a new
cross-scope data model.

## Candidate Designs

### Cursor Helper

Add a small core helper for fixed-width row values:

```rust
let mut row = RowWriter::<BOOTSTRAP_REQUEST_VALUE_BYTES>::new();
row.bytes32("from_endpoint", fact.from_endpoint);
row.bytes32("to_endpoint", fact.to_endpoint);
row.bytes32("invite_fact_id", fact.invite_fact_id);
```

The matching `RowReader` consumes fields by name and rejects trailing or missing
bytes. This is the smallest step and keeps all row layouts hand-written but
removes offset arithmetic.

### Declarative Row Layout Macro

Add a protocol-facing macro or derive-like helper:

```rust
row_value! {
    BootstrapRequestRowValue {
        from_endpoint: Bytes32,
        to_endpoint: Bytes32,
        invite_fact_id: Bytes32,
        invite_secret_fact_id: Bytes32,
        initiator_ephemeral_secret_fact_id: Bytes32,
    }
}
```

The generated type owns encode/decode, byte length, and row-value round trips.
Row modules call it from their existing `*_row` helpers.

### Reuse Existing Fact Codecs Where Exact

Some rows intentionally store the same bytes as a fact payload. In those cases,
prefer reusing the fact codec or a shared layout type instead of defining a
second row codec. Only do this when row semantics exactly match fact semantics;
projection rows often omit authority fields or add query-specific fields.

## Migration Plan

1. Inventory every `rows.rs` file that manually writes byte offsets.
2. Add a `RowWriter` / `RowReader` helper or a declarative row layout macro.
3. Convert one representative fixed-width row family first:
   `connection/request/rows.rs`.
4. Add golden tests that prove the new codec emits the same bytes as the old
   implementation.
5. Convert the rest of the connection rows, then auth/content/sync rows.
6. Add a guardrail test that flags direct `value[N..M].copy_from_slice(...)`
   in `rows.rs` files outside an explicit temporary allowlist.
7. Remove each allowlist entry as its row module moves to typed codecs.
8. Commit the completed work on that same worktree branch before handoff or
   review.

## Tests

Each conversion should include realistic tests:

- Existing row bytes remain stable for a golden fixture.
- Decode rejects wrong-length row values.
- Encode/decode round trips preserve every named field.
- Row-key helpers are unchanged.
- Projector tests still observe the same materialized rows.
- The guardrail test prevents new manual offset packing in row modules.
