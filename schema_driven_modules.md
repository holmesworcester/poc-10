# Schema-Driven Event Modules

A proposal to collapse `fact.rs`, `layout.rs`, and the boilerplate share of
`create.rs` onto schema generation, leaving only protocol-bearing recipes in
hand-written Rust.

The fixed-length guardrail is already canonical (`new_architecture.md:69-70`,
`RULES.md:82-83`, `new_architecture.md:347-350`). This proposal is about
following through: declare the layouts and constructors as data, generate the
code, and isolate the parts that genuinely deserve hand-written Rust.

## Why

Looking across the 30-plus modules in `src/event_modules/`:

- `fact.rs` is almost always a typed struct with semantic field names.
- `layout.rs` is almost always a tag byte plus fixed-offset writes of those
  fields, paired with a roundtrip test.
- `create.rs` splits into two populations: a thin boilerplate majority
  (validate non-zero ids, build struct, encode, wrap in `Fact::new`) and a
  small crypto-bearing minority that runs real protocol work.

The boilerplate share is mechanical. The repo already has the right primitives
(`src/core/wire.rs` — `FixedLayout`, `Id32`, `U64be`, `Nonce24`, `FixedSlot<N>`,
`Ciphertext<N>`) and a schema DSL parser (`src/core/schema_dsl.rs`). The newer
modules (`transit`, `signed_fact`, parts of `encryption`) already use the
`FixedLayout` trait; the older ones (`content_message`, `content_file`,
`connection_response`) still hand-write byte-offset arithmetic that describes
the same thing the schema would.

## What the schema can absorb

### `fact.rs` — 100%

Every fact in the tree is a struct of fixed-width fields. The minority with
"expressive" content reduces to:

- **Tagged-union enums** (`encryption/fact.rs:18` `WrappedSecretKind`):
  schema enum with explicit discriminants.
- **One-line derived helpers** (`content_message/fact.rs:44` `unix_minute_for`):
  drop the helper, keep the `UNIX_MINUTE_MS` constant, let callers divide; or
  let the schema generate `*_at_minute_of` helpers for any `*_at_ms` field.
- **Constructor / validation methods** (`identity_invite/fact.rs:22`
  `InviteSecretFact::new/scoped/validate`): mechanical once the schema supports
  derived fields (`bootstrap_hash = bootstrap_secret_hash(bootstrap_secret)`)
  and joint-optional groups (`workspace_id` and `invite_event_id` are
  both-Some-or-both-None).

The bodies of named primitives the schema points at (`bootstrap_secret_hash`,
etc.) still live in Rust, but in a crypto-helpers module, not in the fact
module.

### `layout.rs` — 100%

Every layout is "write a tag byte, then concatenate these typed fields at
fixed offsets." The cases that look expressive are either guardrail-compliant
fixed-length already or open deviations that should be fixed:

- `encryption/layout.rs:353` `validate_key_wrap` checks zero-when-not-applicable
  fields on a packed-union struct. A tagged-union schema makes this implicit.
- `encryption/layout.rs:476` `mask_prefix_to_depth` validates that
  `event_id_prefix` (a fixed `[u8; 32]`) is masked to `bit_depth`. Content
  invariant on a fixed field; expressible as a schema constraint.
- `disappearing_messages_setting/layout.rs` encodes `Option<FactId>` as a zero
  sentinel on a fixed `[u8; 32]`. Encoding convention; schema can declare it.
- `identity_workspace/layout.rs` uses `FixedSlot<WORKSPACE_NAME_BYTES>` with
  NUL-terminated decode. Already guardrail-compliant.

### `create.rs` — the boilerplate tail

For protocol modules with no crypto (`identity_workspace`,
`content_file_deletion`, `content_message_deletion`, `signed_fact`,
`removal_frontier`, several others), `create.rs` is: validate ids, build
struct, encode, wrap in `Fact::new` with the right scope and timestamp.
Schema-derivable end-to-end.

For crypto modules (`connection_response`, `content_message`, `encryption`),
the tail of every recipe is the same shape: build the fact struct, encode,
optionally wrap in a signed envelope, return a `Fact` with the right scope.
The schema absorbs that tail. What it does not absorb is the recipe body.

## What stays hand-written

The crypto recipes. They are the protocol; they need to be explicit and
reviewable. Concretely:

- `connection_response/create.rs` — X25519 DH (ee, es), HKDF derivation of
  response key and connection secret, transcript hashing.
- `content/message/create.rs` — deterministic nonce derivation, AEAD encrypt
  of message fields, plaintext padding, signed-envelope wrapping. The old
  `sealed_message` module remains legacy layout/row compatibility, not a
  canonical authoring, runtime-routing, or transport-admission path.
  Its projector exposes authenticated message metadata before decrypt so
  author deletions can purge without keys, while opened message context remains
  gated on successful decryption.
- `encryption/create.rs` — key wrap/unwrap with per-recipient deterministic
  sender keys, AEAD with associated data, dispatch over wrapped-secret kinds.

Net effect after lifting the boilerplate: a 200-line
`connection_response/create.rs` shrinks to roughly 40 lines that read
top-to-bottom as the handshake. The 489-line `encryption/create.rs` becomes
mostly the wrap/unwrap recipe plus deterministic-key derivation. The recipe
stays in Rust where a cryptographer can audit it.

## Schema vocabulary needed

The current `schema_dsl.rs` parses explicit row-table declarations, typed
tables, columns, row keys, and indexes. To absorb fact/layout/create boilerplate
it needs:

1. **Fact-shape declarations**: per-fact tag byte, scope kind (Global, Local,
   Scoped<workspace>, …), timestamp source.
2. **Typed scalar fields** beyond the current `Bytes/U64/I64/Text/Bool`:
   `U16be`, `U32be`, `FixedBytes<N>`, `Id32`, `Hash32`, `Nonce24`,
   `PublicKey32`, `SymmetricKey32`, `Signature64`, `FixedSlot<N>`,
   `Ciphertext<N>`.
3. **Tagged-union enums** with explicit `u8` discriminants and per-variant
   field constraints ("these fields must be zero when variant X").
4. **Sentinel-encoded `Option<T>`** on fixed-byte fields (zero means `None`).
5. **Joint-optional groups** (`{ workspace_id, invite_event_id }` are
   both-Some-or-both-None).
6. **Derived fields** by named function reference
   (`bootstrap_hash: derived(bootstrap_secret, bootstrap_secret_hash)`). The
   function body lives in a Rust crypto-helpers module; the schema only names
   it.
7. **Content invariants** on fixed-byte fields: "non-zero", "masked to
   `bit_depth`", "valid utf-8 with trailing zero padding".
8. **Bound primitives** for crypto recipes — `associated_data`, `transcript`,
   `info` byte builders are field-concatenation with a label. Schema annotation
   like `associated_data(workspace_id, frontier_id, minute)` generates a method
   on the fact; recipes call `fact.associated_data()` instead of building the
   bytes inline.

## Deviations to fix first

The fixed-length guardrail has slipped in a handful of places. The schema
direction does not work until these are converted to `FixedSlot<N>` or
`[u8; N]`, or explicitly justified as bounded opaque slots per `RULES.md:82`.

Open `Vec<u8>` / `String` payloads in `fact.rs`:

| File | Field | Resolution |
| --- | --- | --- |
| `content_event/fact.rs:15` | `payload: Vec<u8>` | Pick a max, use `FixedSlot<N>` |
| `content_file/fact.rs:44` | `sealed_metadata: Vec<u8>` | `FixedSlot<N>` |
| `content_file_slice/fact.rs:28` | `ciphertext: Vec<u8>` | Already bounded by slice size — type as `[u8; N]` |
| `content_reaction/fact.rs:24` | `ciphertext: Vec<u8>` | `[u8; N]` (size constant exists) |
| `identity_endpoint_shared/fact.rs:51` | `device_name: String` | `FixedSlot<N>` (mirror workspace name) |
| `identity_user/fact.rs:16` | `username: String` | `FixedSlot<N>` |
| `sealed_message/fact.rs:28` | `ciphertext: Vec<u8>` | `[u8; CIPHERTEXT_BYTES]` |
| `signed_fact/fact.rs:23` | `payload: Vec<u8>` | Either pick a max envelope size and use `FixedSlot<N>`, or carve out as the documented bounded-opaque exception |
| `transit_received/fact.rs:21` | `origin_addr: Vec<u8>` | `FixedSlot<N>` |

The `signed_fact` payload is the interesting case: it wraps an inner fact and
its size is the sum of inner-fact wire layouts. Two options: declare a global
max (the largest fact in the tree plus envelope overhead) and use
`FixedSlot<MAX>`, or accept signed envelopes as the documented bounded-opaque
slot the guardrail allows.

## Supporting moves for crypto

These are not part of the codegen but make the residual hand-written recipes
shorter and more auditable:

1. **Centralize labels and purpose strings.** `HANDSHAKE_PURPOSE`,
   `CONNECTION_SECRET_PURPOSE`, `KEY_WRAP_PURPOSE`,
   `b"topo key wrap sender x25519 v1"`, `b"topo-bootstrap-token-v1"`,
   `TRANSCRIPT_LABEL` are scattered across modules. They are the
   protocol's domain-separator contract; one `crypto_labels.rs` registry makes
   the set greppable and reviewable as a whole.
2. **Pin KAT vectors per crypto fact.** Known inputs → known fact bytes. Lets
   the recipe be refactored without silently changing the wire shape.
3. **Schema-generated associated-data / transcript builders.** Listed under
   schema vocabulary above; called out separately because it is the single
   move that most shortens the crypto recipes.

## What disappears, what stays

After the work:

- `fact.rs` files — generated. Disappears as a hand-edited file in the tree.
- `layout.rs` files — generated. Same.
- `create.rs` files for non-crypto modules — generated.
- `create.rs` files for crypto modules — still hand-written, now ~30-50 lines
  of recipe each instead of 200-500.
- `core/wire.rs` — unchanged; it is the runtime substrate the generated code
  uses.
- `core/crypto.rs` — unchanged; it is the primitive library the recipes call.
- `core/schema_dsl.rs` — grows to cover the vocabulary above.
- `src/event_modules/schema.p8sql` — grows from table declarations to also
  declare facts, enums, fixed scalars, and per-fact builders.
- One new `crypto_labels.rs` — centralized purpose strings.

## Migration shape

1. **Extend `schema_dsl.rs`** to parse the additional vocabulary. Land it
   under failing tests against a target schema file that exercises each
   feature.
2. **Fix the variable-length deviations** in the table above. Each is a
   self-contained change with a roundtrip test.
3. **Convert one boilerplate module end-to-end** (`identity_workspace` is a
   good candidate — it already has `FixedSlot` and no crypto). Generate
   `fact.rs`, `layout.rs`, `create.rs`. Delete the hand-written files. Land
   the generator behind a feature flag if needed.
4. **Convert remaining non-crypto modules** in batches.
5. **Refactor crypto `create.rs`** to lean on generated AD/transcript
   builders and generated fact constructors. Pin KATs before refactoring.
6. **Centralize purpose strings** as the last cleanup pass.

## What this is not

- Not a crypto DSL. Recipes stay in Rust.
- Not a code-generation framework. The generator is whatever produces Rust
  from the schema AST `schema_dsl.rs` already builds; a small `build.rs` or
  a checked-in generated tree both fit.
- Not a runtime change. The generated code emits the same `FixedLayout` types
  and `Fact::new` calls the hand-written code emits today.
