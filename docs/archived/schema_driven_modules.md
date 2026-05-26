# Schema-Driven Fact Modules

A proposal to collapse `fact.rs`, `layout.rs`, and the boilerplate share of
`create.rs` onto schema generation, leaving only protocol-bearing recipes in
hand-written Rust.

The fixed-length guardrail is already canonical (`new_architecture.md:69-70`,
`RULES.md:82-83`, `new_architecture.md:347-350`). This proposal is about
following through: declare the layouts and constructors as data, generate the
code, and isolate the parts that genuinely deserve hand-written Rust.

## Why

Looking across the protocol fact-family modules in `src/protocol/`:

- `fact.rs` is almost always a typed struct with semantic field names.
- `layout.rs` is almost always a tag byte plus fixed-offset writes of those
  fields, paired with a roundtrip test.
- `create.rs` splits into two populations: a thin boilerplate majority
  (validate non-zero ids, build struct, encode, wrap in `Fact::new`) and a
  small crypto-bearing minority that runs real protocol work.

The boilerplate share is mechanical. The repo already has the right primitives
(`src/core/wire.rs` - `FixedLayout`, `Id32`, `U64be`, `Nonce24`, `FixedSlot<N>`,
`Ciphertext<N>`) and a schema DSL parser (`src/core/schema_dsl.rs`). The newer
modules (`connection::frame`, naturally signed auth/content facts, and
`auth::key_wrap`) use the same fixed-layout primitives as the rest of the
protocol tree. Schema generation should preserve those byte contracts rather
than introduce a second layout vocabulary.

## What the schema can absorb

### `fact.rs` — 100%

Every fact in the tree is a struct of fixed-width fields. The minority with
"expressive" content reduces to:

- **Tagged-union enums** (`auth/key_wrap/fact.rs:18` `WrappedSecretKind`):
  schema enum with explicit discriminants.
- **One-line derived helpers** (`content_message/fact.rs:44` `unix_minute_for`):
  drop the helper, keep the `UNIX_MINUTE_MS` constant, let callers divide; or
  let the schema generate `*_at_minute_of` helpers for any `*_at_ms` field.
- **Constructor / validation methods** (`auth/invite/fact.rs:22`
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

- `auth/key_wrap/layout.rs:353` `validate_key_wrap` checks zero-when-not-applicable
  fields on a packed-union struct. A tagged-union schema makes this implicit.
- `auth/key_wrap/layout.rs:476` `mask_prefix_to_depth` validates that
  `event_id_prefix` (a fixed `[u8; 32]`) is masked to `bit_depth`. Content
  invariant on a fixed field; expressible as a schema constraint.
- `retention_policy/layout.rs` encodes `Option<FactId>` as a zero
  sentinel on a fixed `[u8; 32]`. Encoding convention; schema can declare it.
- `auth_workspace/layout.rs` uses `FixedSlot<WORKSPACE_NAME_BYTES>` with
  NUL-terminated decode. Already guardrail-compliant.

### `create.rs` — the boilerplate tail

For protocol modules with no crypto (`auth_workspace`,
`content_file_deletion`, `content_message_deletion`, `removal_frontier`, several others),
`create.rs` is: validate ids, build
struct, encode, wrap in `Fact::new` with the right scope and timestamp.
Schema-derivable end-to-end.

For crypto modules (`connection_response`, `content_message`, `auth::key_wrap`),
the tail of every recipe is the same shape: build the fact struct, populate
natural signature fields when the family is signed, encode, and return a `Fact`
with the right scope. The schema absorbs that tail. What it does not absorb is
the recipe body.

## What stays hand-written

The crypto recipes. They are the protocol; they need to be explicit and
reviewable. Concretely:

- `connection_response/create.rs` — X25519 DH (ee, es), HKDF derivation of
  response key and connection secret, transcript hashing.
- `content/message/create.rs` — deterministic nonce derivation, AEAD encrypt
  of message fields, plaintext padding, and natural content-message signing.
  Its projector exposes authenticated message metadata before decrypt so
  author deletions can purge without keys, while opened message context remains
  gated on successful decryption.
- `auth/key_wrap/create.rs` — key wrap/unwrap with per-recipient deterministic
  sender keys, AEAD with associated data, dispatch over wrapped-secret kinds.

Net effect after lifting the boilerplate: a 200-line
`connection_response/create.rs` shrinks to roughly 40 lines that read
top-to-bottom as the handshake. The 489-line `auth/key_wrap/create.rs` becomes
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

## Fixed-Field Guardrail

Protocol fact structs use fixed-width fields at the fact boundary:
`FixedSlot<N>`, `FixedText<N>`, fixed arrays, or bounded structs that encode to
a fixed layout. Shareable facts carry natural signer fields directly in their
family layout. Projectors verify those signatures while projecting their own
payloads, and deterministic `key_wrap` remains the raw exception.

The schema direction depends on this invariant. Generated fact declarations
should reject public `Vec<T>` and `String` fields in `fact.rs`, keep opaque
payloads bounded by named constants, and treat connection frames as fixed
small, file-slice, or bundle carriers rather than open byte arrays.

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
- `src/protocol/facts/schema.p8sql` — grows from table declarations to also
  declare facts, enums, fixed scalars, and per-fact builders.
- One new `crypto_labels.rs` — centralized purpose strings.

## Migration shape

1. **Extend `schema_dsl.rs`** to parse the additional vocabulary. Land it
   under failing tests against a target schema file that exercises each
   feature.
2. **Fix the variable-length deviations** in the table above. Each is a
   self-contained change with a roundtrip test.
3. **Convert one boilerplate module end-to-end** (`auth_workspace` is a
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
