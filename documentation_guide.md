# Documentation Guide

This project should document core code in the style used by the Stellar core
tree: concise prose that tells the reader what a component is for, how it works,
what invariants it relies on or provides, and where a future change belongs.

The goal is not to make comments longer. The goal is to make ownership and
mechanism explicit enough that a maintainer can change the right file without
reverse-engineering the boundary from call sites.

## Source Examples

The examples below come from Stellar Core, using repo-relative paths from that
project.

### Open With The Model

`src/ledger/readme.md` starts by defining the domain object before naming
implementation details:

```text
A ledger represents the state of the Stellar universe at a given point in time.
```

It then explains mechanism and structure: SCP chooses a transaction set, the
ledger is linked to its predecessor, and `LedgerHeader` carries references to
the actual data. Use this pattern for subsystem files:

```rust
//! Standing context relationships used to wake fact projection.
//!
//! Context is the durable matching surface between projectors...
```

Start with the thing, not the file. Then name the machinery.

### Explain Redundant Or Surprising State

`src/bucket/readme.md` explains why ledger state exists in SQL and in the
BucketList: one form is good for lookup, the other for hashes and catchup. That
style is useful whenever a file appears to duplicate state.

Use it here for pairs such as `facts` and `local_fact_admissions`, or durable
and ephemeral intent queues. The prose should say why both exist and what
each one owns.

### Mark The Boundary

`src/rust/src/soroban_proto_any.rs` explains that one module is mounted under
several protocol adaptor modules and therefore can only use the intersection of
their interfaces. The key pattern is:

```text
If you cannot write code that is "version agnostic" in this way, you need to
write some adaptor code...
```

Use the same directness in core files. Say where a change belongs:

```rust
//! If a new relationship can be expressed as exact equality, add its role to
//! `ContextMatchers::new`. If the relationship needs range, prefix, visibility,
//! or other protocol semantics, implement `ContextMatcher` in the module that
//! owns those semantics.
```

This is the "realm of responsibility" sentence. Every core file should have
one, either in the module docs or near the public type that defines the boundary.

### State The Invariant Before The Helper

`src/rust/src/soroban_module_cache.rs` explains why the cache must hold
multiple protocol-specific caches simultaneously before showing the struct. It
does not just say "cache for Soroban modules"; it says why the shape is
necessary.

Use the same pattern for helpers:

```rust
/// Projection output replaces the previous set for that owner. This replacement
/// model is what prevents stable unmet needs from self-waking forever.
```

Inline docs should cover the invariant the function relies on or preserves, not
just restate the signature.

### Keep Mechanism Concrete

`src/transactions/readme.md` describes validity and application as separate
operations, then lists the actual steps. For pipeline code, prefer the same
shape:

```rust
//! It claims the next row for a registered kind, loads only the facts requested
//! by the handler, calls the handler, and commits the row deletion plus handler
//! effects in one transaction.
```

This tells the reader the order and the atomic boundary. Avoid vague phrases
such as "handles dispatch" when the order matters.

## How To Use This Style

For each file, write the opening docs in this order:

1. Purpose: what this file owns in the system.
2. Mechanism: the main flow or data shape it uses.
3. Invariants: what callers may rely on, and what the file assumes.
4. Responsibility: where to make related changes, and what does not belong here.

For public structs, traits, and important helpers:

1. Say what boundary the type or function represents.
2. Name the atomicity, idempotence, ordering, or ownership rule if there is one.
3. Say what the caller still owns.

Examples:

```rust
/// Queue identity is `(kind, idempotence_key)`. Re-inserting the same payload is
/// a no-op; a different payload for the same identity rejects because dispatch
/// would no longer know which work item the key names.
```

```rust
/// Core stores and sorts these bytes, but never parses them. If matching needs
/// range, prefix, or version semantics, that logic belongs in the module's
/// `ContextMatcher`, not in this type.
```

## Review Checklist

Use this checklist when touching a core file:

1. Can a reader say what this file owns after the first two paragraphs?
2. Does the prose explain the main mechanism without narrating every line?
3. Are atomic commit, idempotence, ordering, and replacement rules named?
4. Does it say what the file must not know or do?
5. Does it point future changes to the right module?
6. Are inline comments attached to real invariants rather than obvious code?

If documentation has to fight the file to explain it, do not keep adding prose.
Flag the structural issue and consider splitting the file or moving the
responsibility to the module that owns the semantics.
