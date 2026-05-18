# Projector Style Guide

This guide describes the production projector style for poc-10. The goal is
not minimal line count. The goal is that a reviewer can read the policy,
follow the context proof, and see exactly why a fact is parked, rejected, or
materialized.

Inline documentation is part of the projector. Use it freely when it explains a
security invariant, wake-loop invariant, authority path, or context dependency.
Avoid comments that restate syntax.

## Recommendation

Write each projector as:

1. A numbered top-of-file policy.
2. A `project()` body whose major sections use matching `// 1.`, `// 2.`
   markers.
3. Named context needs, read through `ProjectionContext` helpers.
4. Branch-specific path functions when authority or materialization differs by
   path.
5. Row materialization through module row helpers and schema-owned tables.

The current model projector is
`src/protocol/facts/identity/device_invite/project.rs`.

## Inline Policy

Every non-trivial projector should explain what it admits:

```rust
//! POLICY. A device_invite is admitted iff:
//!   1. STRUCTURAL. The outer fact is global, signed, contains a device_invite,
//!      and all selector fields are non-zero.
//!   2. AUTHORITY. The invite follows one of two named authority paths:
//!      user-signed invites require workspace, user, and user_invite context;
//!      endpoint-signed invites require workspace and endpoint_shared context.
//!   3. MATERIALIZE. Once the path validates, write the row, publish exact/key
//!      offers, and mark the fact shareable with the workspace.
```

Inside the function, keep the same order:

```rust
// 1. Structural.
let envelope = identity::signed_fact::decode_envelope(fact.body())
    .map_err(|_| "device_invite fact must be signed".to_string())?;

// 2. Authority.
//
// `user_invite_fact_id` is the authority-chain discriminator:
// Some(id) means the device invite must be signed by the user fact
// authorized by that user_invite; None means it must be signed by an
// already-trusted endpoint_shared fact for the same user/workspace.
match device_invite.user_invite_fact_id {
    Some(user_invite_fact_id) => {
        project_user_signed(fact, &device_invite, &envelope, user_invite_fact_id, context)
    }
    None => project_endpoint_signed(fact, &device_invite, &envelope, context),
}
```

The comment above the match is doing real work: it names the invariant behind
the branch. It does not merely say "match the option."

## Context Rule

Projectors must read matched context by the exact `ContextNeed` they declared.
Use:

- `payload_for(&need)` for one exact payload.
- `payload_for_checked(&need, label)` when the module wants the shared
  offer/payload consistency check.
- `matched_payloads_for(&need)` only for intentional multi-match roles, such as
  transit receive provenance or range roots.

Do not call `matched_context()` from protocol projectors. Do not scan
`context.offers()` to infer whether a declared need is satisfied. Do not inspect
`ContextOffer::payload_ref` in projectors.

Good:

```rust
let Some(user_fact) = context.payload_for(&needs.user) else {
    // Missing user authority context: park until the exact user need matches.
    return Ok(needs.output());
};
```

Intentional multi-match:

```rust
let receive = context
    .matched_payloads_for(&needs.receive)
    .map(|(_, fact)| fact)
    .min_by_key(|fact| fact.id);
```

The need is still concrete. The projector is choosing among multiple payloads
that matched that one need.

## Typed Facts

Core persists facts as opaque bytes. A projector may decode its own incoming
fact at the boundary, because that is where the owning fact module turns bytes
into policy input:

```rust
let user_invite = layout::decode_fact(&envelope.payload)?;
```

Foreign fact bytes are different. A projector should not import another fact
module's `layout` or call another module's raw layout codec. It should call a
module-owned typed helper:

```rust
let endpoint = endpoint_shared::decode_fact_payload(&endpoint_envelope.payload)
    .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
```

That keeps wire formatting centralized inside the owning fact module while
letting projector policy read as typed facts and named witnesses. The same rule
applies to signed envelopes: use `identity::signed_fact::TYPE_SIGNED_FACT` and
`identity::signed_fact::decode_envelope`, not the signed-fact layout module.

## Named Needs

Do not use positional `Vec<ContextNeed>` contracts for security-sensitive
projectors. A helper that fills `needs[0]`, `needs[1]`, then a later helper that
decodes those same indexes is fragile.

Prefer small branch-specific structs:

```rust
struct UserSignedNeeds {
    workspace: ContextNeed,
    user: ContextNeed,
    user_invite: ContextNeed,
}

impl UserSignedNeeds {
    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.workspace.clone())
            .need(self.user.clone())
            .need(self.user_invite.clone())
    }
}
```

This keeps every context proof named at the call site:

```rust
let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
    return Ok(needs.output());
};
let Some(user_fact) = context.payload_for(&needs.user) else {
    return Ok(needs.output());
};
let Some(user_invite_fact) = context.payload_for(&needs.user_invite) else {
    return Ok(needs.output());
};
```

## Parking And Errors

Missing context parks. Mismatched context rejects.

That distinction should be visible in code. It is fine to add comments before
park returns when the missing dependency is semantically important. Do not turn
missing context into an error just to get a nicer message; that breaks the
wake-loop contract.

Examples:

```rust
let Some(invite_fact) = context.payload_for(&invite_need) else {
    // Missing invite secret: keep the row unmaterialized until local context
    // proves this bootstrap request is authorized.
    return Ok(output.need(invite_need));
};

if invite_fact.scope != FactScope::Local {
    return Err("connection request invite context must be local".to_string());
}
```

## Authority Paths

If a fact has multiple validation paths, dispatch on the real discriminator and
put each path in its own function. The dispatcher should name what the branch
means; each path should read top to bottom as a proof.

Good:

```rust
match invite.user_invite_fact_id {
    Some(user_invite_fact_id) => project_user_signed(..., user_invite_fact_id, context),
    None => project_endpoint_signed(..., context),
}
```

Bad:

```rust
validate_authority(&needs, &invite, &envelope, context)?;
```

Generic names like `validate_authority` hide the security proof. If the helper
contains cross-field policy, give it a path-specific name or keep the checks at
the call site under the numbered policy section.

## Schema And Rows

Projectors may decide when a row should be materialized. They do not own the row
shape.

- Durable table ownership belongs in the schema DSL files.
- Opaque keyed byte tables use explicit `row_table name;`.
- Queryable read-model tables should be typed `table` declarations with
  columns, indexes, uniqueness, and byte lengths in the DSL.
- Projectors emit row intents through module row helpers.

Good:

```rust
materialized_output(fact, invite, needs.output())
```

where `materialized_output` calls:

```rust
AtomicIntent::PutRow(device_invite_row(fact.id, invite)?).into_intent()
```

Bad:

```rust
const DEVICE_INVITE_ROWS: TableName = ...;
TableRow { key, value }
```

in a projector file.

## Patterns To Keep

- Numbered policy comments for non-trivial projectors.
- Named needs structs for multi-context branches.
- `payload_for`, `payload_for_checked`, and `matched_payloads_for`.
- Comments explaining why a branch parks and what future context will prove.
- Inline cross-field security checks where the reader can see the full rule.
- Small helpers for structural mechanics: decoding, row construction, transcript
  construction, repeated field checks.

## Patterns To Avoid

- `matched_context()` in protocol projectors.
- `context.offers()` scans to decide whether a declared need is satisfied.
- `ContextOffer::payload_ref` in projector code.
- Positional `needs[0]` / `needs[1]` contracts.
- Generic `validate_authority` helpers that hide branch-specific policy.
- Hidden-state context wrappers that auto-track consulted needs.
- `Verdict` or `Plan` enums that use `?` for both reject and park.
- Declarative check arrays where an interpreter becomes the real logic.
- Projector-owned row tables, row shapes, SQL, file IO, network IO, or CLI
  parsing.
- Foreign fact-module layout imports or raw layout decoder calls in projectors.

## Rules And Todo Tests

The current active guardrails live in
`tests/poc10_intent_cleanliness_test.rs`:

- `target_projectors_use_typed_context_lookups_not_direct_match_scans`
- `target_projectors_do_not_read_raw_context_offer_storage_fields`
- `target_projectors_use_named_needs_not_positional_authority_flows`
- `target_projectors_document_policy_narratives`
- `target_projectors_do_not_decode_foreign_fact_layouts_inline`

When a projector is modernized, remove it from the failing output by satisfying
the rule. Do not add allowlist entries unless the exception is permanent and
documented.

## Historical Note

This style started from an experiment branch that compared many projector
shapes against the same invariant battery. The production rules above supersede
that branch. The experiment is still useful provenance, but the source of truth
is now the production guardrails, the schema DSL, and the model projectors in
`src/protocol/facts`.
