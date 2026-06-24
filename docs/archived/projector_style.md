# Projector Style Guide

This guide describes the production projector style for poc-10. The goal is
not minimal line count. The goal is that a reviewer can read the policy,
follow the context proof, and see exactly why a fact is parked, rejected, or
materialized.

Inline documentation is part of the projector. Use it freely when it explains a
security invariant, wake-loop invariant, authority path, or context dependency.
Avoid comments that restate syntax.

Use this with `documentation_guide.md`: the general guide explains the expected
file-level prose, while this guide names the extra proof structure every
projector should make visible.

## Recommendation

Write each projector as:

1. A numbered top-of-file policy.
2. A `Projector::project()` body that immediately delegates through
   `core::projectors::project_typed::<ModuleCodec, _>()`.
3. A `TypedProjector<ModuleCodec>::project_typed()` body whose major sections
   use matching `// 1.`, `// 2.` markers.
4. Named context needs, read through `ProjectionContext` helpers.
5. Branch-specific path functions when authority or materialization differs by
   path.
6. Row materialization through module row helpers and schema-owned tables.

## Deletion Pattern

Deletion is target-owned. A deletion, close, or retirement fact publishes
context with an offer; a due time wake supplies time context. The target fact
keeps the matching need or wake in its normal projection output. When that
context matches, the target projector validates the payload when there is one,
deletes only rows it owns, and then calls `ProjectionOutput::purge_self` for
its own fact id.

Do not build parent-owned child scans or generic cascade handlers. A parent
projector may publish deletion context, but reaction, file, slice, secret, and
connection-material projectors are responsible for observing that context and
removing themselves. The only purge a projector may emit is its own fact id;
core rejects cross-fact purges from projector output.

The current model projector is
`src/protocol/auth/device_invite/project.rs`.

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
impl Projector for DeviceInviteProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for DeviceInviteProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        device_invite: DeviceInviteFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("device_invite fact must have global scope".to_string());
        }
        super::layout::verify_signature(&device_invite)?;

        // 2. Authority.
        //
        // `user_invite_fact_id` is the authority-chain discriminator:
        // Some(id) means the device invite must be signed by the user fact
        // authorized by that user_invite; None means it must be signed by an
        // already-trusted endpoint_shared fact for the same user/workspace.
        match device_invite.user_invite_fact_id {
            Some(user_invite_fact_id) => project_user_signed(
                fact,
                &device_invite,
                user_invite_fact_id,
                context,
            ),
            None => project_endpoint_signed(fact, &device_invite, context),
        }
    }
}
```

The comment above the match is doing real work: it names the invariant behind
the branch. It does not merely say "match the option."

## Context Rule

Projectors must read matched context by the exact `ContextNeed` they declared.
Use:

- `match_for(&need)` for one exact matched offer.
- `match_for_checked(&need, label)` when the module wants the shared matched
  offer validation.
- `matches_for(&need)` only for intentional multi-match roles, such as
  connection fact receipts or range-backed offers.
- `value_for(&need)` when only the matched offer value is needed.

Do not scan the raw context collection from protocol projectors to infer
whether a declared need is satisfied. A matched offer exposes only its semantic
value plus core-stamped owner metadata; projectors should reach it only through
the `ProjectionContext` helper anchored to the need they emitted.

Good:

```rust
let Some(user_match) = context.match_for(&needs.user) else {
    // Missing user authority context: park until the exact user need matches.
    return Ok(needs.output());
};
```

Intentional multi-match:

```rust
let receive = context
    .matches_for(&needs.receive)
    .min_by_key(|matched| matched.offer_owner());
```

The need is still concrete. The projector is choosing among multiple offers
that matched that one need.

## Typed Facts

Core persists facts as opaque bytes, but primary projector input was decoded
through core's typed adapter in this archived design. The owning fact module
supplied a small codec:

```rust
pub(crate) struct Codec;

impl crate::core::projectors::ArchivedCodecTrait for Codec {
    type Payload = fact::DeviceInviteFact;

    fn decode_fact(fact: &Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
```

The projector receives that typed payload in `project_typed()`. It should not
call `layout::decode_fact(fact.body())` or dispatch on raw primary bytes except
inside the module codec. If the fact family is signed, the typed payload carries
natural signer fields and the projector verifies the signature in its structural
section before authority checks.

Foreign context fact bytes are different. A projector should not import another
fact module's `layout` or call another module's raw layout codec. It should call
a module-owned typed helper:

```rust
let endpoint = endpoint_shared::decode_fact_payload(endpoint_fact.body())
    .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
endpoint_shared::layout::verify_signature(&endpoint)?;
```

That keeps wire formatting centralized inside the owning fact module while
letting projector policy read as typed facts and named witnesses.

Family projectors use the same rule with a module-owned enum:

```rust
pub enum ProjectionPayload {
    Message(fact::ContentMessageFact),
    SecretNode(fact::SecretNodeFact),
}
```

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
let Some(workspace_fact) = context.match_for(&needs.workspace) else {
    return Ok(needs.output());
};
let Some(user_fact) = context.match_for(&needs.user) else {
    return Ok(needs.output());
};
let Some(user_invite_fact) = context.match_for(&needs.user_invite) else {
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
let Some(invite_match) = context.match_for(&invite_need) else {
    // Missing invite secret: keep the row unmaterialized until local context
    // proves this bootstrap request is authorized.
    return Ok(output.need(invite_need));
};

if invite_match.offer_owner_scope != FactScope::Local {
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
validate_authority(&needs, &invite, context)?;
```

Generic names like `validate_authority` hide the security proof. If the helper
contains cross-field policy, give it a path-specific name or keep the checks at
the call site under the numbered policy section.

## Schema And Rows

Projectors may decide when a row should be materialized. They do not own the row
shape.

- Durable table ownership belongs in the explicit SQL schema declarations in
  the module that owns the rows, currently `core::schema`, `core::network`, or
  `protocol::registry`.
- Opaque keyed byte tables should still have module-owned row helper functions
  that name the table and validate key/value bytes.
- Queryable read-model tables should have named columns, indexes, uniqueness,
  and byte-length expectations in schema plus typed row helpers in the owning
  module.
- Projectors emit row mutations through module row helpers.

Good:

```rust
materialized_output(fact, invite, needs.output())
```

where `materialized_output` calls:

```rust
ProjectionOutput::new()
    .row_mutation(RowMutation::PutRow(device_invite_row(fact.id, invite)?))
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
- `match_for`, `match_for_checked`, `matches_for`, and `value_for`.
- Comments explaining why a branch parks and what future context will prove.
- Inline cross-field security checks where the reader can see the full rule.
- Small helpers for structural mechanics: decoding, row construction, transcript
  construction, repeated field checks.

## Patterns To Avoid

- `matched_context()` in protocol projectors.
- `context.offers()` scans to decide whether a declared need is satisfied.
- Direct matched-offer field inspection in projector code.
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

- `target_projectors_stay_pure_context_to_intents`
- `target_projectors_use_typed_context_lookups_not_direct_match_scans`
- `target_projectors_do_not_read_raw_context_offer_storage_fields`
- `target_projectors_use_named_needs_not_positional_authority_flows`
- `target_projectors_document_policy_narratives`
- `target_projectors_route_primary_decode_through_core_typed_adapter`
- `target_projectors_do_not_decode_foreign_fact_layouts_inline`
- `target_projectors_do_not_define_intent_payloads_or_handler_logic`
- `target_projectors_do_not_define_row_tables_or_row_shapes`

Architecture boundary tests also enforce that target projectors emit only
needs, offers, and intents, and that they do not write store rows directly.

When a projector changes, satisfy the rule directly. Do not add allowlist
entries unless the exception is permanent and documented next to the code that
needs it.

The source of truth is the production guardrails, explicit schema declarations,
and the model projectors in `src/protocol/facts`.
