# Projector Style Guide

Distilled from a fourteen-variant experiment on the two most complex authority
projectors (`connection_request` and `identity_device_invite`). Every variant
passed the same ~30-invariant battery; the winners optimized for **legibility
to a newcomer who has never seen this framework** while preserving the wake-loop
contract.

## Recommendation in one sentence

Write each projector as a **numbered top-of-file English policy** followed by a
**function body with matching `// 1.` `// 2.` markers**; use the five shared
primitives below; never invent a custom error/park enum.

## The five shared primitives

These live in a single module (illustrative path; settle the real location when
adopting). They are pure structural mechanics — never domain cross-field checks.

```rust
/// Turn one boolean invariant into a `?`-friendly call. Reads like a spec line.
pub fn require(condition: bool, error: &str) -> Result<(), String> { ... }

/// True if every byte of a 32-byte selector field is zero (the canonical
/// "unset" sentinel for FactId / public-key fields in this codebase).
pub fn is_zero32(field: &[u8; 32]) -> bool { ... }

/// Open a signed envelope, confirm its inner type tag, and decode the inner
/// payload. The single most-recurring pattern across authority projectors.
pub fn open_signed<T>(
    bytes: &[u8],
    expected_type: u8,
    decode: fn(&[u8]) -> Result<T, String>,
    envelope_err: &str,
    payload_err: &str,
) -> Result<(SignedFactEnvelope, T), String> { ... }

/// Accumulates the needs a projector publishes as it discovers them.
/// `park()` drains the set into a `ProjectionOutput` carrying just the needs.
pub struct NeedSet { ... }
impl NeedSet {
    pub fn new() -> Self;
    pub fn add(&mut self, need: ContextNeed);
    pub fn park(self) -> ProjectionOutput;
}
```

The fifth primitive is not a function but a discipline: **match on the
discriminating axis**, not on a magic field equality. For a single-path
projector that's `match fact.scope`; for a multi-path projector it's a typed
classifier built from the decoded fact.

## Idiom A — single-path projector

Use when the projector has one validation flow with optional scope-specific
branches. The whole projector fits in one `project()` function with a top spec.

Reduced from the wave-3 `connection_request` winner (158 LOC). Header below is
the *entire* file-level documentation; the function body mirrors it 1:1.

```rust
//! Connection-request projector, written as a narrated security policy.
//!
//! POLICY. A connection_request is admitted iff:
//!   1. STRUCTURAL.   Bytes decode; every selector field is non-zero;
//!                    from_endpoint != to_endpoint.
//!   2. INVITE.       The named invite_secret is present (else park), its
//!                    fact id and local scope match the request's claim, its
//!                    bootstrap_hash matches, and if the invite is bound to a
//!                    particular invite_event_id, that matches too.
//!   3. SIGNATURE.    invite_signature verifies under the invite's bootstrap
//!                    key over the canonical transcript.
//!   4. DEPENDENCY.   LOCAL  -- we hold the named initiator ephemeral secret
//!                               (local, owner = from_endpoint, public key
//!                               matches the request).
//!                    GLOBAL -- local transit-receive provenance names this
//!                               exact fact (kind = bootstrap, addressed to
//!                               to_endpoint, sent by from_endpoint, and if
//!                               it names a request, names this one).
//!                    Missing context parks; mismatched context rejects.
//!   5. MATERIALIZE.  Publish the offer and emit the put_row intent.

impl Projector for ConnectionRequestProjector {
    fn project(&self, fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let request = layout::decode_fact(&fact.bytes)?;
        require(!is_zero32(&request.from_endpoint), "connection request from_endpoint cannot be empty")?;
        // ... other non-zero checks ...
        require(request.from_endpoint != request.to_endpoint,
            "connection request endpoints must differ")?;

        // 2. Invite.
        let mut needs = NeedSet::new();
        let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
        needs.add(invite_need.clone());
        let Some(invite) = ctx.payload_for(&invite_need) else { return Ok(needs.park()); };
        let invite_secret = invite_layout::decode_fact(&invite.bytes)
            .map_err(|_| "connection request invite context is not an invite secret".to_string())?;
        require(invite.id == request.invite_secret_event_id,
            "connection request invite context id does not match request")?;
        require(invite.scope == FactScope::Local,
            "connection request invite context must be local")?;
        require(invite_secret.bootstrap_hash == request.bootstrap_hash,
            "connection request bootstrap hash is not authorized")?;

        // 3. Signature.
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"topo-connection-request-invite-signing-transcript-v1");
        transcript.extend_from_slice(&request.from_endpoint);
        // ... build the rest inline so the reader sees what's signed ...
        let invite_public_key = crypto::ed25519_public_key(&invite_secret.bootstrap_secret);
        require(crypto::ed25519_verify(&invite_public_key, &transcript, &request.invite_signature),
            "connection request invite signature is not authorized")?;

        // 4. Dependency.
        match fact.scope {
            FactScope::Local => { /* park-on-miss + check ephemeral */ }
            FactScope::Global => { /* park-on-miss + check transit_received */ }
            _ => return Err("connection request fact must be local or global".to_string()),
        }

        // 5. Materialize.
        Ok(ProjectionOutput::new()
            .offer(matchers::connection_request_offer(fact.id, fact.id))
            .intent(AtomicIntent::PutRow(connection_request_row(fact.id, &request)?).into_intent()))
    }
}
```

The reader reads the policy (24 lines), then scans `project()` to verify each
numbered section does what its policy line says. Two short passes, no scope
hopping.

## Idiom B — multi-path projector

Use when the projector has structurally different validation paths that don't
share a common spine. A thin `project()` dispatches; each path function is
preceded by its own English contract and reads as its own narrative.

Reduced from the wave-3 `device_invite` winner (291 LOC). The dispatcher is
two lines; each path function stands alone for security review.

```rust
//! Device-invite projector, written as two parallel English narratives.
//!
//! A device-invite has exactly two issuing paths — a user issues one for
//! their own new device, or an already-trusted endpoint_shared issues one on
//! the user's behalf. Each path is a self-contained function whose body
//! reads top-to-bottom as the security policy for that path.

impl Projector for DeviceInviteProjector {
    fn project(&self, fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        let (envelope, invite) = open_and_shape_check(fact)?;
        match invite.user_invite_event_id {
            Some(user_invite_event_id) => {
                project_user_signed(fact.id, &envelope, &invite, user_invite_event_id, ctx)
            }
            None => project_endpoint_signed(fact.id, &envelope, &invite, ctx),
        }
    }
}

// =============================================================================
// Path A: the invite was signed by the user themselves.
//
// Required corroborating facts:
//   - workspace          (named by invite.workspace_id)
//   - user               (named by invite.user_authority_event_id)
//   - user_invite        (named by invite.user_invite_event_id)
//
// Rules (each rule is one block of code below, in this order):
//   1. The workspace payload matches by id and is workspace-shaped.
//   2. envelope.signer_id == invite.user_authority_event_id.
//   3. The user payload matches by id and decodes as a signed user.
//   4. envelope.signer_public_key == user.public_key.
//   5. user.workspace_id == invite.workspace_id.
//   6. The user envelope was itself signed by `invite.user_invite_event_id`.
//   7. The user_invite payload checks out (id, type, workspace, public key).
// =============================================================================

fn project_user_signed(
    owner: FactId,
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    user_invite_event_id: FactId,
    ctx: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let mut needs = NeedSet::new();
    let workspace_need = m::exact_need(owner, m::workspace_role(), invite.workspace_id);
    let user_need = m::exact_need(owner, m::user_role(), invite.user_authority_event_id);
    let user_invite_need = m::exact_need(owner, m::user_invite_role(), user_invite_event_id);
    needs.add(workspace_need.clone());
    needs.add(user_need.clone());
    needs.add(user_invite_need.clone());

    let (Some(workspace_fact), Some(user_fact), Some(user_invite_fact)) = (
        ctx.payload_for(&workspace_need),
        ctx.payload_for(&user_need),
        ctx.payload_for(&user_invite_need),
    ) else {
        return Ok(needs.park());
    };

    // Rule 1.
    check_workspace_payload(workspace_fact, invite.workspace_id)?;

    // Rule 2.
    require(envelope.signer_id == invite.user_authority_event_id,
        "user-signed device_invite authority must match signer user")?;

    // Rule 3.
    require(user_fact.id == invite.user_authority_event_id,
        "device_invite user context payload id mismatch")?;
    let (user_envelope, user) = open_signed(
        &user_fact.bytes,
        user_layout::TYPE_USER,
        user_layout::decode_fact,
        "device_invite signer must be user or endpoint_shared",
        "device_invite user signer payload is invalid",
    )?;

    // Rule 4.
    require(envelope.signer_public_key == user.public_key,
        "device_invite signer public key does not match user")?;

    // Rule 5.
    require(user.workspace_id == invite.workspace_id,
        "device_invite user authority belongs to a different workspace")?;

    // Rule 6.
    require(user_envelope.signer_id == user_invite_event_id,
        "device_invite user_invite dependency does not match signed user")?;

    // Rule 7.
    // ... open_signed user_invite, check workspace + key chain ...

    materialize(owner, invite, needs.park())
}

// Path B has its own English header block and its own narrative body.
```

## Patterns that win

1. **`require(cond, msg)?` micro-helper** — collapses each rule from 3-4 lines
   of `if !cond { return Err("...".into()) }` to one line that reads like a
   spec.
2. **`let Some(x) = ctx.payload_for(&need) else { return Ok(needs.park()); };`** —
   uniform park-on-miss at every fetch site. `NeedSet::add` then `park` is the
   only vocabulary for parking.
3. **`open_signed::<T>(bytes, type, decoder, env_err, payload_err)?`** —
   collapses the four-line "decode envelope / check inner_type / decode payload"
   pattern that appears in 5+ projectors. Saves the most LOC for the least
   abstraction cost.
4. **Match on the discriminating axis** — make the bootstrap-vs-delegated split
   a `match` (on `fact.scope`, or on a typed classifier built from the decoded
   fact), never an in-band field-equality trick like
   `if authority_event_id == workspace_id`. The reader sees a sum type, not a
   magic value.
5. **Build cryptographic transcripts at the verification site, inline.** The
   reader sees exactly what bytes get signed; no helper function buries the
   serialization.

## Patterns that consistently failed the newcomer test

1. **Typed `Ctx` wrappers that auto-track consulted needs.** The hidden state
   ("the wrapper remembers every accessor call and turns them into a park")
   forces the reader to study the wrapper to understand parking semantics.
2. **`Verdict` / `Plan` enums that ride `?` for both reject AND park.**
   `Err(Verdict::Park)` inverts Rust's `Err = failure` convention. A newcomer
   pauses every time they see `?` to confirm what kind of "not yet" it carries.
3. **Declarative `&[Check]` policy lists where the interpreter is the real
   logic.** When the policy is data and the interpreter is 30+ lines, adding
   a check now requires editing two `const` arrays AND a match arm — and the
   reader has to learn the interpreter's vocabulary before seeing any actual
   rule.
4. **Generic helpers that abstract cross-field checks behind names like
   `validate_authority`.** The reader has to read the helper's body in full
   to know what's enforced. Cross-field policy belongs at the call site, where
   the rule is named; structural mechanics (decode, format) belong in helpers.

## Anti-pattern: helper-split projector (the current baseline shape)

```rust
let needs = authority_needs(fact.id, &device_invite, envelope.signer_id);
let output = output_with_needs(&needs);
if !has_all_context(&needs, context) {
    return Ok(output);
}
validate_authority(&needs, &device_invite, &envelope, context)?;
```

The split between `authority_needs` (declares positional `&needs[0]`/`&needs[1]`)
and `validate_authority` (consumes them by index) is fragile. The 4-arg
`validate_authority` couples to caller indexes that aren't named in its
signature. Reviewers must flip between functions to confirm the indices line up
with the named dependencies in the policy. The recommended idiom keeps every
named dependency in scope alongside the rule that checks it.

## Background — the experiment branch

Every claim above is backed by working code that passes a ~30-invariant battery
shared across variants. The branch lives at:

```
worktree-projector-experiment    /home/holmes/poc-10/.claude/worktrees/projector-experiment
```

Within it:

- `src/projector_experiment/shared.rs` — the contract every variant satisfies
- `src/projector_experiment/checks.rs` — the five shared primitives, fully
  implemented
- `src/projector_experiment/connection_request/baseline/` — current production
  code (control, 219 LOC)
- `src/projector_experiment/connection_request/attempt_NN_*/` — eleven
  alternative shapes ranging from 146 to 405 LOC
- `src/projector_experiment/device_invite/baseline/` — control (242 LOC)
- `src/projector_experiment/device_invite/attempt_NN_*/` — ten alternative
  shapes ranging from 217 to 467 LOC

Run `cargo test --lib projector_experiment` from the worktree to verify all
variants pass the shared battery.

The current winners (the shapes shown above) are:

- `connection_request/attempt_09_narrative_polish/project.rs` — 158 LOC, single
  function with top spec
- `device_invite/attempt_10_iterated_05/project.rs` — 291 LOC, parallel
  narrative path functions with a shared dispatcher

Two codex passes on a related refactor that drops `ContextOffer.payload_ref`
(branch `worktree-role-payload-ref-cleanup`) verified that the framework can
now enforce `owner == projected_fact.id` structurally, which is the precondition
for trusting the "the matched payload is the upstream projector's own fact"
property that this style depends on for clarity.
