# Poc-10 Runtime Cutover Plan

Status: implemented in this worktree. The active runtime no longer has a
`pipeline.rs` facade; `project_fact.rs` and `handle_intent.rs` own the n=1 work
items, and incoming network frames enter as incoming facts that can be retained
while waiting on context.

## Goal

Replace the current pipeline abstraction with a smaller runtime model:

- commands snapshot pre-command state and author durable facts,
- runtime enqueues authored facts,
- `project_fact` projects one queued fact and commits it,
- `handle_intent` handles one queued intent and commits it,
- store provides storage primitives only,
- daemon drains queues and owns replay timing.

There is no backwards-compatible staged pipeline. Projectors own fact meaning.
Core owns work-item mechanics.

## File Shape

Target core files:

- `src/core/store.rs`: SQLite connection, transactions, fact storage primitives,
  and typed row primitives.
- `src/core/project_fact.rs`: `drain_facts`, `project_fact`, projection commit,
  context matching/requeue, and time wakes.
- `src/core/handle_intent.rs`: `drain_intents`, `handle_intent`, intent retry,
  and intent commit.
- `src/core/command.rs`: command clock, local capability value types, and
  authored command result types.

`src/core/pipeline.rs` is dissolved. Do not preserve a compatibility facade.

Protocol files:

- `author.rs`: constructs fact bytes and `Fact` values.
- `queries.rs`: exposes projected-state reads owned by the fact family.
- `commands.rs`: queries pre-command state, calls authors, and returns authored
  facts plus a receipt.
- `project.rs`: owns decode, authenticate, adapt, replay behavior, retention,
  deletion, context needs/offers, rows, effects, and intents for that fact
  family.

All fact-family `decode`, `authenticate`, and `adapt` helpers must be local
modules inside the owning `project.rs`.

## Commands

A simple command is:

```text
queries.rs snapshot -> author.rs facts -> runtime enqueue
```

Rules:

- Commands do not call other commands.
- Commands do not commit, drain, project, handle intents, or mutate rows.
- Commands do not emit intents, row mutations, purges, or derived state.
- Commands query only pre-command state.
- Pre-command projected-state reads must go through the owning fact family's
  `queries.rs`.
- Commands receive the command clock directly and query local capabilities from
  protocol-owned state before authoring facts.
- Commands may compose multiple newly authored facts in memory.
- Dependencies between newly authored facts are passed directly as ids/values,
  not through projected rows.
- `author.rs` constructs `Fact` values only. It does not enqueue.
- Runtime atomically inserts authored facts as retained and enqueues them for
  projection.

Command shape:

```rust
struct AuthoredCommand<T> {
    receipt: T,
    facts: Vec<Fact>,
}

fn command(
    store: &Store,
    clock: &dyn CommandClock,
    input: Input,
) -> Result<AuthoredCommand<Receipt>, String> {
    let snapshot = family::queries::snapshot(store, input)?;
    let capability = auth::endpoint::commands::local_signing_capability(
        store,
        snapshot.workspace_id,
    )?;
    let now = clock.next_timestamp();

    let fact = family::author::fact(&snapshot, &capability, now, input)?;
    let signature = auth::signature::author::sign_fact(
        snapshot.workspace_id,
        &fact,
        &capability.private_key,
        now,
    )?;

    Ok(AuthoredCommand {
        receipt: Receipt { fact_id: fact.id },
        facts: vec![fact, signature],
    })
}
```

Runtime submit:

```rust
fn submit_authored_command<T>(cmd: AuthoredCommand<T>) -> Result<T, String> {
    let receipt = cmd.receipt;

    store.write_transaction(|tx| {
        for fact in cmd.facts {
            tx.insert_retained_fact(&fact)?;
            enqueue_projection(tx, fact.id, ProjectionMode::Normal)?;
        }
        Ok(())
    })?;

    Ok(receipt)
}
```

Command-created facts are retained immediately. They never enter the volatile
incoming incoming store.

## Command Chains

Simple commands may compose facts in memory, but they must not commit or query
mid-chain.

Allowed:

```text
query existing state
author fact A
pass A.id directly to author fact B
return [A, B]
```

Disallowed:

```text
author fact A
commit/project A
query A's projected row
author fact B
```

If an operation needs mid-chain projected state, it is not a simple command. It
must be either:

- a user-visible sequence of commands where command A returns only after its
  command-visible projection barrier, then command B queries normal state, or
- an explicit workflow/daemon operation.

`chop_now`-style operations that submit/drain in phases are workflows, not
simple commands.

## Incoming Facts

Network/sync/handler-arrived facts enter as volatile candidates:

```rust
fn submit_incoming_fact(fact: Fact) -> Result<(), String> {
    store.write_transaction(|tx| {
        tx.insert_incoming_fact(&fact)?;
        enqueue_candidate_projection(tx, fact.id)?;
        Ok(())
    })
}
```

Incoming facts may be lost before projection. Once projected, a projector
decides whether a candidate should become retained, dropped, or retained while
parked on standing context needs. Network frame candidates use that last path
when observation, connection, or key material context has not arrived yet.

## Projection

`drain_facts` is only a loop and budget:

```rust
fn drain_facts(limit: usize) -> Result<ProjectionProgress, String> {
    let mut progress = ProjectionProgress::default();

    while progress.projected < limit {
        match project_fact()? {
            ProjectFact::Projected(report) => progress.merge(report),
            ProjectFact::NoWork => break,
        }
    }

    Ok(progress)
}
```

`project_fact` is the complete n=1 fact projection transaction:

```rust
fn project_fact() -> Result<ProjectFact, String> {
    store.write_transaction(|tx| {
        let Some(item) = claim_next_fact_item(tx)? else {
            return Ok(ProjectFact::NoWork);
        };

        let input = load_projection_input(tx, item)?;
        let output = projector.project(&input.fact, &input.context)?;

        validate_projection_output(&input, &output)?;
        commit_projection(tx, input, output)?;

        Ok(ProjectFact::Projected(report))
    })
}
```

Projectors run once per queued item. They do not search for additional context.
The context visible to a projector is only the context attached to that queued
work item.

## Projection Commit

Projection commit stays in `project_fact.rs` for readability. It owns:

- retaining or dropping candidates,
- consuming the queued fact item,
- replacing owner needs,
- appending owner offers,
- matching added needs/offers,
- requeueing matched owners with attached context,
- replacing time wakes,
- applying projection-emitted facts, purges, typed rows, and intents.

Sketch:

```rust
fn commit_projection(tx: &Store, input: ProjectionInput, output: ProjectionOutput) -> Result<()> {
    retain_or_drop_incoming(tx, &input, output.retain_self)?;

    if input.is_retained_after_commit() {
        commit_context_and_requeue_matches(tx, input.fact.id, output.context_set())?;
        replace_time_wakes(tx, input.fact.id, output.time_wakes)?;
        apply_projection_effects(tx, output.effects)?;
    }

    consume_fact_queue_item(tx, input.item)?;
    Ok(())
}
```

Need/offer matching happens only during projection commit:

```rust
fn commit_context_and_requeue_matches(
    tx: &Store,
    owner: FactId,
    next: ContextSet,
) -> Result<()> {
    let previous = previous_context_for_owner(tx, owner)?;

    replace_owner_needs(tx, owner, &next.needs)?;
    append_owner_offers(tx, owner, &next.offers)?;

    let delta = diff_context_sets(previous, next);

    for need in delta.added_needs {
        for offer in find_matching_offers(tx, &need)? {
            requeue_owner_with_match(tx, need.owner, need.clone(), offer)?;
        }
    }

    for offer in delta.added_offers {
        for need in find_matching_needs(tx, &offer)? {
            requeue_owner_with_match(tx, need.owner, need, offer.clone())?;
        }
    }

    Ok(())
}
```

There are no same-drain probes. The database queue is the loop.

## Projector Responsibilities

Each projector owns the full local meaning of its fact:

- decode raw bytes,
- authenticate intrinsic fields and ids,
- adapt legacy versions if any,
- inspect supplied context,
- emit missing needs,
- validate present offers,
- decide incoming retention,
- decide replay behavior from `ProjectionContext::mode()`,
- decide when to purge/delete itself,
- emit offers, time wakes, rows, child facts, and intents.

Projectors must document context-dependent validation in the current local
style: what context is required, why a missing context parks, and what is
validated when the context is present.

## Intents

`handle_intent.rs` mirrors `project_fact.rs`.

`drain_intents` is only a loop and budget. `handle_intent` owns one intent
transaction:

```rust
fn handle_intent() -> Result<HandleIntent, String> {
    store.write_transaction(|tx| {
        let Some(intent) = claim_next_intent(tx)? else {
            return Ok(HandleIntent::NoWork);
        };

        let handler = handlers.for_kind(intent.kind)?;
        let context = load_handler_context(tx, handler, &intent)?;
        let effects = handler.handle(&intent, &context)?;

        commit_handled_intent(tx, intent, effects)?;

        Ok(HandleIntent::Handled(report))
    })
}
```

Commands do not create intents directly. Projectors and handlers may.

Intent commit stays in `handle_intent.rs` even if it duplicates short storage
helpers from projection. Prefer readable local transaction bodies over abstract
shared commit machinery.

## Store

`store.rs` provides storage mechanics only:

- transaction helpers,
- retained fact primitives,
- incoming fact primitives,
- typed protocol row insert/delete,
- opaque row primitives if still needed,
- validated table clearing primitives.

Good store methods are primitive:

```rust
insert_retained_fact
insert_incoming_fact
move_incoming_to_retained
load_retained_fact
load_incoming_fact
purge_retained_fact
delete_incoming_fact
insert_values
delete_where
delete_all_rows
```

Bad store methods are workflow-shaped and do not belong in `store.rs`:

```rust
project_fact
handle_intent
commit_projection
requeue_context_matches
replay_all_facts
```

`store.rs` may provide `delete_all_rows(table)` or `clear_tables(tables)`.
Replay code chooses which tables to wipe.

## Protocol Rows

Projectors and handlers emit typed row mutations from protocol schema. They do
not emit raw SQL.

Protocol schema declares table names, columns, and key columns. Store builds
generic SQL from registered schema:

```rust
CONTENT_MESSAGES.insert(values)
CONTENT_MESSAGES.delete_by_key(values)
```

Commit validates target tables and columns against the schema used to build the
runtime.

## Replay

Daemon/runtime owns when replay happens. `replay.rs` may remain as the
orchestration and diagnostics wrapper around the simple replay operation:
wipe derived state, move retained facts back to pending projection in replay
mode, drain `project_fact`, and compare state summaries. It must not grow its
own projection or store policy.

```rust
fn run_replay() -> Result<(), String> {
    store.write_transaction(|tx| {
        mark_replay_in_progress(tx)?;
        wipe_derived_state(tx, protocol_schema)?;
        enqueue_all_retained_facts(tx, ProjectionMode::Replay)?;
        Ok(())
    })?;

    drain_facts_until_idle()?;

    store.write_transaction(|tx| mark_replay_complete(tx))?;
    Ok(())
}
```

Replay wipe policy lives with daemon/replay, not store:

```rust
fn wipe_derived_state(tx: &Store, schema: &ProtocolSchema) -> Result<()> {
    for table in core_replay_reset_tables() {
        tx.delete_all_rows(table)?;
    }
    for table in schema.replay_reset_tables {
        tx.delete_all_rows(table)?;
    }
    Ok(())
}
```

Retained facts are the durable protocol truth and survive replay. Incoming
facts, pending queues, context edges, time wakes, intent queues, and derived
protocol rows are wiped. Local runtime metadata needed to run the database,
such as schema and replay lifecycle rows, may also survive, but it is not
protocol truth.

Projectors receive replay mode in `ProjectionContext` and decide protocol-local
replay behavior. Intent handlers only run during replay when their
`HandlerRoute` explicitly declares replay support; live-only handler output is
kept out of replay by the handler route and projector decisions, not by a broad
post-hoc intent filter.

## Daemon

Daemon owns scheduling:

- live drain order,
- startup replay checks,
- manual replay,
- time wake admission into pending projection,
- recurring live work.

Time wake admission is daemon-managed queueing. Projection commit stores the
time-wake subscriptions emitted by projectors.

## Definition Of Done

- `pipeline.rs` is gone.
- `project_fact.rs` and `handle_intent.rs` are the readable work-item files.
- Commands return authored facts plus receipts and never call commands.
- Commands query pre-command state only through owning `queries.rs` helpers.
- Command-authored facts are retained and pending durably.
- Incoming/network/sync facts are volatile candidates until retained by a
  projector.
- Need/offer matching occurs only during projection commit.
- Same-drain context probing is removed.
- Replay is a daemon/runtime-owned wipe/rebuild over retained facts, with
  `replay.rs` limited to orchestration and diagnostics.
- Store contains storage primitives, not workflow policy.
- All fact projectors absorb decode/authenticate/adapt helpers into `project.rs`
  and document local context/replay/retention decisions.
- Significant black-box tests pass.
- Commit the completed work on this branch before handoff or review.
