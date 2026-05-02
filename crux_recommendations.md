# Crux Recommendations For poc-8

## Summary

The best fit is to put Crux around the kernel control loop, then split the
current pipeline into pure planners plus explicit shell effects. Do not make
each event module its own Crux app, and do not turn canonical protocol events
into Crux events. In Crux terms, `Event` should mean "message into the kernel
loop"; poc canonical events should remain domain facts with canonical bytes and
event ids.

Recommended shape:

```text
CLI/TCP/SQLite shell
  -> KernelMsg
  -> Crux KernelApp update(model, msg)
  -> pure pipeline planners
  -> pure event modules
  -> typed Store/Network/Rng/Clock/Stdout effects
  -> shell interpreters
  -> StoreReply/NetworkReply/etc back into KernelMsg
```

The immediate value is not that Crux provides a magic scheduler. The value is
that it gives a typed `Message -> Command<Effect, Message>` boundary. That
boundary makes IO visible, testable, and hard to accidentally smuggle into
domain modules.

## What The Prototypes Showed

All six experiments are standalone Cargo crates under `crux_experiments/`.
They compile against `crux_core 0.17.x` and have passing tests.

| Experiment | Result | What it proves | Main limitation |
| --- | --- | --- | --- |
| `01_facade_wrap_pipeline` | `2 passed` | Crux can wrap the current store -> drain -> print flow and make the ordering explicit. | Decouples the CLI, but does not make the pipeline/event modules IO-less. |
| `02_pure_planner_effects` | `2 passed` | A pure planner can return Store, Network, and Drain plan steps; Crux turns them into typed effects. | Uses notify-only effects, so completion/error paths are not modeled. |
| `03_module_deciders` | `4 passed` | Event-module-like deciders/projectors can stay deterministic and separate from Crux messages. | Needs real event ids, admission status, and apply failure semantics. |
| `04_effect_shell` | `2 passed` | Explicit Store/TCP/RNG/Clock/Stdout operations can be interpreted by a fake shell with transcript tests. | Adds boilerplate for operation/reply enums and `From<Request<_>>` implementations. |
| `05_sync_state_machine` | `2 passed` | Crux can orchestrate protocol messages while a pure connection/sync state machine owns transitions. | The prototype is single-peer and omits retries, backoff, and backpressure. |
| `06_test_harness_guardrails` | `4 passed` | Fake shell transcript tests and dependency-drain invariants can constrain LLM edits. | Runtime invariant checks are not full formal proofs. |

Verified locally with:

```sh
cargo test # in crux_experiments/01_facade_wrap_pipeline
cargo test --manifest-path Cargo.toml # in crux_experiments/02_pure_planner_effects
cargo test # in crux_experiments/03_module_deciders
cargo test # in crux_experiments/04_effect_shell
cargo test --manifest-path Cargo.toml # in crux_experiments/05_sync_state_machine
cargo test # in crux_experiments/06_test_harness_guardrails
```

## Recommended Architecture

### 1. Use Crux For Kernel Orchestration

Create a `KernelApp` around the current `pipeline` and `control_loop`
responsibilities:

```rust
pub enum KernelMsg {
    Cli(CliCommand),
    FrameReceived { origin: Addr, bytes: Vec<u8> },
    DrainReady,
    Store(StoreReply),
    Network(NetworkReply),
    Rng(RngReply),
    Clock(ClockReply),
}

pub struct KernelModel {
    pub draining: bool,
    pub active_streams: ActiveStreams,
    pub last_error: Option<String>,
}
```

Crux `update` should decide what happens next and return typed effects. It
should not open SQLite, read sockets, generate randomness, or print.

### 2. Make IO Explicit With Operation Enums

Prefer explicit Crux operations over `Store` traits in core code:

```rust
pub enum StoreOperation {
    LoadMaxTimestamp,
    AdmitRecords { records: Vec<EventRecord> },
    LoadReadyBatch { limit: usize },
    ApplyProjection { event_id: EventId, projection: Projection },
    LoadIngressContext { origin: Addr, transit: Vec<u8> },
    LoadSyncContext { connection_id: EventId },
}

impl crux_core::capability::Operation for StoreOperation {
    type Output = StoreReply;
}
```

This is stronger than passing a read trait because a trait can hide IO anywhere.
With effects, every store lookup is visible in tests and every reply has to be
handled explicitly.

Use `Command::request_from_shell` when later work depends on the reply. Use
`Command::notify_shell` only for fire-and-forget operations such as logging or
best-effort notifications.

### 3. Split Pipeline Into Plan And Continue Functions

Current functions such as `pipeline::ingest_frame(&Store, ...)` need store
context. In the Crux shape, split them:

```rust
fn plan_ingest_frame(origin: Addr, bytes: Vec<u8>) -> StoreOperation;

fn continue_ingest_frame(ctx: IngressContext) -> Result<PipelinePlan, Error>;
```

The first function asks the shell for context. The second function is pure and
returns a plan:

```rust
pub struct PipelinePlan {
    pub store: Vec<StoreOperation>,
    pub network: Vec<NetworkOperation>,
    pub follow_up: Vec<KernelMsg>,
}
```

This is the main migration needed to make `pipeline.rs` IO-less.

### 4. Keep Event Modules Below Crux

Event modules should become pure domain components:

```rust
fn decode(bytes: &[u8]) -> Result<TypedEvent, DecodeError>;
fn dependencies(event: &TypedEvent) -> Vec<EventId>;
fn decide(command: Command, context: ModuleContext) -> Result<Vec<CanonicalEvent>, Rejection>;
fn project(event: TypedEvent, context: ProjectionContext) -> Result<Projection, ProjectionError>;
```

Crux messages can carry canonical bytes or event ids, but canonical events
should not become Crux messages. Otherwise the app loop turns into a giant
protocol dispatcher and Crux starts owning the domain vocabulary.

### 5. Make Sync Responses Normal Projector Output

Sync protocol handling should also fit the normal projector contract. The
projector should receive a typed sync event plus a plain context object. It
should not receive `Store`, perform SQLite queries, or write TCP frames.

```rust
enum SyncEvent {
    Compare(CompareEvent),
    HaveId(HaveIdEvent),
    NeedId(NeedIdEvent),
    Data(DataEvent),
}

struct SyncProjectorContext {
    connection: ConnectionView,
    negentropy: NegentropyView,
    local_events: LocalEventView,
}

struct NegentropyView {
    summary: [BucketSummary; 256],
    ids_by_requested_bucket: Vec<(u8, Vec<EventId>)>,
}

struct LocalEventView {
    presence: Vec<(EventId, bool)>,
    bytes: Vec<(EventId, Vec<u8>)>,
}
```

The negentropy tree, summary, bucket index, or cache is part of projector
context. It should be a module-owned projected read model maintained when
durable data events apply. Sync projectors read a snapshot of that structure
through context and return declarative output.

The clean shape is two-stage:

```rust
fn context_requirements(event: &SyncEvent) -> SyncContextRequest;

fn project(event: SyncEvent, ctx: SyncProjectorContext) -> Projection;
```

Examples:

```text
Compare(remote summary)
  + local negentropy summary / ids for differing buckets
  -> emitted HaveId events
  -> optional session rows

HaveId(id)
  + local presence(id)
  -> emitted NeedId if missing

NeedId(id)
  + local bytes(id)
  -> emitted Data event if present

Data(bytes)
  -> admitted durable event bytes
  -> optional session rows / labels
```

If sync responses are canonical events, they belong in `emitted_events`. If
something is ready to send on a connection, it belongs in `outbox` or in a
transit event that later projects to `outbox`. That keeps compare/have/need/data
as normal event processing instead of a bespoke callback loop.

### 6. Model Sync And Connection Session Flow Explicitly

The sync and connection modules should expose transition functions like:

```rust
fn step(state: SyncState, input: SyncInput) -> Transition<SyncState, SyncAction>;
```

Crux should map `SyncAction::SendFrame` into a `NetworkOperation`; the state
machine should not write TCP frames itself. This fits the current rule that the
network layer owns framing and transport mechanics, while protocol semantics
belong below the kernel.

Do not force every sync helper into a state machine. Set reconciliation helpers
such as "which buckets differ?" or "which ids are missing?" should stay as plain
pure functions. The state-machine shape is for session memory and phase logic:
handshake state, current connection id, pending requested ids, frames in flight,
retry counters, `more` frames, close behavior, and drain completion.

## Migration Plan

1. Add a `kernel` or `app` module with `KernelMsg`, `KernelModel`,
   `KernelEffect`, and shell operation enums. Keep it thin at first.

2. Wrap one existing CLI flow with Crux as a facade. `generate` is the best
   first candidate: generate records, admit records, drain ready, print output.
   This proves the shell loop and output formatting without touching sync.

3. Move `main.rs` behind the shell boundary. `main.rs` should parse args,
   dispatch `KernelMsg::Cli`, interpret effects, and print output. It should
   stop importing `Store`, `pipeline`, `control_loop`, `network`, and
   `event_modules` directly.

4. Convert `pipeline.rs` functions from `&Store` callers into pure planners
   plus continuation functions that consume DTO context loaded by store effects.

5. Refactor event module commands so they do not call `Store` directly.
   Commands should decide canonical events or projections from explicit
   context. Admission, apply, and module-row writes should be shell effects.

6. Move connection and sync flow control into pure state machines. Crux remains
   the outer orchestrator; the state machines own protocol transition logic.

7. Add guardrail tests before broad migration. Include transcript tests for
   effects, boundary tests that fail if `main.rs` imports kernel internals, and
   dependency-drain invariant tests.

## Testing Strategy

Use three layers of tests:

1. Pure unit tests for event modules and planners. These should not construct a
   `Store`, bind TCP, call RNG, or read the clock.

2. Crux transcript tests with fake shell interpreters. Drive a `KernelMsg`, pull
   emitted effects, resolve requests with fake replies, and assert the exact
   effect/reply sequence.

3. Black-box CLI/network tests for the real shell. Keep the existing sync tests,
   but after migration they should exercise shell interpreters rather than
   direct CLI access to kernel internals.

Useful permanent guardrails:

```text
rg "topo::store::Store|topo::pipeline|topo::control_loop|topo::event_modules" src/main.rs
rg "crate::store::Store|rusqlite|TcpStream|TcpListener" src/event_modules
rg "crate::store::Store|TcpStream|TcpListener" src/pipeline.rs
```

Those searches should be empty, except for documented shell/interpreter files.

## Risks And Tradeoffs

- Crux adds boilerplate. Every shell operation needs an `Operation`, reply type,
  effect wrapper, and interpreter case.

- Effect ordering must be intentional. Independent `Command`s may run
  concurrently; use request continuations when later effects depend on earlier
  replies.

- The first facade migration can hide old coupling. It is useful for proving the
  shell boundary, but it should not be mistaken for the final architecture.

- Store context DTOs need careful design. If they are too broad, the core sees a
  database-shaped snapshot. If they are too narrow, the update loop gets noisy.

- Apply semantics need to be precise. Projection should happen only after the
  shell confirms admission/apply status, unless the operation is explicitly
  speculative and reversible.

## Decision

Adopt Crux incrementally, but aim for the `02_pure_planner_effects` plus
`04_effect_shell` pattern as the target. Use `01_facade_wrap_pipeline` only as
the first compatibility step. Use `03_module_deciders` to guide event-module
refactors, `05_sync_state_machine` for connection/sync flow, and
`06_test_harness_guardrails` for permanent tests.

The north star is simple: most `poc-8` code should be plain functions over
plain data. Crux should sit at the boundary where those functions request IO.
