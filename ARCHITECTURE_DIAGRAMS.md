# Architecture Diagrams

GitHub-renderable Mermaid flowcharts for the Context runtime. They are a visual
companion to `README.md`, `src/core/README.md`, `docs/RULES.md`, and the scope
READMEs; the Rust modules remain the source of truth.

## Runtime Queue Model

The runtime is a queue-driven system. Core owns queue storage, scheduling, and
commit boundaries. Protocol code supplies the two callbacks that transform
queued work:

- a **fact projector** turns one fact into standing context, rows, time wakes,
  intents, durable facts, and incoming facts, and
- an **intent handler** performs one bounded stateful action (IO, sealing,
  responding) and returns a `RuntimeEffects` batch.

Protocol code also supplies edge hooks: command authoring, inbound byte
classification, and fact admission validation. Those hooks feed queues; they do
not drain queues or decide runtime ordering.

Core never interprets a fact. It only admits facts, matches context ranges,
schedules wakes, and pumps these queues through the protocol functions. Most
queues are durable SQLite tables that survive restart; `incoming_facts` and
`local_intents` are `CREATE TEMP TABLE`, so they last as long as the SQLite
connection - the whole daemon session, or one CLI command - and a restart
recreates them empty. The daemon drains them each tick on its own long-lived
connection. A normal CLI command or query turn does not drain runtime queues. It
reads currently projected rows or commits authored facts to durable pending
projection. Because temp tables are connection-local and a CLI command runs on a
separate connection from the daemon, temp rows from one turn are not handed to
another turn (see diagram 3):

```text
facts (+ local_fact_admissions)   immutable fact store
network_incoming                  raw inbound frame bytes awaiting classification (temp)
incoming_facts                    incoming facts staged for projection (temp)
pending_projection                pending facts waiting to be projected
context_edges                     standing needs and offers
pending_projection_matches        offers that matched a parked need
time_wakes                        facts scheduled to reproject at a time
intents (+ local_intents)         bounded work waiting for a handler (local is temp)
network_outgoing                  sealed bytes waiting for the TCP pump
<scope>_rows                      materialized state, read by queries and handlers, never by projectors
```

The sections below isolate the main queue transitions and runtime boundaries.

## 1) The Runtime Loop

A durable fact reaches projection through `pending_projection`. A network fact
reaches projection through `incoming_facts`. Projector output can add context,
rows, time wakes, intents, emitted durable facts, emitted incoming facts, or a
decision to retain the incoming input. Core matches new offers against parked
needs, re-queues woken owners, and dispatches intents to handlers; handler
output re-enters the same queues.

Materialized rows are read-model and planning state, not part of the projection
and context-match cycle. Projectors and context matching never read them.
Queries read rows, and handlers may read rows when planning bounded work, such
as sync range summaries.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    FACTS[("facts: immutable store")]
    PENDING[("pending: pending_projection")]
    PEER["other peer"]
    NETWORK[("network: TCP + network_incoming")]
    INCOMING[("incoming: incoming_facts")]
    PROJECTOR{{"projection: fact projector (protocol)"}}
    CONTEXT[("context_edges: needs + offers")]
    MATCHES[("pending_projection_matches")]
    WAKES[("time_wakes")]
    INTENTS[("intents + local_intents")]
    HANDLER{{"intent handler (protocol)"}}
    OUT[("network_outgoing")]
    NETOUT["outbound bytes (to peers)"]
    ROWS[("scope rows: materialized")]
    QUERY["query reads rows"]

    PEER --> NETWORK
    NETWORK -->|classify inbound bytes| INCOMING
    FACTS -->|admit| PENDING
    INCOMING --> PROJECTOR
    PENDING --> PROJECTOR
    MATCHES -.matched offer payload.-> PROJECTOR

    PROJECTOR -->|needs + offers| CONTEXT
    PROJECTOR -->|time wakes| WAKES
    PROJECTOR -->|emitted durable facts| FACTS
    PROJECTOR -->|emitted incoming facts| INCOMING
    PROJECTOR -->|intents| INTENTS
    PROJECTOR -.may retain incoming fact.-> FACTS
    PROJECTOR -.context needs keep owner pending.-> PENDING
    PROJECTOR -->|rows| ROWS

    CONTEXT -->|core matches range overlap| MATCHES
    MATCHES -->|wake parked owner| PENDING
    WAKES -->|due time admits owner| PENDING

    INTENTS --> HANDLER
    HANDLER -->|facts| FACTS
    HANDLER -->|rows| ROWS
    HANDLER -->|sealed bytes| OUT

    OUT -->|TCP pump| NETOUT
    ROWS --> QUERY
    ROWS -.read for planning.-> HANDLER
```

Core owns every queue transition and the atomic commit behind it; the rounded
boxes are the protocol callbacks. The inbound classifier turns network bytes
into typed incoming facts, but it does not run projection or decide durability.
Projectors are deterministic derivation: they may park on missing context, but
they do not perform IO. Intent handlers are the protocol-owned boundary for
bounded stateful work. Core still performs mechanical IO of its own: the TCP
listener reads frames, the raw incoming queue holds them until classification,
and the pump writes `network_outgoing`, deferring targets whose sockets are not
ready. That IO moves length-prefixed bytes and never interprets facts.

## 2) Project One Fact

Projection is a single-item queue drain. `Runtime::drain_durable_projection` and
`Runtime::drain_incoming_projection` call `project_one` repeatedly. Each call
handles one durable pending owner or one volatile incoming fact. Everything
before the commit is calculation. The commit consumes the selected work and
publishes replacement context, time wakes, rows, facts, and intents as one SQL
boundary.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    SOURCE["chosen source: durable pending_projection or incoming_facts"] --> LOAD["load one projection input"]
    LOAD --> FOUND{"backing fact bytes found?"}
    FOUND -- no --> STALE["retire stale input in commit"]
    FOUND -- yes --> CONTEXT["attach pending matches and time ranges"]
    CONTEXT --> RUN["run protocol projector"]
    RUN --> VALIDATE["validate owner, rows, effects, and admission"]
    VALIDATE --> ACCEPTED{"projector accepted input?"}
    ACCEPTED -- no --> REJECT["retire rejected work in commit"]
    ACCEPTED -- yes --> PREPARED["PreparedProjection"]

    STALE --> CLEANUP["cleanup stale selected work"]
    REJECT --> CLEANUP_REJECT["retire rejected selected work"]
    CLEANUP --> END_CLEANUP["commit cleanup transaction"]
    CLEANUP_REJECT --> END_CLEANUP

    PREPARED --> COMMIT["commit accepted projection transaction"]
    COMMIT --> SOURCE_BOUNDARY["consume source marker or incoming row"]
    SOURCE_BOUNDARY --> KEEP_STATE{"keeps standing projection state?"}
    KEEP_STATE -- yes --> CONTEXT_STATE["replace needs, append offers"]
    CONTEXT_STATE --> WAKE["wake newly matched dependent owners"]
    KEEP_STATE -- yes --> TIME_STATE["replace owner time wakes"]
    KEEP_STATE -- no --> DROP["drop volatile or self-purged state"]
    WAKE --> EFFECTS["commit RuntimeEffects"]
    TIME_STATE --> EFFECTS
    DROP --> EFFECTS

    EFFECTS --> FACTS["admit facts and priority facts"]
    EFFECTS --> INCOMING["stage incoming facts"]
    EFFECTS --> ROWS["apply row mutations"]
    EFFECTS --> INTENTS["record durable and local intents"]
    EFFECTS --> PURGES["purge allowed exact facts"]
```

Durable projection drains from `pending_projection`; incoming projection drains
from process-local `incoming_facts`. Incoming rows project once. The projector
may retain the incoming fact as durable evidence, retain it while parked on
context, or drop it after opening it into incoming child facts. Emitted facts
are not projected inline: durable emitted facts go to `facts` and
`pending_projection`, incoming emitted facts go to `incoming_facts`, and a later
projection item handles each one.

## 3) Serialized Turns And Locks

Commands, queries, and the daemon turn all acquire `<db>.runtime.lock`, but they
do not all drive the runtime loop. A normal write command verifies storage
readiness, reads currently projected state, authors facts, commits them to
durable pending projection, and returns a receipt. A normal query verifies
storage readiness and reads currently projected rows. Maintenance commands such
as protocol update and replay diagnostics may bypass readiness, but they still
do not run daemon queue drains. The daemon turn (the recurring scheduler plus
`daemon::tick`) is the live loop that advances queues.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    LOCK["acquire <db>.runtime.lock"]

    LOCK --> CMD["ordinary write command turn"]
    CMD --> CMD_READY["require storage_ready"]
    CMD_READY --> READ_INPUTS["read current projected rows"]
    READ_INPUTS --> AUTHOR["author facts"]
    AUTHOR --> COMMIT_FACTS["commit authored facts -> pending_projection"]
    COMMIT_FACTS --> RECEIPT["return receipt"]

    LOCK --> Q["ordinary query turn"]
    Q --> Q_READY["require storage_ready"]
    Q_READY --> READ["read materialized rows"]

    LOCK --> MAINT["maintenance or diagnostic command"]
    MAINT --> MAINT_WORK["read diagnostics or submit priority update effects"]
    MAINT_WORK --> MAINT_RETURN["return output"]

    LOCK --> TICK["daemon turn"]
    TICK --> DAEMON_TICK["run daemon::tick"]
```

The difference between turns is whether they drain queues at all. Queries and
commands do not drain projection, incoming facts, time wakes, recurring work, or
handlers; they observe already projected state and may enqueue authored facts for
the daemon. Handler-emitted facts are committed atomically with intent dispatch
and remain queued for a later durable projection batch.

```mermaid
sequenceDiagram
    participant D as daemon process
    participant L as RuntimeTurnLock
    participant C as CLI process
    participant R as Runtime

    D->>L: acquire for daemon tick
    L-->>D: granted
    D->>R: run daemon tick
    C->>L: acquire for CLI command
    Note over C,L: OS blocks while daemon holds flock
    D->>L: release
    L-->>C: granted
    C->>R: open runtime
    C->>R: run registered protocol CLI command
    alt ordinary query
        C->>R: require storage_ready
        C->>R: read projected state
    else ordinary write command
        C->>R: require storage_ready
        C->>R: read projected state
        C->>R: submit AuthoredFacts
    else maintenance command
        C->>R: run diagnostic or submit update effects
    end
    C->>L: release
    D->>L: acquire for next daemon tick
```

The lock is an OS `flock`. A CLI process that arrives while the daemon is in a
turn waits in the kernel until the daemon releases the file lock. There is no
shared in-process command slot inside the daemon tick.

## 4) Daemon Tick Queue Order

Inside one daemon tick, recurring schedules get a pre-readiness pass that stops
after the first queued local intent. Protocols can put a readiness repair route
first, giving that work a chance to run before live IO. If storage is ready, the
daemon runs the live queues in an explicit order. The full `project one fact`
path above is represented here as a single node.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    START["daemon::tick"] --> FIRST["fire due recurring schedules until one intent queues"]
    FIRST --> FIRST_DRAIN{"queued an early local intent?"}
    FIRST_DRAIN -- yes --> LOCAL_ONE["drain one local intent"]
    LOCAL_ONE --> DURABLE_REPAIR["drain durable projection after early intent"]
    FIRST_DRAIN -- no --> READY_ONE{"storage_ready?"}
    DURABLE_REPAIR --> READY_ONE
    READY_ONE -- no --> REPAIR["drain repair queues only"]
    REPAIR --> RETURN_REPAIR["return from tick"]

    READY_ONE -- yes --> RECUR["fire remaining due recurring intents"]
    RECUR --> LOCAL["drain local intents"]
    LOCAL --> DURABLE_PRE["drain durable projection"]
    DURABLE_PRE --> READY_TWO{"storage_ready?"}
    READY_TWO -- no --> REPAIR
    READY_TWO -- yes --> INBOUND["accept frames into network_incoming"]
    INBOUND --> CLASSIFY_IN["drain network_incoming into incoming_facts"]
    CLASSIFY_IN --> TIME["admit due time_wakes"]
    TIME --> DURABLE["drain durable projection"]
    DURABLE --> INCOMING["drain incoming projection"]
    INCOMING --> DURABLE_INTENTS["drain durable intents"]
    DURABLE_INTENTS --> LOCAL_INTENTS["drain local intents"]
    LOCAL_INTENTS --> OUTGOING["pump network_outgoing"]
    OUTGOING --> DONE["return active flag"]

    DURABLE --> PROJECT_ONE["project one durable pending fact"]
    INCOMING --> PROJECT_INCOMING["project one incoming fact"]
    DURABLE_INTENTS --> HANDLER_DURABLE["dispatch one durable intent"]
    LOCAL_INTENTS --> HANDLER_LOCAL["dispatch one local intent"]
```

The recurring steps are daemon-only and are the source of all periodic work.
Recurring intents are not durable state: an in-memory `RecurringScheduler`,
installed once from the handler registry at daemon start, fires due operational
loops during `daemon::tick` and enqueues ordinary local intents. The pre-readiness
recurring pass gives the first queued local intent a special repair chance before
live IO; if storage is not ready, the daemon drains only repair queues and skips
normal network and wall-clock work. The live daemon's cadence is only the
scheduling mechanism; the work itself is plain facts and handlers.

## 5) Needs And Offers

Context matching is the one mechanism that lets facts wake each other without
core understanding them. A projector that lacks proof emits a **need** and
parks; any fact may publish an **offer**. The match is not a background scan: it
runs inside the projection commit in `project_fact.rs`. When a projector's
output commits, core takes the needs and offers that output just added (the
context delta) and matches them against the already-stored set on `(role, scope,
range)` overlap — symmetrically, a newly committed offer wakes the owners of
overlapping stored needs, and a newly committed need is checked against stored
offers. Core records each hit in `pending_projection_matches` and re-queues the
matched owner with the offer payload attached; the woken projector then decides
whether that payload actually proves what it needed.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    A["fact A projector: missing proof"] -->|emit need role/scope/range| NEED[("context_edges: need (A)")]
    NEED --> PARK["A parked in pending_projection"]

    B["fact B projector: accepted"] -->|emit offer role/scope/range| OFFER[("context_edges: offer (B)")]

    NEED --> MATCH{{"core: range overlap match<br/>(runs at projection commit)"}}
    OFFER --> MATCH
    MATCH -->|record| MATCHED[("pending_projection_matches: B for A")]
    MATCHED -->|re-queue A| PENDING[("pending_projection")]
    PENDING --> REPROJECT["A projector reruns with B's payload"]
    REPROJECT -->|payload proves it| OUT["replace needs, emit rows + offers + intents"]
    REPROJECT -.payload insufficient.-> NEED
```

Three properties make this more than a dependency block: an offer may be
published before the need that consumes it exists; one offer can satisfy many
needs; and needs are a *replacement* subscription (a reprojection's needs fully
replace the prior set) while offers are append-only evidence until the owner
fact is purged. The concrete role/range catalog lives beside each scope's
projector docs, not here.

## 6) Queued Cause Chain

A runtime turn is one exclusive period under `RuntimeTurnLock`, but a causal
chain can span many turns. Entry points first commit queued work. Later daemon
or replay drains project one fact or dispatch one intent. Projection and
handlers can both emit more queued work, so the same chain moves forward without
nesting projection or handlers inline.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart LR
    subgraph ENTRY["turn N: entry point"]
        CMD["CLI command"] --> AUTHORED["commit AuthoredFacts"]
        NET["network_incoming drain"] --> INCOMING["commit incoming_facts"]
        TIME["due time_wake"] --> WOKEN["mark owner pending_projection"]
        HANDLER_OUT["handler output"] --> EFFECTS_IN["commit RuntimeEffects"]
    end

    AUTHORED --> QUEUES[("pending_projection, incoming_facts, intents")]
    INCOMING --> QUEUES
    WOKEN --> QUEUES
    EFFECTS_IN --> QUEUES

    subgraph DRAIN["same or later daemon/replay queue step"]
        QUEUES --> PROJECT["project one fact"]
        PROJECT --> NEEDS["standing needs"]
        PROJECT --> OFFERS["standing offers"]
        NEEDS --> MATCH["context overlap match"]
        OFFERS --> MATCH
        MATCH --> WAKE["wake dependent owner"]
        PROJECT --> INTENT["emit intent"]
        QUEUES --> HANDLER["dispatch one intent"]
        HANDLER --> EFFECTS_OUT["commit RuntimeEffects"]
    end

    WAKE --> QUEUES
    INTENT --> QUEUES
    EFFECTS_OUT --> QUEUES
```

The contract is that queue commits, not call-stack nesting, carry the chain
forward. A handler that emits facts does not project them before returning; a
projector that emits intents does not run their handlers before committing.

## 7) Daemon Network Flow

The daemon owns background network progress. Incoming bytes are accepted by core
into `network_incoming`, then drained through the protocol inbound classifier
into `incoming_facts`. Projection opens those incoming facts with standing
context plus incoming metadata. Projectors emit durable observation or receipt
facts when receive metadata must survive replay, and established frame
projectors stage contained facts back into incoming projection. Outgoing bytes
are produced by protocol handlers and written by the core TCP pump.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart LR
    PEER["another peer"] --> TCP_IN["TCP listener"]

    subgraph DAEMON["local daemon tick"]
        TCP_IN --> ACCEPT["accept_available"]
        ACCEPT --> RAW_IN["network_incoming raw bytes + origin metadata"]
        RAW_IN --> INTAKE["receive_network_frame_facts"]
        INTAKE --> FRAME_FACT["incoming request, connection, or frame fact"]
        RAW_IN -.origin and receive-time metadata.-> PROJECT_FRAME["drain incoming projection: project frame fact"]
        FRAME_FACT --> PROJECT_FRAME
        PROJECT_FRAME --> CHILD_FACTS["opened child facts"]
        CHILD_FACTS --> CHILD_INCOMING[("incoming_facts")]
        PROJECT_FRAME --> RECEIVE_FACTS["receipt or observation facts"]
        RECEIVE_FACTS --> RETAINED_FACTS[("facts -> pending_projection")]
        CHILD_INCOMING --> LATER_PROJECT["later projection"]
        RETAINED_FACTS --> LATER_PROJECT

        LATER_PROJECT --> FOLLOWUP_INTENTS["sync or connection follow-up intents"]
        FOLLOWUP_INTENTS --> SEND_FACTS["send_facts_on_connection handler"]
        FOLLOWUP_INTENTS --> QUEUE_FRAME["queue_outgoing_frame handler"]
        SEND_FACTS --> OUTBOUND_ROWS["network_outgoing rows"]
        QUEUE_FRAME --> OUTBOUND_ROWS
        OUTBOUND_ROWS --> TCP_OUT["TCP pump"]
    end

    TCP_OUT --> PEER
```

`receive_network_frame_facts` does not unseal established frames or run a
handler. It chooses the incoming fact family from frame bytes and lets that
fact's projector decide whether to retain or drop the fact. Origin and
receive-time metadata stay on the incoming queue/context path; projectors use
that metadata only when emitting durable observation or receipt facts.

## 8) Sync: The Convergence Loop

The previous sections describe one node's loop. Sync is the same loop
alternating between peers over time. The network adds no separate runtime
machinery: every message on the wire is an ordinary fact, so each step is the
same `admit -> project (writes a row) -> emit intent -> handler emits the next
message` cycle. The summaries exchanged are negentropy range summaries (a
`count` and a `fingerprint`) over each peer's durable share/leaf/node index.

```mermaid
sequenceDiagram
    autonumber
    participant A as Node A
    participant B as Node B

    Note over A,B: Each arrow is a sealed connection frame. The sender's handler queues<br/>send_facts_on_connection. The receiver classifies bytes into incoming_facts,<br/>then a frame projector stages the named sync fact for projection.

    Note over A: owner (auth/content) projector admits a shared fact and emits<br/>share_fact_with_sync. Its handler upserts shareable + negentropy<br/>leaf/node rows — the durable range index (count + fingerprint).
    Note over A: seed_connection_sync / maintain_sync handler reads that index,<br/>builds a range summary, and emits the first compare.

    A->>B: compare(range, summary{count, fingerprint})

    loop until the two range summaries are equal
        Note over B: admit compare -> project (sync_compare_rows) -> emit send_sync_compare_response.<br/>Handler reads B's shareable + negentropy rows and diffs the summaries.
        alt summaries differ broadly
            B->>A: compare(child range, summary)
            Note over A: same admit -> project -> handler step on a narrower range
        else difference localized to specific facts
            B->>A: fact bytes: in-range owners + context_have dependency closure
            Note over A: opened bytes admit as ordinary facts. Owning projectors validate,<br/>materialize rows, emit share_fact_with_sync -> A's index now matches B
        end
    end

    Note over A,B: Exact-id request path (have_id / need_id): used when a peer advertises<br/>one specific id instead of bulk-comparing. Same project -> intent -> handler shape.
    opt advertise, then request a single id
        B->>A: have_id(fact_id)
        Note over A: project have_id (sync_have_id_rows) -> send_needed_fact_id.<br/>If A lacks the id, the handler authors need_id
        A->>B: need_id(fact_id)
        Note over B: project need_id (sync_need_id_rows) -> send_requested_fact.<br/>Handler loads that one fact, checks it is shareable here, sends it (no closure)
        B->>A: fact bytes: the single requested fact
    end

    Note over A,B: Summaries equal -> converged. New local facts live-tail immediately:<br/>a share_fact_with_sync upsert queues send_facts_on_connection to live peers<br/>without waiting for the next compare round.
```

The same exchange runs in both directions over one connection, so each peer both
sends and receives. A productive response narrows the compared range, transfers
selected facts plus their closure, or just returns a same-range summary; for a
stable, authorized range whose transferred facts are admitted, these responses
drive the summaries together. But a round can make no progress — a same-range
summary with nothing to send, or a no-op because the peer already has the fact,
or it is missing, unshareable, or rejected on projection — so convergence is
eventual, not guaranteed per round.

Two boundaries define the exchange. **Sync vs connection:** sync chooses fact
ids and their dependency closure; connection decides how to batch, seal,
address, and write the bytes, and records a `connection_fact_receipt` so
live-tail can skip the origin peer. **Core vs protocol:** core pumps
length-prefixed bytes and never parses a frame; recurring drivers
(`maintain_connections`, `maintain_sync`) are handlers emitting ordinary facts.
The handshake that brings a connection live (request, connection,
ephemeral-secret context), the established frame types (`frame_small`,
`frame_file_slice`, `frame_bundle`), and the exact compare/have/need fact
layouts are detailed in `src/protocol/connection/README.md` and
`src/protocol/sync/README.md`.
