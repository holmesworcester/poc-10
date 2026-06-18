# Architecture Diagrams

GitHub-renderable Mermaid flowcharts for the Context runtime. They are a visual
companion to `README.md`, `src/core/README.md`, `docs/RULES.md`, and the scope
READMEs; the Rust modules remain the source of truth.

## The One Idea

The whole runtime is a small set of **queues** plus a little protocol-supplied
logic that core pumps between them. Two functions do the steady-state work of
the loop:

- a **fact projector** turns one fact into standing context, rows, time wakes,
  intents, and follow-up facts, and
- an **intent handler** performs one bounded stateful action (IO, sealing,
  responding) and returns more facts.

Protocol code also has thinner hooks at the edges — it authors facts for a
command, converts inbound network bytes into `RuntimeEffects`, and validates a
fact on admission — but those only feed the queues; the projector and handler
are where queued work is transformed.

Core never interprets a fact. It only admits facts, matches context ranges,
schedules wakes, and pumps these queues through the protocol functions. Most
queues are durable SQLite tables that survive restart; `incoming_facts` and
`local_intents` are `CREATE TEMP TABLE`, so they last as long as the SQLite
connection — the whole daemon session, or one CLI command — and a restart
rebuilds them empty. The daemon drains them each tick on its own long-lived
connection. A CLI command or query turn does not drain runtime queues. It reads
currently projected rows or commits authored facts to durable pending
projection. Because temp tables are connection-local and a CLI command runs on a
separate connection from the daemon, any temp rows such a turn stages are
dropped when its connection closes — they are not handed to the daemon (see
diagram 2):

```text
facts (+ local_fact_admissions)   immutable fact store
incoming_facts                    outside-origin facts staged for projection (temp)
pending_projection                facts waiting to be projected
context_edges                     standing needs and offers
pending_projection_matches        offers that matched a parked need
time_wakes                        facts scheduled to reproject at a time
intents (+ local_intents)         bounded work waiting for a handler (local is temp)
network_outgoing                  sealed bytes waiting for the TCP pump
<scope>_rows                      materialized state — read by queries and handlers, never by projectors
```

Each diagram below is one zoom level on that loop.

## 1) The Runtime Loop

A fact lands in `pending_projection` and the projector runs. Its output fans
into the other queues; core matches new offers against parked needs, re-queues
the woken owners, and dispatches intents to handlers, whose facts re-enter the
loop. Materialized rows are read-model and planning state, not part of the
projection→match cycle: projectors and context matching never read them.
Queries read rows, and handlers may read them when planning work (for example,
sync computing range summaries).

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    FACTS[("facts: immutable store")]
    PENDING[("pending_projection")]
    NETIN["inbound bytes (from peers)"]
    INTAKE{{"inbound intake hook (protocol)"}}
    EFFECTS["RuntimeEffects"]
    INCOMING[("incoming_facts (temp)")]
    PROJECTOR{{"fact projector (protocol)"}}
    CONTEXT[("context_edges: needs + offers")]
    MATCHES[("pending_projection_matches")]
    WAKES[("time_wakes")]
    INTENTS[("intents + local_intents")]
    HANDLER{{"intent handler (protocol)"}}
    OUT[("network_outgoing")]
    NETOUT["outbound bytes (to peers)"]
    ROWS[("scope rows: materialized")]
    QUERY["query reads rows"]

    NETIN --> INTAKE
    INTAKE --> EFFECTS
    EFFECTS -->|incoming facts| INCOMING
    EFFECTS -->|retained facts| FACTS
    EFFECTS -->|intents| INTENTS
    FACTS -->|admit| PENDING
    INCOMING --> PROJECTOR
    PENDING --> PROJECTOR
    MATCHES -.matched offer payload.-> PROJECTOR

    PROJECTOR -->|needs + offers| CONTEXT
    PROJECTOR -->|time wakes| WAKES
    PROJECTOR -->|intents| INTENTS
    PROJECTOR -->|follow-up facts| FACTS
    PROJECTOR -.may retain incoming fact.-> FACTS
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

Core owns every arrow and the atomic commit behind it; the rounded boxes are the
only protocol code on the diagram. The inbound intake hook classifies opaque
network bytes into runtime effects but does not run projection. The projector is
pure derivation (it may park on missing context but never does IO); the handler
is the only place *protocol* code does bounded stateful work. Core still does
mechanical IO of its own — the TCP listener reads frames and the pump writes
`network_outgoing`, deferring targets whose sockets are not ready — but it moves
opaque bytes and never interprets a fact.

## 2) One Serialized Turn

Commands, queries, and the daemon turn all acquire `<db>.runtime.lock`, but they
do not all drive the runtime loop. A command verifies storage readiness, reads
currently projected state, authors facts, commits them to durable pending
projection, and returns a receipt. A query verifies storage readiness and reads
currently projected rows. The daemon turn (the recurring scheduler plus
`daemon::tick`) is the live loop that advances queues.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    LOCK["acquire <db>.runtime.lock"]

    LOCK --> CMD["command turn"]
    CMD --> CMD_READY["require storage_ready"]
    CMD_READY --> READ_INPUTS["read current projected rows"]
    READ_INPUTS --> AUTHOR["author facts"]
    AUTHOR --> COMMIT_FACTS["commit authored facts -> pending_projection"]
    COMMIT_FACTS --> RECEIPT["return receipt"]

    LOCK --> Q["query turn"]
    Q --> Q_READY["require storage_ready"]
    Q_READY --> READ["read materialized rows"]

    LOCK --> TICK["daemon turn"]
    TICK --> R0["1. fire first due recurring intent"]
    R0 --> R1["if queued: drain one local intent, then durable projection"]
    R1 --> READY1{"storage_ready?"}
    READY1 -- no --> REPAIR["drain repair queues only"]
    REPAIR --> RETURN1["return from tick"]
    READY1 -- yes --> T0["2. fire remaining due recurring intents"]
    T0 --> T1["3. drain local intents"]
    T1 --> T2["4. drain durable projection"]
    T2 --> READY2{"storage_ready?"}
    READY2 -- no --> REPAIR
    READY2 -- yes --> T3["5. accept frames and commit inbound RuntimeEffects"]
    T3 --> T4["6. admit due time_wakes -> pending_projection"]
    T4 --> T5["7. drain durable projection"]
    T5 --> T6["8. drain incoming projection"]
    T6 --> T7["9. drain durable intents"]
    T7 --> T8["10. drain local intents"]
    T8 --> T9["11. pump network_outgoing"]

    T0 -.enqueued local intents drained at.-> T1
    T3 -.incoming facts projected at.-> T6
    T4 -.woken durable owners projected at.-> T5
```

The difference between turns is whether they drain queues at all. Queries and
commands do not drain projection, incoming facts, time wakes, recurring work, or
handlers; they observe already projected state and may enqueue authored facts for
the daemon. Handler-emitted facts are committed atomically with intent dispatch
and remain queued for a later durable projection batch.

The recurring steps are daemon-only and are the source of all periodic work.
Recurring intents are not durable state: an in-memory `RecurringScheduler`,
installed once from the handler registry at daemon start, fires due operational
loops during `daemon::tick` and enqueues ordinary local intents. The first due
recurring loop gets a special readiness-repair chance before live IO; if storage
is not ready, the daemon drains only repair queues and skips normal network and
wall-clock work. The live daemon's cadence is only the scheduling mechanism; the
work itself is plain facts and handlers.

## 3) Needs And Offers

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

## 4) Sync: The Convergence Loop

The previous three diagrams are the loop running on one node. Sync is what makes
two nodes' loops converge, and it is best read as a back-and-forth over time
rather than a flowchart. The crucial point is that the network adds no new
machinery: every message on the wire is an ordinary fact, so each step is the
same `admit -> project (writes a row) -> emit intent -> handler emits the next
message` cycle from diagrams 1-3, just alternating between peers. The summaries
exchanged are negentropy range summaries (a `count` and a `fingerprint`) over
each peer's durable share/leaf/node index.

```mermaid
sequenceDiagram
    autonumber
    participant A as Node A
    participant B as Node B

    Note over A,B: Each arrow is a sealed connection frame. The sender's handler queues<br/>send_facts_on_connection. The receiver's intake stages incoming_facts and a<br/>connection projector opens it into the named sync fact, which is then projected.

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

Two divisions of labor keep this small. **Sync vs connection:** sync only
chooses fact ids and their dependency closure; connection decides how to batch,
seal, address, and write the bytes, and records a `connection_fact_receipt` so
live-tail can skip the origin peer. **Core vs protocol:** core pumps opaque
length-prefixed bytes and never parses a frame — the recurring drivers
(`maintain_connections`, `maintain_sync`) are just handlers emitting ordinary
facts. The handshake that brings a connection live (request, connection,
ephemeral-secret context), the established frame types (`frame_small`,
`frame_file_slice`, `frame_bundle`), and the exact compare/have/need fact
layouts are detailed in `src/protocol/connection/README.md` and
`src/protocol/sync/README.md`.
