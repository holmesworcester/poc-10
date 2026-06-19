# Architecture Diagrams Alt

These diagrams describe the current poc-10 runtime shape in code terms. The
important distinction is that a daemon tick and a CLI invocation are separate
runtime turns. They do not call each other. They serialize through the same
`RuntimeTurnLock` for one database.

## Project One Fact

`Runtime::drain_projection_once` repeatedly reduces pending projection and
incoming fact work to this per-fact path. Everything before the commit is
calculation. The commit is the durable boundary that consumes the pending row
or incoming row and publishes replacement context, time wakes, rows, facts,
purges, and intents.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    PENDING["pending_projection or incoming_facts"] --> LOAD["load fact"]
    LOAD --> PREVIOUS["load previous standing context"]
    PREVIOUS --> MATCHED["load matched offers and pending time ranges"]
    MATCHED --> RUN["run protocol projector"]
    RUN --> VALIDATE["validate row mutations and RuntimeEffects"]
    VALIDATE --> OUTPUT["settled ProjectionOutput"]

    OUTPUT --> COMMIT["commit_projection_effects transaction"]
    COMMIT --> CLEAR["clear pending or incoming row and pending time ranges"]
    COMMIT --> REPLACE_CONTEXT["replace needs and append offers"]
    COMMIT --> REPLACE_WAKES["replace owner time wakes"]
    COMMIT --> WAKE["record matches and wake dependent facts"]
    COMMIT --> EFFECTS["commit RuntimeEffects"]

    EFFECTS --> PURGES["purge exact facts"]
    EFFECTS --> CHILD_FACTS["admit durable emitted facts -> facts + pending_projection"]
    EFFECTS --> ROWS["apply row mutations"]
    EFFECTS --> INTENTS["record durable and local intents"]
```

Newly emitted needs do not cause an in-memory projector fixed point. If a new
need overlaps an existing offer, core records the match and queues the owner for
a later projection item. Until that match happens, the owner is parked by its
standing need, not kept in `pending_projection`. Durable child facts emitted by
a projector are admitted to `facts` and marked in `pending_projection` in the
same transaction; they are not projected inline inside the parent's commit.
`RuntimeEffects::incoming_facts` is the separate temp staging path for
outside-origin inputs.

## Daemon Queue Steps

Inside one daemon tick, recurring intents fire first, then inbound network and
time wakes feed the runtime queues. The daemon then runs two explicit runtime
queue steps: one high-volume projection batch and one bounded intent batch. The
full `project one fact` path above is represented here as a single node.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    START["daemon::tick"] --> RECUR["fire due recurring intents -> local_intents"]
    RECUR --> INBOUND["accept frames -> inbound intake"]
    INBOUND --> TIME["admit due time_wakes"]
    TIME --> PRE_PROJECT["Runtime::drain_projection_once(high local limit)"]
    PRE_PROJECT --> PROJECT_ONE["project one pending fact"]
    PROJECT_ONE --> MORE_PROJECTION{"pending projection remains and batch budget remains?"}
    MORE_PROJECTION -- yes --> PROJECT_ONE
    MORE_PROJECTION -- no --> DISPATCH["Runtime::drain_intents_once(base limit)"]

    DISPATCH --> NEXT_INTENT{"registered durable or local intent exists?"}
    NEXT_INTENT -- yes --> HANDLER["run one intent handler"]
    HANDLER --> RETRY{"handler requested retry?"}
    RETRY -- yes --> STOP_DISPATCH["stop this bounded dispatch pass"]
    RETRY -- no --> COMMIT_HANDLER["commit handler output and consume intent"]
    COMMIT_HANDLER --> NEXT_INTENT
    NEXT_INTENT -- no --> PUMP["pump network_outgoing"]
    STOP_DISPATCH --> PUMP
    PUMP --> DONE["return WorkStatus"]
```

Durable intent retry stops the bounded dispatch pass. Local intent retry rotates
the row to the tail, and dispatch may continue until it would retry the same
local intent again.

## Turns, Matches, And Intents

A runtime turn is one exclusive period under `RuntimeTurnLock`. Work can remain
queued between turns. Projection creates standing context. Newly added offers
wake matching needs. Projection and handlers both emit intents, and handlers can
emit more facts, so later turns may keep moving the same causal chain forward.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart LR
    subgraph TURN_ONE["runtime turn N"]
        SOURCE["command, handler, sync, network, or time wake"] --> FACT["admit durable fact -> pending_projection, or stage incoming fact"]
        FACT --> PROJECT["project scheduled fact or incoming input"]
        PROJECT --> NEEDS["standing needs<br/>(parked, not pending)"]
        PROJECT --> OFFERS["standing offers"]
        OFFERS --> MATCH["context overlap match"]
        NEEDS --> MATCH
        MATCH --> WAKE["matching offer re-queues owner into pending_projection"]
        PROJECT --> INTENT["durable or local intent"]
        INTENT --> HANDLER["dispatch registered handler"]
        HANDLER --> EFFECTS["RuntimeEffects"]
        EFFECTS --> EMITTED_FACTS["durable emitted facts -> facts + pending_projection"]
        EFFECTS --> FOLLOWUPS["follow-up intents"]
    end

    EMITTED_FACTS --> QUEUED_FACTS["queued fact work"]
    FOLLOWUPS --> QUEUED_INTENTS["queued intent work"]
    WAKE --> QUEUED_FACTS

    subgraph TURN_TWO["runtime turn N plus 1"]
        QUEUED_FACTS --> PROJECT_AGAIN["project pending fact"]
        QUEUED_INTENTS --> HANDLER_AGAIN["dispatch intent"]
    end
```

## CLI Commands Are Separate Turns

CLI queries and CLI commands use a separate entry point from the daemon loop.
They wait for the same runtime turn lock. Once they hold the lock, they open the
runtime directly and run a registered protocol CLI command. Ordinary commands
do not implicitly settle projection or dispatch; replay and diagnostic commands
are explicit runtime operations with their own command handlers.

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
    alt query style command
        C->>R: read projected state
    else write style command
        C->>R: read projected state
        C->>R: submit AuthoredFacts
    end
    C->>L: release
    D->>L: acquire for next daemon tick
```

## Daemon Network Flow

The daemon owns background network progress. Another peer is abstracted here as
one node. Incoming network bytes are delivered directly to the protocol intake
hook, which classifies recognized bytes into an incoming frame fact and a local
`frame_observation` fact. Outgoing bytes are produced by protocol handlers and
written by the core TCP pump.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart LR
    PEER["another peer"] --> TCP_IN["TCP listener"]

    subgraph DAEMON["local daemon tick"]
        TCP_IN --> ACCEPT["accept_available"]
        ACCEPT --> INTAKE["receive_network_frame_effects intake"]
        INTAKE --> FRAME_OBS["frame_observation fact"]
        INTAKE --> FRAME_FACT["incoming connection frame fact"]
        FRAME_OBS --> DRAIN["run projection batch, then intent batch"]
        FRAME_FACT --> DRAIN

        DRAIN --> PROJECT_FRAME["project frame fact"]
        PROJECT_FRAME --> RECOVERED["recovered protocol facts"]
        PROJECT_FRAME --> RECEIPTS["connection_fact_receipt facts"]
        RECOVERED --> PROJECT_RECOVERED["project recovered facts"]
        RECEIPTS --> PROJECT_RECEIPTS["project receipts"]

        PROJECT_RECOVERED --> FOLLOWUP_INTENTS["sync or connection follow-up intents"]
        FOLLOWUP_INTENTS --> SEND_FACTS["send_facts_on_connection handler"]
        FOLLOWUP_INTENTS --> QUEUE_FRAME["queue_outgoing_frame handler"]
        SEND_FACTS --> OUTBOUND_ROWS["network_outgoing rows"]
        QUEUE_FRAME --> OUTBOUND_ROWS
        OUTBOUND_ROWS --> TCP_OUT["TCP pump"]
    end

    TCP_OUT --> PEER
```
