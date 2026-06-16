# Architecture Diagrams Alt

These diagrams describe the current poc-10 runtime shape in code terms. The
important distinction is that a daemon tick and a CLI invocation are separate
runtime turns. They do not call each other. They serialize through the same
`RuntimeTurnLock` for one database.

## Project One Fact

`drain_pending_projection` repeatedly reduces pending projection work to this
per-fact path. Everything before the commit is calculation. The commit is the
durable boundary that consumes the pending row and publishes replacement
context, time wakes, rows, facts, and intents.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    PENDING["pending_projection or ephemeral_projection_inputs"] --> LOAD["load pending fact"]
    LOAD --> PREVIOUS["load previous standing context"]
    PREVIOUS --> MATCHED["load matched offers and pending time ranges"]
    MATCHED --> RUN["run protocol projector"]
    RUN --> VALIDATE["validate row mutations and effects"]
    VALIDATE --> FIXED_POINT{"newly declared needs match stored offers?"}
    FIXED_POINT -- yes --> EXTEND["extend in-memory ProjectionContext"]
    EXTEND --> RUN
    FIXED_POINT -- no --> OUTPUT["settled ProjectionOutput"]

    OUTPUT --> COMMIT["commit_projection_effects transaction"]
    COMMIT --> CLEAR["clear pending row and pending time ranges"]
    COMMIT --> REPLACE_CONTEXT["replace owner context edges"]
    COMMIT --> REPLACE_WAKES["replace owner time wakes"]
    COMMIT --> WAKE["wake newly matched dependent facts"]
    COMMIT --> EFFECTS["commit PipelineEffects"]

    EFFECTS --> CHILD_FACTS["project emitted child facts inline"]
    EFFECTS --> ROWS["apply row mutations"]
    EFFECTS --> INTENTS["record durable and local intents"]
    EFFECTS --> PURGES["purge allowed exact facts"]
```

## Daemon Queue Drain

`Runtime::drain_daemon_queues_once` is the daemon's queue-settling policy after
network IO and time wakes have been handled. The full `project one fact` path
above is represented here as a single node.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    START["drain_daemon_queues_once(limit)"] --> PRE_PROJECT["process_projection_until_idle"]
    PRE_PROJECT --> PROJECT_ONE["project one pending fact"]
    PROJECT_ONE --> MORE_PROJECTION{"pending projection remains and rounds remain?"}
    MORE_PROJECTION -- yes --> PROJECT_ONE
    MORE_PROJECTION -- no --> DISPATCH["dispatch_intents with full handler set"]

    DISPATCH --> NEXT_INTENT{"registered durable or local intent exists?"}
    NEXT_INTENT -- yes --> HANDLER["run one intent handler"]
    HANDLER --> RETRY{"handler requested retry?"}
    RETRY -- yes --> STOP_DISPATCH["stop this bounded dispatch pass"]
    RETRY -- no --> COMMIT_HANDLER["commit handler output and consume intent"]
    COMMIT_HANDLER --> NEXT_INTENT
    NEXT_INTENT -- no --> POST_PROJECT["process_projection_until_idle"]
    STOP_DISPATCH --> POST_PROJECT

    POST_PROJECT --> PROJECT_AFTER["project one pending fact"]
    PROJECT_AFTER --> MORE_AFTER{"pending projection remains and rounds remain?"}
    MORE_AFTER -- yes --> PROJECT_AFTER
    MORE_AFTER -- no --> DONE["return WorkStatus"]
```

## Turns, Matches, And Intents

A runtime turn is one exclusive period under `RuntimeTurnLock`. Work can remain
queued between turns. Projection creates standing context. Newly added offers
wake matching needs. Projection and handlers both emit intents, and handlers can
emit more facts, so later turns may keep moving the same causal chain forward.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart LR
    subgraph TURN_ONE["runtime turn N"]
        SOURCE["command, handler, sync, network, or time wake"] --> FACT["admit fact or mark owner pending"]
        FACT --> PROJECT["project pending fact"]
        PROJECT --> NEEDS["standing needs"]
        PROJECT --> OFFERS["standing offers"]
        OFFERS --> MATCH["context overlap match"]
        NEEDS --> MATCH
        MATCH --> WAKE["wake dependent owner into pending_projection"]
        PROJECT --> INTENT["durable or local intent"]
        INTENT --> HANDLER["dispatch registered handler"]
        HANDLER --> EFFECTS["PipelineEffects"]
        EFFECTS --> EMITTED_FACTS["emitted facts"]
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
runtime directly and run a registered protocol CLI command. Command-side
settling is explicit work done by that CLI process; it is not a daemon tick
slot.

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
        C->>R: optionally settle command-safe work
        C->>R: read projected state
    else write style command
        C->>R: submit CommandOutput
        C->>R: optionally settle command-safe work
    end
    C->>L: release
    D->>L: acquire for next daemon tick
```

## Daemon Network Flow

The daemon owns background network progress. Another peer is abstracted here as
one node. Incoming network bytes are staged as opaque rows, converted into local
protocol intents, and later interpreted by registered handlers and projectors.
Outgoing bytes are produced by protocol handlers and written by the core TCP
pump.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart LR
    PEER["another peer"] --> TCP_IN["TCP listener"]

    subgraph DAEMON["local daemon tick"]
        TCP_IN --> ACCEPT["accept_available"]
        ACCEPT --> INBOUND_ROWS["network inbound rows"]
        INBOUND_ROWS --> STAGE["convert inbound rows to local receive_network_frame intents"]
        STAGE --> DRAIN["drain daemon queues"]

        DRAIN --> RECEIVE_HANDLER["receive_network_frame handler"]
        RECEIVE_HANDLER --> FRAME_FACT["connection frame fact"]
        FRAME_FACT --> PROJECT_FRAME["project frame fact"]
        PROJECT_FRAME --> RECOVERED["recovered protocol facts"]
        RECOVERED --> PROJECT_RECOVERED["project recovered facts"]

        PROJECT_RECOVERED --> FOLLOWUP_INTENTS["sync or connection follow-up intents"]
        FOLLOWUP_INTENTS --> SEND_FACTS["send_facts_on_connection handler"]
        SEND_FACTS --> SEND_FRAME["send_network_frame handler"]
        SEND_FRAME --> OUTBOUND_ROWS["network outbound rows"]
        OUTBOUND_ROWS --> TCP_OUT["TCP pump"]
    end

    TCP_OUT --> PEER
```
