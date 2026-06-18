# Architecture Diagrams Alt

These diagrams describe the current poc-10 runtime shape in code terms. The
important distinction is that a daemon tick and a CLI invocation are separate
runtime turns. They do not call each other. They serialize through the same
`RuntimeTurnLock` for one database.

## Project One Fact

`Runtime::drain_durable_projection` and `Runtime::drain_incoming_projection`
call `project_one` repeatedly. Each call handles one durable pending owner or
one volatile incoming fact. Everything before the commit is calculation. The
commit consumes the selected work and publishes replacement context, time wakes,
rows, facts, and intents as one SQL boundary.

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

    STALE --> COMMIT["commit projection outcome transaction"]
    REJECT --> COMMIT
    PREPARED --> COMMIT

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

## Daemon Queue Steps

Inside one daemon tick, the first due recurring loop gets a chance to repair
storage before live IO. If storage is ready, the daemon runs the live queues in
an explicit order. The full `project one fact` path above is represented here as
a single node.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart TD
    START["daemon::tick"] --> FIRST["fire first due recurring intent"]
    FIRST --> FIRST_DRAIN{"queued repair intent?"}
    FIRST_DRAIN -- yes --> LOCAL_ONE["drain one local intent"]
    LOCAL_ONE --> DURABLE_REPAIR["drain durable projection"]
    FIRST_DRAIN -- no --> READY_ONE{"storage_ready?"}
    DURABLE_REPAIR --> READY_ONE
    READY_ONE -- no --> REPAIR["drain repair queues only"]
    REPAIR --> RETURN_REPAIR["return from tick"]

    READY_ONE -- yes --> RECUR["fire remaining due recurring intents"]
    RECUR --> LOCAL["drain local intents"]
    LOCAL --> DURABLE_PRE["drain durable projection"]
    DURABLE_PRE --> READY_TWO{"storage_ready?"}
    READY_TWO -- no --> REPAIR
    READY_TWO -- yes --> INBOUND["accept frames and commit inbound RuntimeEffects"]
    INBOUND --> TIME["admit due time_wakes"]
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
        HANDLER --> EFFECTS["RuntimeEffects"]
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
runtime directly and run a registered protocol CLI command. Queries and
commands require `storage_ready`, then read currently projected rows. Write
commands commit authored facts to durable pending projection and return; they do
not drain projection, incoming facts, time wakes, recurring work, or handlers.

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
    C->>R: require storage_ready
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
one node. Incoming network bytes are accepted by core and passed to the protocol
inbound intake hook. The hook commits `RuntimeEffects`: a retained receive
observation fact plus a temporary incoming frame fact for recognized frames.
Projection opens that incoming fact with standing context and emits recovered
protocol facts. Outgoing bytes are produced by protocol handlers and written by
the core TCP pump.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300}} }%%
flowchart LR
    PEER["another peer"] --> TCP_IN["TCP listener"]

    subgraph DAEMON["local daemon tick"]
        TCP_IN --> ACCEPT["accept_available"]
        ACCEPT --> INTAKE["receive_network_frame_effects"]
        INTAKE --> OBSERVATION["retained frame_observation fact"]
        INTAKE --> FRAME_FACT["incoming request, connection, or frame fact"]
        OBSERVATION -.origin and receive-time context.-> PROJECT_FRAME["drain incoming projection: project frame fact"]
        FRAME_FACT --> PROJECT_FRAME
        PROJECT_FRAME --> RECOVERED["recovered protocol facts"]
        RECOVERED --> DURABLE_PROJECT["later durable projection"]

        DURABLE_PROJECT --> FOLLOWUP_INTENTS["sync or connection follow-up intents"]
        FOLLOWUP_INTENTS --> SEND_FACTS["send_facts_on_connection handler"]
        FOLLOWUP_INTENTS --> QUEUE_FRAME["queue_outgoing_frame handler"]
        SEND_FACTS --> OUTBOUND_ROWS["network_outgoing rows"]
        QUEUE_FRAME --> OUTBOUND_ROWS
        OUTBOUND_ROWS --> TCP_OUT["TCP pump"]
    end

    TCP_OUT --> PEER
```
