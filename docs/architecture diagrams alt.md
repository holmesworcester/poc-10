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
flowchart TD
    pending["pending_projection or ephemeral_projection_inputs"] --> load["load pending fact"]
    load --> previous["load previous standing context"]
    previous --> matched["load matched offers and pending time ranges"]
    matched --> run["run protocol projector"]
    run --> validate["validate row mutations and effects"]
    validate --> fixedPoint{"newly declared needs match stored offers?"}
    fixedPoint -- yes --> extend["extend in-memory ProjectionContext"]
    extend --> run
    fixedPoint -- no --> output["settled ProjectionOutput"]

    output --> commit["commit_projection_effects transaction"]
    commit --> clear["clear pending row and pending time ranges"]
    commit --> replaceContext["replace this owner's context edges"]
    commit --> replaceWakes["replace this owner's time wakes"]
    commit --> wake["wake newly matched dependent facts"]
    commit --> effects["commit PipelineEffects"]

    effects --> childFacts["project emitted child facts inline"]
    effects --> rows["apply row mutations"]
    effects --> intents["record durable and local intents"]
    effects --> purges["purge allowed exact facts"]
```

## Daemon Queue Drain

`Runtime::drain_daemon_queues_once` is the daemon's queue-settling policy after
network IO and time wakes have been handled. The full `project one fact` path
above is represented here as a single node.

```mermaid
flowchart TD
    start["drain_daemon_queues_once(limit)"] --> preProject["process_projection_until_idle"]
    preProject --> projectOne["project one pending fact"]
    projectOne --> moreProjection{"pending projection remains and rounds remain?"}
    moreProjection -- yes --> projectOne
    moreProjection -- no --> dispatch["dispatch_intents with full handler set"]

    dispatch --> nextIntent{"registered durable or local intent exists?"}
    nextIntent -- yes --> handler["run one intent handler"]
    handler --> retry{"handler requested retry?"}
    retry -- yes --> stopDispatch["stop this bounded dispatch pass"]
    retry -- no --> commitHandler["commit handler output and consume intent"]
    commitHandler --> nextIntent
    nextIntent -- no --> postProject["process_projection_until_idle"]
    stopDispatch --> postProject

    postProject --> projectAfter["project one pending fact"]
    projectAfter --> moreAfter{"pending projection remains and rounds remain?"}
    moreAfter -- yes --> projectAfter
    moreAfter -- no --> done["return WorkStatus"]
```

## Turns, Matches, And Intents

A runtime turn is one exclusive period under `RuntimeTurnLock`. Work can remain
queued between turns. Projection creates standing context. Newly added offers
wake matching needs. Projection and handlers both emit intents, and handlers can
emit more facts, so later turns may keep moving the same causal chain forward.

```mermaid
flowchart LR
    subgraph turn1["runtime turn N"]
        source["command, handler, sync, network, or time wake"] --> fact["admit fact or mark owner pending"]
        fact --> project["project pending fact"]
        project --> needs["standing needs"]
        project --> offers["standing offers"]
        offers --> match["context overlap match"]
        needs --> match
        match --> wake["wake dependent owner into pending_projection"]
        project --> intent["durable or local intent"]
        intent --> handler["dispatch registered handler"]
        handler --> effects["PipelineEffects"]
        effects --> emittedFacts["emitted facts"]
        effects --> followups["follow-up intents"]
    end

    emittedFacts --> queuedFacts["queued fact work"]
    followups --> queuedIntents["queued intent work"]
    wake --> queuedFacts

    subgraph turn2["runtime turn N + 1"]
        queuedFacts --> projectAgain["project pending fact"]
        queuedIntents --> handlerAgain["dispatch intent"]
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
flowchart LR
    peer["another peer"] --> tcpIn["TCP listener"]

    subgraph daemon["local daemon tick"]
        tcpIn --> accept["accept_available"]
        accept --> inboundRows["network inbound rows"]
        inboundRows --> stage["convert inbound rows to local receive_network_frame intents"]
        stage --> drain["drain daemon queues"]

        drain --> receiveHandler["receive_network_frame handler"]
        receiveHandler --> frameFact["connection frame fact"]
        frameFact --> projectFrame["project frame fact"]
        projectFrame --> recovered["recovered protocol facts"]
        recovered --> projectRecovered["project recovered facts"]

        projectRecovered --> followupIntents["sync or connection follow-up intents"]
        followupIntents --> sendFacts["send_facts_on_connection handler"]
        sendFacts --> sendFrame["send_network_frame handler"]
        sendFrame --> outboundRows["network outbound rows"]
        outboundRows --> tcpOut["TCP pump"]
    end

    tcpOut --> peer
```
