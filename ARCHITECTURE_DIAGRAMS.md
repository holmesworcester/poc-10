# Architecture Diagrams

These are GitHub-renderable Mermaid flowcharts for the current Context
architecture. They are a visual companion to `README.md`, `docs/RULES.md`, and
the scope READMEs; the Rust modules remain the source of truth.

## 0) Runtime Boundaries

Context has one protocol-neutral runtime and several protocol scopes. Core owns
fact admission, context matching, queue mechanics, transaction boundaries, and
opaque network bytes. Protocol scopes own fact meaning, projection, row
materialization, and bounded intent handlers.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 320}} }%%
flowchart TD
    USER["CLI command"] --> APP["core app boundary"]
    DAEMON["daemon tick"] --> RUNTIME["core runtime"]
    APP --> RUNTIME

    NET_IN["network_in opaque bytes"] --> DAEMON
    RUNTIME --> PIPE["core pipeline"]
    PIPE --> STORE[("SQLite fact store, context, rows, intents")]
    STORE --> PIPE

    subgraph SCOPES["Protocol scopes"]
      AUTH["auth facts, keys, authority"]
      CONTENT["content facts, opened rows, purge"]
      CONNECTION["connection facts, frames, receipts"]
      SYNC["sync facts, range summaries, visibility"]
    end

    PIPE --> AUTH
    PIPE --> CONTENT
    PIPE --> CONNECTION
    PIPE --> SYNC
    AUTH --> PIPE
    CONTENT --> PIPE
    CONNECTION --> PIPE
    SYNC --> PIPE

    CONNECTION --> NET_OUT["network_outgoing opaque bytes"]
    NET_OUT --> PEER["remote node"]
    PEER --> NET_IN
```

## 1) Fact Admission And Context Matching

Facts enter from commands, received frames, and handlers. Projection emits the
complete standing needs and offers for the fact being projected. Context is a
range relationship: an offer can satisfy many needs, and an offer may exist
before a later fact creates the matching need.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 320}} }%%
flowchart TD
    CMD["command output"] --> EFFECTS["PipelineEffects"]
    RECV["opened network bytes"] --> EFFECTS
    HANDLER_OUT["handler output"] --> EFFECTS

    EFFECTS --> ADMIT["admit immutable facts"]
    ADMIT --> FACTS[("facts")]
    ADMIT --> PENDING[("pending_projection")]

    PENDING --> LOAD["load fact plus matched context"]
    LOAD --> PROJECTOR["owning projector"]
    PROJECTOR --> NEEDS["context needs"]
    PROJECTOR --> OFFERS["context offers"]
    PROJECTOR --> ROWS["scope-owned rows"]
    PROJECTOR --> INTENTS["durable or local intents"]
    PROJECTOR --> TIME["time wakes"]

    NEEDS --> CONTEXT[("context rows")]
    OFFERS --> CONTEXT
    CONTEXT --> MATCH["range-overlap matcher"]
    MATCH --> WAKE["wake newly matched owners"]
    WAKE --> PENDING

    INTENTS --> QUEUES[("intent queues")]
    QUEUES --> HANDLER["registered intent handler"]
    HANDLER --> HANDLER_OUT

    ROWS --> STORE[("read models and planning rows")]
    TIME --> STORE
```

## 2) Context As The Cross-Scope Interface

Cross-scope proof usually travels through context, not direct row reads.
Projectors publish role-scoped ranges; later projectors consume matched payload
facts through `ProjectionContext` and still validate them locally. This diagram
shows context as a proof surface; fact emission from bootstrap and frame opening
is shown in the connection flow below.

```mermaid
flowchart LR
    subgraph OFFERS["Context offers"]
      AUTH_WS["auth_workspace"]
      AUTH_SIGNER["content_signer"]
      AUTH_ADMIN["auth_admin"]
      AUTH_ENDPOINT["auth_local_endpoint"]
      INVITE_SECRET["connection_invite_secret"]
      RECIPIENT["recipient_key"]
      COVERAGE["secret_coverage"]
      CONN_REQUEST["connection_request"]
      CONN["connection"]
    end

    CONTEXT[("core context matcher")]

    subgraph NEEDS["Projector needs"]
      MSG_NEEDS["message needs signer + key coverage"]
      FILE_NEEDS["file/slice needs message + key coverage"]
      DELETE_NEEDS["deletion needs target + admin proof"]
      REQUEST_NEEDS["request needs invite secret"]
      CONNECTION_NEEDS["connection needs request + invite proof"]
    end

    subgraph OUTPUTS["Validated outputs"]
      OPENED["opened content rows"]
      CONTENT_CONTEXT["content context offers"]
      CONNECTION_ROWS["connection rows and context"]
    end

    AUTH_WS --> CONTEXT
    AUTH_SIGNER --> CONTEXT
    AUTH_ADMIN --> CONTEXT
    AUTH_ENDPOINT --> CONTEXT
    INVITE_SECRET --> CONTEXT
    RECIPIENT --> CONTEXT
    COVERAGE --> CONTEXT
    CONN_REQUEST --> CONTEXT
    CONN --> CONTEXT

    CONTEXT --> MSG_NEEDS
    CONTEXT --> FILE_NEEDS
    CONTEXT --> DELETE_NEEDS
    CONTEXT --> REQUEST_NEEDS
    CONTEXT --> CONNECTION_NEEDS

    MSG_NEEDS --> OPENED
    MSG_NEEDS --> CONTENT_CONTEXT
    FILE_NEEDS --> OPENED
    DELETE_NEEDS --> OPENED
    REQUEST_NEEDS --> CONNECTION_ROWS
    CONNECTION_NEEDS --> CONNECTION_ROWS
```

## 3) Connection Bootstrap And Established Frames

Connection owns sealed transport. Request and connection facts are their own
sealed wire bytes. Established frames carry ordinary fact bytes; once opened,
child facts return to core admission and their owning scope validates meaning.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 340}} }%%
flowchart TD
    REMOTE_REQ["remote sealed request bytes"] --> RECEIVE["receive_network_frame"]
    RECEIVE --> REQ["request fact"]
    RECEIVE --> OBS1["frame_observation for request"]
    REQ --> CREATE_RESP["create_connection"]
    OBS1 --> REQ
    CREATE_RESP --> RESP_SECRET["responder ephemeral_secret"]
    CREATE_RESP --> RESP_OUT["sealed connection fact"]
    RESP_OUT --> RESP_PROJECT_A["connection projector"]
    RESP_PROJECT_A --> CONNECTION_A["connection row and context"]
    RESP_PROJECT_A --> QUEUE_RESP["queue_outgoing_frame"]
    QUEUE_RESP --> RESP_BYTES["sealed connection bytes"]
    RESP_BYTES --> PEER["remote node"]

    PEER --> REMOTE_RESP["remote sealed response bytes"]
    REMOTE_RESP --> RECEIVE
    RECEIVE --> RESP_LOCAL["connection fact"]
    RECEIVE --> OBS2["frame_observation for response"]
    RESP_LOCAL --> RESP_PROJECT_B["connection projector"]
    OBS2 --> RESP_PROJECT_B
    RESP_PROJECT_B --> CONNECTION_B["connection row and context"]
    RESP_PROJECT_B --> SEED["seed_connection_sync"]

    subgraph ESTABLISHED["Established connection"]
      SYNC_IDS["sync-selected fact ids"] --> SEND_IDS["send_facts_on_connection"]
      CONNECTION_B --> SEND_IDS
      FACT_STORE[("fact store payload bytes")] --> SEND_IDS
      SEND_IDS --> FRAME_OUT["frame_small or frame_file_slice"]
      FRAME_OUT --> NETWORK["network_outgoing"]
      NETWORK --> PEER
      PEER --> FRAME_IN_BYTES["sealed established frame bytes"]
      FRAME_IN_BYTES --> RECEIVE
      RECEIVE --> OBS["frame_observation"]
      RECEIVE --> FRAME_IN["frame_small or frame_file_slice"]
      OBS --> FRAME_IN
      CONNECTION_B --> FRAME_IN
      FRAME_IN --> CHILD["child facts"]
      FRAME_IN --> REC_CHILD["connection_fact_receipt per child"]
    end

    CHILD --> CORE["ordinary core admission"]
    REC_CHILD --> CORE
```

## 4) Sync Seed, Live Tail, And Catch-Up

Sync plans replication over connection rows. A received connection becomes live
only after its projector validates request, authority, observation,
and ephemeral-secret context. That projection writes the live connection row and
emits `seed_connection_sync`. That seed creates the first compare. Later share
contributions live-tail to established authorized connections. Periodic daemon
ticks drain queued compare, have, need, send, and time-wake work when catch-up
remains.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 340}} }%%
flowchart TD
    BOOT_RESP["connection opens sealed bytes"] --> RESP_FACT["connection fact"]
    RESPONDER["create_connection handler"] --> RESP_FACT
    RESPONDER --> RESP_SECRET["responder ephemeral_secret"]
    REQUEST_CTX["connection_request context"] --> RESP_PROJECTOR["connection projector"]
    INVITE_CTX["connection_invite_secret context"] --> RESP_PROJECTOR
    OBS_CTX["frame_observation context"] --> RESP_PROJECTOR
    EPHEMERAL_CTX["connection_ephemeral_secret context"] --> RESP_PROJECTOR
    RESP_FACT --> RESP_PROJECTOR
    RESP_PROJECTOR --> CONNECTION_ROWS["connection rows"]
    RESP_PROJECTOR --> SEED["seed_connection_sync"]
    SEED --> ROOT_COMPARE["root compare fact"]
    ROOT_COMPARE --> SEND_COMPARE["send_facts_on_connection"]
    SEND_COMPARE --> PEER["remote node"]

    PEER --> PEER_COMPARE["received compare"]
    PEER_COMPARE --> COMPARE_HANDLER["send_sync_compare_response"]
    COMPARE_HANDLER --> CHILD_COMPARE["child compare facts"]
    COMPARE_HANDLER --> HAVE["have_id facts"]
    COMPARE_HANDLER --> SELECT["selected fact ids"]
    SELECT --> EXPAND["expand context_have recursively"]
    EXPAND --> SEND_BYTES["send owner bytes plus authorized dependencies"]
    SEND_BYTES --> PEER

    HAVE --> PEER_NEED["peer sends need_id if missing"]
    PEER_NEED --> SEND_REQUESTED["send_requested_fact"]
    SEND_REQUESTED --> EXPAND

    OWNER_PROJECTOR["auth/content/sync projector"] --> SHARE["share_fact_with_sync"]
    SHARE --> INDEX["shareable rows, leaves, context_have, summaries"]
    SHARE --> LIVE["live-tail advertisement"]
    LIVE --> ORIGIN_FILTER["skip origin connection receipts"]
    ORIGIN_FILTER --> EXPAND

    TICK["daemon tick catch-up"] --> QUEUED["queued intents and due time wakes"]
    QUEUED --> COMPARE_HANDLER
    QUEUED --> SEND_REQUESTED
    QUEUED --> SEND_COMPARE
```

## 5) Responsibility Summary

```mermaid
flowchart TD
    FACTS["facts are immutable protocol statements"] --> PROJECTORS["projectors validate meaning"]
    PROJECTORS --> CONTEXT["context offers and needs express relationships"]
    CONTEXT --> CORE_MATCH["core matches ranges and wakes owners"]
    PROJECTORS --> ROWS["scope-owned rows materialize local state"]
    PROJECTORS --> INTENTS["intents name bounded stateful work"]
    INTENTS --> HANDLERS["handlers perform retryable effects"]
    HANDLERS --> FACTS

    CONNECTION["connection carries bytes"] --> FACTS
    SYNC["sync chooses ids and dependency closure"] --> CONNECTION
    AUTH["auth proves authority and key access"] --> PROJECTORS
    CONTENT["content proves user-visible data and purge"] --> PROJECTORS
```
