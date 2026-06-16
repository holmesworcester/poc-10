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
    RUNTIME --> WORKERS["core runtime workers"]
    WORKERS --> STORE[("SQLite facts, context, rows, queues, time wakes")]
    STORE --> WORKERS

    subgraph SCOPES["Protocol scopes"]
      AUTH["auth facts, keys, authority"]
      CONTENT["content facts, opened rows, purge"]
      CONNECTION["connection facts, frames, receipts"]
      SYNC["sync facts, range summaries, visibility"]
    end

    WORKERS --> AUTH
    WORKERS --> CONTENT
    WORKERS --> CONNECTION
    WORKERS --> SYNC
    AUTH --> WORKERS
    CONTENT --> WORKERS
    CONNECTION --> WORKERS
    SYNC --> WORKERS

    CONNECTION --> NET_OUT["network_outgoing opaque bytes"]
    NET_OUT --> PEER["remote node"]
    PEER --> NET_IN
```

## 1) Fact Admission And Context Matching

Facts enter from commands, inbound network intake, opened frames, and handlers.
Core commits command-authored facts and `RuntimeEffects::facts` as retained
`facts` with `pending_projection` rows. Core stages
`RuntimeEffects::incoming_facts` in the temporary `incoming_facts` queue; the
runtime drains those rows straight into the owning projector, and projector
output decides whether core retains the incoming fact or deletes it. Projection
emits the complete standing needs and offers for the fact being projected.
Context is a range relationship: an offer can satisfy many needs, and an offer
may exist before a later fact creates the matching need.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 320}} }%%
flowchart TD
    CMD["AuthoredCommand facts"] --> DURABLE_IN["durable fact commit"]
    INTAKE["inbound network intake RuntimeEffects"] --> EFFECTS["RuntimeEffects"]
    OPENED["opened child facts and receipts"] --> EFFECTS
    HANDLER_OUT["handler RuntimeEffects"] --> EFFECTS

    EFFECTS --> DURABLE_IN
    EFFECTS --> INCOMING_STAGE["stage incoming fact"]
    DURABLE_IN --> FACTS[("facts")]
    DURABLE_IN --> PENDING[("pending_projection retained queue")]
    INCOMING_STAGE --> INCOMING[("incoming_facts temporary queue")]

    PENDING --> LOAD["load retained fact plus matched context"]
    INCOMING --> INCOMING_READY["incoming ready scan"]
    INCOMING_READY --> LOAD_INCOMING["load incoming fact plus matched context"]
    LOAD_INCOMING --> PROJECTOR
    LOAD --> PROJECTOR["owning projector"]
    PROJECTOR --> NEEDS["context needs"]
    PROJECTOR --> OFFERS["context offers"]
    PROJECTOR --> ROWS["scope-owned rows"]
    PROJECTOR --> INTENTS["durable or local intents"]
    PROJECTOR --> TIME["time wakes"]
    PROJECTOR --> INCOMING_DECISION["incoming projector output"]
    INCOMING_DECISION --> RETAIN["retain incoming fact"]
    INCOMING_DECISION --> DROP["delete incoming_facts row"]

    NEEDS --> CONTEXT[("context rows")]
    OFFERS --> CONTEXT
    CONTEXT --> MATCH["range-overlap matcher"]
    MATCH --> WAKE["wake newly matched owners"]
    WAKE --> PENDING
    WAKE --> INCOMING_READY

    INTENTS --> QUEUES[("intent queues")]
    QUEUES --> HANDLER["registered intent handler"]
    HANDLER --> HANDLER_OUT

    ROWS --> STORE[("read models and planning rows")]
    RETAIN --> FACTS
    TIME --> TIME_ROWS[("time_wakes")]
    TIME_ROWS --> DUE["daemon admits due ranges"]
    DUE --> PENDING
```

The lifecycle diagram above is the context diagram: it shows projectors
declaring needs and offers, core matching ranges, and matches waking later
projection work. The concrete role catalog belongs beside the projector docs
that own those roles, not in a second architecture graph.

## 2) Connection Bootstrap And Established Frames

Connection owns sealed transport. Request and connection facts are their own
sealed wire bytes. The daemon converts accepted TCP bytes through
`receive_network_frame` intake effects, which stage typed incoming facts plus
`frame_observation`. Request sends are live operational work from
`maintain_connections`; response sends are emitted by the connection projector
after the connection fact commits. Established frames carry ordinary fact bytes;
once opened, child facts return to core admission and their owning scope
validates meaning.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 340}} }%%
flowchart TD
    REQUEST_CMD["request command or accepted invite row"] --> LOCAL_REQ["ephemeral_secret plus sealed request fact"]
    LOCAL_REQ --> REQUEST_PROJECTOR["request projector"]
    REQUEST_PROJECTOR --> REQUEST_ROW["retryable request row"]
    REQUEST_ROW --> MAINTAIN["maintain_connections recurring intent"]
    MAINTAIN --> SEND_REQ["network_outgoing sealed request"]
    SEND_REQ --> PEER["remote node"]

    PEER --> REMOTE_REQ["remote sealed request bytes"]
    REMOTE_REQ --> RECEIVE["receive_network_frame intake effects"]
    RECEIVE --> REQ["incoming request fact"]
    RECEIVE --> OBS1["frame_observation for request"]
    REQ --> REQ_PROJECTOR["request projector"]
    OBS1 --> REQ_PROJECTOR
    REQ_PROJECTOR --> REQ_RECEIPT["connection_fact_receipt for request"]
    REQ_PROJECTOR --> CREATE_RESP["create_connection"]
    CREATE_RESP --> RESP_SECRET["responder ephemeral_secret"]
    CREATE_RESP --> RESP_OUT["sealed connection fact"]
    RESP_OUT --> RESP_PROJECT_A["connection projector"]
    RESP_PROJECT_A --> CONNECTION_A["connection row and context"]
    RESP_PROJECT_A --> QUEUE_RESP["queue_outgoing_frame"]
    RESP_PROJECT_A --> SEED_A["seed_connection_sync"]
    QUEUE_RESP --> RESP_BYTES["network_outgoing sealed connection"]
    RESP_BYTES --> PEER

    PEER --> REMOTE_RESP["remote sealed response bytes"]
    REMOTE_RESP --> RECEIVE
    RECEIVE --> RESP_LOCAL["incoming connection fact"]
    RECEIVE --> OBS2["frame_observation for response"]
    RESP_LOCAL --> RESP_PROJECT_B["connection projector"]
    OBS2 --> RESP_PROJECT_B
    RESP_PROJECT_B --> CONNECTION_B["connection row and context"]
    RESP_PROJECT_B --> RESP_RECEIPT["connection_fact_receipt for response"]
    RESP_PROJECT_B --> SEED_B["seed_connection_sync"]

    subgraph ESTABLISHED["Established connection"]
      SYNC_IDS["sync-selected fact ids"] --> SEND_IDS["send_facts_on_connection"]
      CONNECTION_B --> SEND_IDS
      FACT_STORE[("fact store payload bytes")] --> SEND_IDS
      SEND_IDS --> FRAME_OUT["frame_small, frame_file_slice, or frame_bundle"]
      FRAME_OUT --> NETWORK["network_outgoing"]
      NETWORK --> PEER
      PEER --> FRAME_IN_BYTES["sealed established frame bytes"]
      FRAME_IN_BYTES --> RECEIVE
      RECEIVE --> OBS["frame_observation"]
      RECEIVE --> FRAME_IN["incoming frame fact"]
      OBS --> FRAME_PROJECTOR["frame projector"]
      CONNECTION_B --> FRAME_PROJECTOR
      FRAME_IN --> FRAME_PROJECTOR
      FRAME_PROJECTOR --> PARK["retain with needs until context appears"]
      FRAME_PROJECTOR --> CHILD["child facts"]
      FRAME_PROJECTOR --> REC_CHILD["connection_fact_receipt per child"]
    end

    CHILD --> CORE["ordinary core admission"]
    REC_CHILD --> CORE
```

## 3) Sync Seed, Live Tail, And Catch-Up

Sync plans replication over connection rows. A connection becomes live only
after its projector validates request, authority, observation, and
ephemeral-secret context. That projection writes the live connection row and
emits `seed_connection_sync`. The seed and live-only recurring `maintain_sync`
path create compares over the active local sync-setting range. Later share
contributions live-tail to established authorized connections. Periodic daemon
ticks drain recurring intents, queued compare, have, need, fact-send, and
replayable time-wake work when catch-up remains.

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
    CONNECTION_ROWS --> MAINTAIN_SYNC["maintain_sync recurring intent"]
    SETTING["active sync-setting range"] --> RANGE_COMPARE["compare fact"]
    SEED --> RANGE_COMPARE
    MAINTAIN_SYNC --> RANGE_COMPARE
    RANGE_COMPARE --> SEND_COMPARE["send_facts_on_connection"]
    SEND_COMPARE --> PEER["remote node"]

    PEER --> PEER_COMPARE["received compare"]
    PEER_COMPARE --> COMPARE_HANDLER["send_sync_compare_response"]
    COMPARE_HANDLER --> CHILD_COMPARE["child compare facts"]
    COMPARE_HANDLER --> HAVE["have_id facts"]
    COMPARE_HANDLER --> SELECT["selected fact ids"]
    CHILD_COMPARE --> SEND_COMPARE
    HAVE --> SEND_HAVE["send_facts_on_connection have_id"]
    SEND_HAVE --> PEER
    SELECT --> EXPAND["expand context_have recursively"]
    EXPAND --> SEND_BYTES["send owner bytes plus authorized dependencies"]
    SEND_BYTES --> PEER

    PEER --> PEER_HAVE["received have_id"]
    PEER_HAVE --> NEED_HANDLER["send_needed_fact_id"]
    NEED_HANDLER --> NEED_FACT["need_id fact if missing"]
    NEED_FACT --> SEND_NEED["send_facts_on_connection"]
    SEND_NEED --> PEER
    PEER --> PEER_NEED["received need_id"]
    PEER_NEED --> SEND_REQUESTED["send_requested_fact"]
    SEND_REQUESTED --> EXPAND

    OWNER_PROJECTOR["auth/content/sync projector"] --> SHARE["share_fact_with_sync"]
    SHARE --> INDEX["shareable rows, leaves, context_have, summaries"]
    SHARE --> LIVE["live-tail advertisement"]
    LIVE --> ORIGIN_FILTER["skip origin connection receipts"]
    ORIGIN_FILTER --> EXPAND

    TICK["daemon tick catch-up"] --> QUEUED["recurring intents, queued intents, and due time wakes"]
    QUEUED --> COMPARE_HANDLER
    QUEUED --> SEND_REQUESTED
    QUEUED --> SEND_COMPARE
```

## 4) Responsibility Summary

```mermaid
flowchart TD
    FACTS["facts are immutable protocol statements"] --> PROJECTORS["projectors validate meaning"]
    PROJECTORS --> CONTEXT["context offers and needs express relationships"]
    CONTEXT --> CORE_MATCH["core matches ranges and wakes owners"]
    PROJECTORS --> ROWS["scope-owned rows materialize local state"]
    PROJECTORS --> INTENTS["intents name bounded stateful work"]
    INTENTS --> HANDLERS["handlers perform retryable effects"]
    HANDLERS --> EFFECTS["RuntimeEffects"]
    EFFECTS --> FACTS
    EFFECTS --> INCOMING

    COMMANDS["commands author facts only"] --> FACTS
    INTAKE["network intake stages incoming typed facts"] --> INCOMING["incoming_facts temp queue"]
    INCOMING --> PROJECTORS
    PROJECTORS --> RETAIN_INCOMING["incoming retention decision"]
    RETAIN_INCOMING --> FACTS
    REPLAY["replay drains retained facts and replayable time wakes"] --> PROJECTORS
    RECURRING["live recurring intents run operational loops"] --> HANDLERS
    CONNECTION["connection carries bytes"] --> INTAKE
    SYNC["sync chooses ids and dependency closure"] --> CONNECTION
    AUTH["auth proves authority and key access"] --> PROJECTORS
    CONTENT["content proves user-visible data and purge"] --> PROJECTORS
```
