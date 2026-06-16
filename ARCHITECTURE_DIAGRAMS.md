# Architecture Diagrams

These are GitHub-renderable Mermaid flowcharts for the current Context
architecture. They are a visual companion to `README.md`, `docs/RULES.md`, and
the scope READMEs; the Rust modules remain the source of truth.

## 0) Runtime Boundaries

Context has one protocol-neutral runtime organized around serialized turns.
Core owns turn locking, queue draining, context matching, transaction
boundaries, time-wake admission, recurring schedule firing, and opaque network
bytes. Protocol code participates through runtime-facing hooks: command authors,
inbound intake, the projector router, the handler registry, and recurring intent
builders.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 320}} }%%
flowchart TD
    CLI["CLI command or query"] --> TURN["serialized runtime turn"]
    DAEMON["daemon loop"] --> TURN
    TURN --> RUNTIME["Runtime handle: store, projector, handler set"]

    RUNTIME <--> STORE[("runtime store and queues: facts, incoming_facts, context, time_wakes, intents, local_intents, rows")]

    subgraph HOOKS["runtime-facing protocol hooks"]
      COMMANDS["protocol command authors"]
      INTAKE["inbound intake hook"]
      PROJECTOR["projector router"]
      HANDLERS["handler registry"]
      RECURRING["recurring intent builders"]
    end

    RUNTIME --> COMMAND_PATH["command/query path"]
    COMMAND_PATH --> COMMANDS
    COMMANDS --> COMMAND_FACTS["authored facts"]
    COMMAND_FACTS --> COMMIT["atomic fact/effect commit"]
    COMMAND_PATH --> PREQUERY["query pre-settle: retained projection only"]
    PREQUERY --> PROJECTOR

    RUNTIME --> DAEMON_PATH["daemon tick path"]
    DAEMON_PATH --> FIRE["fire recurring local intents"]
    FIRE --> RECURRING
    RECURRING --> LOCAL_QUEUE["queue local_intents"]
    LOCAL_QUEUE --> STORE
    FIRE --> NET_IN["accept opaque TCP frames"]
    NET_IN --> INTAKE
    INTAKE --> COMMIT
    NET_IN --> TIME["admit due time wakes"]
    TIME --> STORE

    subgraph DRAIN["runtime queue drain order"]
      TIME --> PROJECTION_A["drain projection work"]
      STORE --> PROJECTION_A
      PROJECTION_A --> PROJECTOR
      PROJECTOR --> PROJECTION_OUT["ProjectionOutput and RuntimeEffects"]
      PROJECTION_OUT --> COMMIT
      PROJECTION_A --> DISPATCH["dispatch intent queues"]
      STORE --> DISPATCH
      DISPATCH --> HANDLERS
      HANDLERS --> HANDLER_OUT["handler RuntimeEffects"]
      HANDLER_OUT --> COMMIT
      DISPATCH --> PROJECTION_B["projection drain after handlers"]
      PROJECTION_B --> PROJECTOR
    end

    COMMIT --> STORE
    PROJECTION_B --> NET_OUT["pump network_outgoing"]
    STORE --> NET_OUT
    NET_OUT --> PEER["remote peer"]
    PEER --> NET_IN
```

## 1) Fact Admission And Context Matching

Facts enter through the shared effect commit path, then projection drains the
queues that commit created. Command output is normalized to
`RuntimeEffects::facts`; handlers, inbound intake, and projector follow-up work
already return `RuntimeEffects`. `commit_runtime_effects_in_tx` retains
`RuntimeEffects::facts` and queues retained projection work, but only stages
`RuntimeEffects::incoming_facts` in the temporary incoming queue. `drain_projection`
selects retained work first, then ready incoming work. The owning projector is
the decision point: `commit_projection_effects_in_tx` either clears retained
work, retains an incoming fact, or deletes the incoming row, then writes the
projector's declared context, time wakes, rows, intents, and follow-up effects.
In code, durable effect facts use `insert_fact_and_pending_with_mode_in_tx`,
incoming effect facts use `insert_incoming_fact_in_tx`, retained projection uses
`pending_durable_projection_items`, incoming projection uses
`incoming_pending_fact_ids`, and the incoming decision commits through
`move_incoming_to_retained_in_tx` or `delete_incoming_fact_in_tx`.
Context is a range relationship: an offer can satisfy many needs, and an offer
may exist before a later fact creates the matching need.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 320}} }%%
flowchart TD
    CMD["command-authored facts"] --> EFFECT_COMMIT["effect commit transaction"]
    INTAKE["inbound intake effects"] --> EFFECT_COMMIT
    HANDLER_OUT["handler effects"] --> EFFECT_COMMIT
    PROJECTOR_EFFECTS["projector follow-up effects"] --> EFFECT_COMMIT
    OPENED["opened frame child facts"] --> EFFECT_COMMIT

    EFFECT_COMMIT --> RETAINED[("retained facts: facts + local_fact_admissions")]
    EFFECT_COMMIT --> PENDING[("retained work queue: pending_projection")]
    EFFECT_COMMIT --> INCOMING[("incoming work queue: incoming_facts")]
    EFFECT_COMMIT --> ROWS[("scope-owned rows")]
    EFFECT_COMMIT --> INTENTS[("intent queues: intents + local_intents")]

    subgraph DRAIN["projection drain"]
      RETAINED --> RETAINED_ITEM["retained projection item"]
      PENDING --> RETAINED_ITEM
      MATCHES[("queued context matches")] --> RETAINED_ITEM
      DUE_RANGES[("queued due time ranges")] --> RETAINED_ITEM
      INCOMING --> INCOMING_ITEM["incoming projection item"]
      RETAINED_ITEM --> PROJECTOR["owning projector"]
      INCOMING_ITEM --> PROJECTOR
    end

    PROJECTOR --> OUTPUT["projection output: context, time, rows, intents, effects, incoming decision"]
    OUTPUT --> PROJECTION_COMMIT["projection commit transaction"]

    PROJECTION_COMMIT -->|durable source| CONSUMED["clear consumed retained work"]
    PROJECTION_COMMIT -->|retain incoming| RETAINED
    PROJECTION_COMMIT -->|drop incoming| DROP_INCOMING["delete dropped incoming row"]
    PROJECTION_COMMIT --> CONTEXT[("standing context: replacement needs + append-only offers")]
    PROJECTION_COMMIT --> TIME_ROWS[("time_wakes")]
    PROJECTION_COMMIT --> ROWS
    PROJECTION_COMMIT --> INTENTS
    PROJECTION_COMMIT --> PROJECTOR_EFFECTS

    CONTEXT --> MATCHER["range matcher"]
    MATCHER --> MATCHES
    MATCHES --> PENDING

    TIME_ROWS --> DUE["daemon due-time admission"]
    DUE --> DUE_RANGES
    DUE --> PENDING

    INTENTS --> HANDLER["intent dispatch"]
    HANDLER --> HANDLER_OUT
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
