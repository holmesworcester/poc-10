# Architecture Diagrams

These are GitHub-renderable Mermaid flowcharts for the current Context
architecture. They are a visual companion to `README.md`, `docs/RULES.md`, and
the scope READMEs; the Rust modules remain the source of truth.

Primary source modules:

- `src/core/*`
- `src/core/pipeline/*`
- `src/protocol/registry.rs`
- `src/protocol/auth/*`
- `src/protocol/content/*`
- `src/protocol/connection/*`
- `src/protocol/sync/*`

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

    CONNECTION --> NET_OUT["network_out opaque bytes"]
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
facts through `ProjectionContext` and still validate them locally.

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
      CONN_RESPONSE["connection_response"]
    end

    CONTEXT[("core context matcher")]

    subgraph NEEDS["Projector needs"]
      MSG_NEEDS["message needs signer + key coverage"]
      FILE_NEEDS["file/slice needs message + key coverage"]
      DELETE_NEEDS["deletion needs target + admin proof"]
      BOOT_NEEDS["bootstrap needs local endpoint"]
      REQUEST_NEEDS["request needs invite secret"]
      RESPONSE_NEEDS["response needs request + invite proof"]
      FRAME_NEEDS["frame needs connection response"]
    end

    subgraph OUTPUTS["Validated outputs"]
      OPENED["opened content rows"]
      CONNECTION_ROWS["connection rows"]
      CHILD_FACTS["opened child facts"]
    end

    AUTH_WS --> CONTEXT
    AUTH_SIGNER --> CONTEXT
    AUTH_ADMIN --> CONTEXT
    AUTH_ENDPOINT --> CONTEXT
    INVITE_SECRET --> CONTEXT
    RECIPIENT --> CONTEXT
    COVERAGE --> CONTEXT
    CONN_REQUEST --> CONTEXT
    CONN_RESPONSE --> CONTEXT

    CONTEXT --> MSG_NEEDS
    CONTEXT --> FILE_NEEDS
    CONTEXT --> DELETE_NEEDS
    CONTEXT --> BOOT_NEEDS
    CONTEXT --> REQUEST_NEEDS
    CONTEXT --> RESPONSE_NEEDS
    CONTEXT --> FRAME_NEEDS

    MSG_NEEDS --> OPENED
    FILE_NEEDS --> OPENED
    DELETE_NEEDS --> OPENED
    BOOT_NEEDS --> CHILD_FACTS
    REQUEST_NEEDS --> CONNECTION_ROWS
    RESPONSE_NEEDS --> CONNECTION_ROWS
    FRAME_NEEDS --> CHILD_FACTS
```

## 3) Connection Bootstrap And Established Frames

Connection owns sealed transport. Bootstrap wrappers are local receive facts
that preserve sealed bytes until projection can open them with local endpoint
context. Established frames carry ordinary fact bytes; once opened, child facts
return to core admission and their owning scope validates meaning.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 340}} }%%
flowchart TD
    REMOTE_REQ["remote sealed request bytes"] --> RECEIVE["receive_network_frame"]
    RECEIVE --> BOOT_REQ["bootstrap_request"]
    BOOT_REQ --> REQ["request"]
    BOOT_REQ --> REC1["fact_receipt for request"]
    REQ --> CREATE_RESP["create_connection_response"]
    REC1 --> CREATE_RESP
    CREATE_RESP --> RESP_SECRET["responder ephemeral_secret"]
    CREATE_RESP --> RESP["response"]
    CREATE_RESP --> BOOT_RESP_OUT["sealed bootstrap_response bytes"]
    BOOT_RESP_OUT --> PEER["remote node"]

    PEER --> REMOTE_RESP["remote sealed response bytes"]
    REMOTE_RESP --> RECEIVE
    RECEIVE --> BOOT_RESP["bootstrap_response"]
    BOOT_RESP --> RESP_LOCAL["response"]
    BOOT_RESP --> REC2["fact_receipt for response"]
    RESP_LOCAL --> SEED["seed_connection_sync"]

    subgraph ESTABLISHED["Established connection"]
      SYNC_IDS["sync-selected fact ids"] --> SEND_IDS["send_facts_on_connection"]
      RESP_LOCAL --> SEND_IDS
      FACT_STORE[("fact store payload bytes")] --> SEND_IDS
      SEND_IDS --> FRAME_OUT["frame_small or frame_file_slice"]
      FRAME_OUT --> NETWORK["send_network_frame"]
      NETWORK --> PEER
      PEER --> FRAME_IN_BYTES["sealed established frame bytes"]
      FRAME_IN_BYTES --> RECEIVE
      RECEIVE --> OBS["frame_observation"]
      RECEIVE --> FRAME_IN["frame_small or frame_file_slice"]
      OBS --> FRAME_IN
      RESP_LOCAL --> FRAME_IN
      FRAME_IN --> CHILD["child facts"]
      FRAME_IN --> REC_CHILD["connection_fact_receipt per child"]
    end

    CHILD --> CORE["ordinary core admission"]
    REC_CHILD --> CORE
```

## 4) Sync Seed, Live Tail, And Catch-Up

Sync plans replication over established connection facts. A connection response
becomes durable only after its projector validates request, invite, receipt,
and ephemeral-secret context. That projection emits `seed_connection_sync`,
which creates the first compare. Later share contributions live-tail to
established authorized connections. Periodic daemon ticks drain queued compare,
have, need, send, and time-wake work when catch-up remains.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 340}} }%%
flowchart TD
    BOOT_RESP["bootstrap_response opens sealed bytes"] --> RESP_FACT["response fact"]
    RESPONDER["create_connection_response handler"] --> RESP_FACT
    REQUEST_CTX["connection_request context"] --> RESP_PROJECTOR["response projector"]
    INVITE_CTX["connection_invite_secret context"] --> RESP_PROJECTOR
    RECEIPT_CTX["connection_fact_receipt context"] --> RESP_PROJECTOR
    EPHEMERAL_CTX["connection_ephemeral_secret context"] --> RESP_PROJECTOR
    RESP_FACT --> RESP_PROJECTOR
    RESP_PROJECTOR --> RESPONSE_ROWS["connection_response rows"]
    RESP_PROJECTOR --> RESPONSE_CTX["connection_response context"]
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

## 5) Range Sync Dependency Closure

Range sync makes a bounded user-visible slice useful without downloading the
whole workspace. Sync starts with the owner facts in the requested time range,
then follows projector-supplied `context_have` edges so the receiver can
project the selected facts quickly.

```mermaid
flowchart LR
    RANGE["requested time range"] --> OWNERS["owner facts in range"]

    OWNERS --> MSG["message_hello"]
    MSG --> AUTH_CTX["signer authority"]
    MSG --> KEY_CTX["key wrap or retained key node"]
    MSG --> RETENTION_CTX["retention policy"]

    AUTH_CTX --> AUTH_PARENT["workspace user admin chain"]
    KEY_CTX --> RECIPIENT["recipient_key"]
    KEY_CTX --> FRONTIER["removal_frontier"]
    RETENTION_CTX --> POLICY_PARENT["policy authority"]

    OWNERS --> SEND_SET["send set"]
    AUTH_CTX --> SEND_SET
    KEY_CTX --> SEND_SET
    RETENTION_CTX --> SEND_SET
    AUTH_PARENT --> SEND_SET
    RECIPIENT --> SEND_SET
    FRONTIER --> SEND_SET
    POLICY_PARENT --> SEND_SET

    SEND_SET --> CONNECTION_FILTER["connection visibility filter"]
    CONNECTION_FILTER --> FRAME["sealed connection frames"]
    FRAME --> RECEIVER["receiver admits facts normally"]
    RECEIVER --> PROJECT["projectors materialize visible slice"]
```

## 6) Example Workspace Fact Graph

This graph shows a realistic interrelated set of shared facts and local-only
facts. Shared facts can be replicated. Local facts provide private capabilities
for this store and must not leave through connection frames.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 340}} }%%
flowchart LR
    subgraph SHARED["Shared facts"]
      WS["workspace_acme"]
      ALICE["user_alice"]
      ADMIN["admin_alice"]
      BOB_INV["user_invite_bob"]
      BOB["user_bob"]
      BOB_EP["endpoint_shared_bob_laptop"]
      FRONTIER["removal_frontier_chat"]
      RECIP["recipient_key_bob_laptop"]
      WRAP["key_wrap_frontier_to_bob"]
      MSG["message_hello"]
      DEL["message_deletion_hello"]
    end

    subgraph LOCAL["Local facts"]
      LOCAL_EP["endpoint_secret_alice_phone"]
      SIGNER["local_signer_secret_alice"]
      ROOT["local_key_secret_frontier"]
      RECIP_PRIV["local_recipient_key_bob_laptop"]
    end

    WS --> ALICE
    ALICE --> ADMIN
    ADMIN --> BOB_INV
    BOB_INV --> BOB
    BOB --> BOB_EP
    WS --> FRONTIER
    BOB_EP --> RECIP
    FRONTIER --> WRAP
    RECIP --> WRAP
    ROOT --> WRAP

    ALICE --> MSG
    FRONTIER --> MSG
    WRAP --> MSG
    MSG --> DEL
    ADMIN --> DEL

    LOCAL_EP -. auth_local_endpoint .-> BOB_INV
    SIGNER -. local_signer_secret .-> MSG
    ROOT -. secret_coverage .-> MSG
    RECIP_PRIV -. unwrap_key_wrap .-> WRAP

    MSG --> SHARE_MSG["share_fact_with_sync message"]
    DEL --> SHARE_DEL["share_fact_with_sync deletion"]
    WRAP --> SHARE_WRAP["share_fact_with_sync key wrap"]
```

## 7) Responsibility Summary

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
