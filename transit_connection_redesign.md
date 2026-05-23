# Connection Frame Receive Model

Network receive is a fact-pipeline boundary. The receive handler classifies
inbound bytes by the public tag/header and emits the fact type that the pipeline
should see:

- `connection_request`: durable global fact
- `connection_response`: durable local fact
- `connection_frame_small`: ephemeral local fact
- `connection_frame_large`: ephemeral local fact

There is no generic incoming wrapper fact. Bootstrap request and response bytes
are already semantic connection protocol messages, so they enter durable fact
projection directly. Established-connection frames are encrypted carriers, so
they enter the pipeline as ephemeral facts whose projector may use durable
connection context to open them.

## Core Shape

Durable facts live in `facts`, have local admission metadata, and enter
`pending_projection`. Their projector output replaces the fact owner's standing
context and time wakes. A durable fact with unresolved needs is parked by
committing those needs; later matching offers wake it by inserting a new pending
projection row.

Ephemeral facts live in the temp `ephemeral_projection_inputs` table. They use
the same `Fact` container for id, scope, timestamp, and bytes, but the bytes do
not enter durable `facts` or `local_fact_admissions`. Projection drains durable
pending facts first, then ephemeral facts.

Ephemeral facts may read durable context and may emit one-shot needs during the
projection fixed point so core can match existing durable offers and rerun the
projector before commit. Those needs are never stored. If the final ephemeral
output still has needs and no effects, core deletes the ephemeral input and
commits no context. If the final output has effects, it must have no unresolved
needs.

Ephemeral facts cannot emit durable offers or time wakes. Durable context must
not point at an owner whose payload disappears on restart.

## Receive Classification

`connection::receive_network_frame` owns intent payload decoding and origin
normalization. It does not construct facts inline. It delegates the mechanical
classification to `connection::frame::create`:

1. If the first byte is `connection_request`, decode the request payload,
   create the durable global request fact, and create durable
   `connection::fact_receipt` receipt data.
2. If the first byte is `connection_response`, decode the response payload,
   create the durable local response fact, and create durable response receipt
   data.
3. Otherwise, decode the public connection-frame header. A valid small header
   emits a local ephemeral `connection_frame_small` fact; a valid large header
   emits a local ephemeral `connection_frame_large` fact.
4. Malformed, unsupported, or unclassifiable bytes complete with no effects.

The receive handler is therefore close to the networking layer, but it only uses
public wire shape. Semantic validation remains in projectors.

## Projection

`connection_request` owns bootstrap request validity. Received requests require
the invite secret, the addressed local endpoint, and a connection-request fact
receipt. This keeps the durable request path safe even though receive
classification admitted the raw request bytes before semantic validation.

`connection_response` owns bootstrap response validity. Received responses
require request, invite, initiator ephemeral-secret, and connection-response
fact-receipt context before they materialize a local connection.

`connection::frame` owns established-connection frame projection.
Its projector accepts only local ephemeral small/large frame facts, reads the
connection id from the public header, and needs the exact local
`connection_response` fact for that connection. If that context is not already
available, the one-shot ephemeral need fails and the input is dropped. If the
context is present, the projector opens the frame and emits durable child facts
plus durable fact receipts.

## Child Facts

Projectors may emit durable child facts with `ProjectionOutput::fact`. Emitted
facts are semantic graph material, not temporary work.

Projection commits child facts immediately inside the same transaction:

1. Insert the child fact durably and mark it pending.
2. Run the child's projector in the same projection closure.
3. If the child materializes, commit its rows, offers, wakes, and effects.
4. If the child is valid but lacks durable context, commit the child fact and
   its standing needs; this is a successful projection decision.
5. If the child projector fails, roll back the whole parent projection.

Duplicate child facts are idempotent: if the fact already exists, the immediate
child projection path skips it.

## Ownership Boundaries

Core owns queue lifetime, projection fixed points, transactional child
projection, durable fact storage, and validation that ephemeral owners do not
publish durable standing context.

`connection::receive_network_frame` owns network receive intent decoding and
delegates fact creation to protocol modules.

`connection::frame` owns encrypted frame fact layout, fixed frame
layout, sendability checks, frame opening, and established-connection frame
projection.

`connection::fact_receipt` owns durable local fact receipt. It records
that a semantic fact was observed from an origin through a connection request,
connection response, or connection frame. It does not open frames; it publishes
fact-receipt context that
semantic projectors validate.

`connection`, `identity`, `encryption`, `content`, and `sync` fact families own
the semantic validity of their own facts. Connection-frame projection only
decides whether encrypted carrier bytes can be opened into durable child fact
candidates and receipts.

## Coverage

Core tests cover ephemeral projection, one-shot durable context use, discard
without standing needs, rejection of ephemeral offers, immediate child
projection, child parking as success, and rollback on child projection failure.

Connection tests cover receive-handler classification, durable bootstrap
request admission, connection-frame opening, origin normalization, sync control
payload admission, large-frame parking before ciphertext materialization, and
discard of malformed raw network bytes.
