# Transit Projection Model

Transit receive is a projection problem, not a durable raw-frame storage
problem. Raw inbound transit bytes are operational carrier material; opened
connection protocol messages, inner payload facts, and receive provenance are
semantic facts. Core therefore supports projectable inputs with two lifetimes:
durable facts and ephemeral inputs.

## Core Shape

Durable facts live in `facts`, have local admission metadata, and enter
`pending_projection`. Their projector output replaces the fact owner's standing
context and time wakes. A durable fact with unresolved needs is parked by
committing those needs; later matching offers wake it by inserting a new pending
projection row.

Ephemeral inputs live in the temp `ephemeral_projection_inputs` table. They use
the same `Fact` container for id, scope, timestamp, and bytes, but the bytes do
not enter durable `facts` or `local_fact_admissions`. Projection drains durable
pending facts first, then ephemeral inputs.

Ephemeral inputs may read durable context. They may emit one-shot needs during
the projection fixed point so core can match existing durable offers and rerun
the projector before commit. Those needs are never stored. If the final
ephemeral output still has needs and no effects, core deletes the ephemeral
input and commits no context. If the final output has effects, it must have no
unresolved needs.

Ephemeral inputs cannot emit durable offers or time wakes. Durable context must
not point at an owner whose payload disappears on restart.

## Child Facts

Projectors may emit durable child facts with `ProjectionOutput::fact`. That is
the convention boundary: emitted facts are semantic graph material, not
temporary work.

Projection commits child facts immediately inside the same transaction:

1. Insert the child fact durably and mark it pending.
2. Run the child's projector in the same projection closure.
3. If the child materializes, commit its rows, offers, wakes, and effects.
4. If the child is valid but lacks durable context, commit the child fact and
   its standing needs; this is a successful projection decision.
5. If the child projector fails, roll back the whole parent projection.

Duplicate child facts are idempotent: if the fact already exists, the immediate
child projection path skips it.

## Transit Input

`transport::transit` is a transient fact family. Its `TransitInputFact` carries
canonical origin bytes, local receive time, and raw inbound frame bytes. The
receive handler decodes the network intent and emits this input as an ephemeral
projection input through `PipelineEffects::ephemeral_fact`.

The transit projector owns frame classification and opening:

- Bootstrap request frames need existing `connection_invite_secret` context and
  `identity_local_endpoint` context.
- Bootstrap response frames need no pre-open context.
- Encrypted connection frames need existing `connection_response` context keyed
  by the connection id in the public frame header.

Missing context is a one-shot need. Core checks for matching durable offers
during the same projection attempt. If the needed context is not already
available, the transit input is consumed with no durable rows and no standing
needs. The sender can retry, or later sync can provide the semantic facts by
another route.

Malformed, unsupported, or undecryptable transit frames complete with no
effects. They do not poison the temp projection queue. Context-invariant
violations, such as a matched offer whose payload does not match its advertised
role, remain projection errors.

## Durable Outputs

Opened transit frames emit durable semantic child facts:

- A valid bootstrap request emits a global `connection_request` fact and local
  `transport::transit_received` provenance.
- A valid bootstrap response emits a local `connection_response` fact and local
  receive provenance.
- A valid encrypted connection frame emits each admitted inner fact plus local
  receive provenance for that inner fact.

`transport::transit_received` remains a durable local fact family. It records
that a semantic fact was observed from an origin under bootstrap or connection
context. It does not open frames; it publishes receive-provenance context that
other semantic projectors validate.

Bootstrap attempts are not facts. Bootstrap request and response messages are
facts because they are semantic connection protocol state. Ongoing transit
frames are not facts; their opened inner payloads are facts.

## Ownership Boundaries

Core owns queue lifetime, projection fixed points, transactional child
projection, durable fact storage, and validation that ephemeral owners do not
publish durable standing context.

`transport::receive_transit_frame` owns only intent payload decoding and staging
the ephemeral transit input.

`transport::transit` owns transit input layout, frame layout, sendability checks,
frame opening, and the transit projector's one-shot admission policy.

`connection`, `identity`, `encryption`, `content`, and `sync` fact families own
the semantic validity of their own facts after transit emits them. A transit
projector does not substitute for those projectors; it only decides whether raw
carrier bytes can be turned into durable child fact candidates and provenance.

## Coverage

Core tests cover ephemeral input projection, one-shot durable context use,
discard without standing needs, rejection of ephemeral offers, immediate child
projection, child parking as success, and rollback on child projection failure.

Transit tests cover receive-handler staging, bootstrap request projection,
connection-frame opening, origin normalization, sync control payload admission,
large-frame parking before ciphertext materialization, and discard of malformed
raw frames.
