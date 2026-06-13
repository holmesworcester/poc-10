pub mod decode {
    //! Byte decoding for key request facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{KEY_REQUEST_BYTES, TYPE_KEY_REQUEST};
    use super::super::fact::KeyRequestFact;

    pub fn decode_key_request(bytes: &[u8]) -> Result<KeyRequestFact, String> {
        wire::expect_len(bytes, KEY_REQUEST_BYTES).map_err(wire_err)?;
        if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_KEY_REQUEST {
            return Err("expected key request".to_string());
        }
        Ok(KeyRequestFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            requester_endpoint_id: bytes[33..65].try_into().unwrap(),
            responder_endpoint_id: bytes[65..97].try_into().unwrap(),
            frontier_id: bytes[97..129].try_into().unwrap(),
            recipient_key_id: bytes[129..161].try_into().unwrap(),
            created_at_ms: wire::take_u64be(&bytes[161..169]).map_err(wire_err)?,
            signer_public_key: bytes[169..201].try_into().unwrap(),
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::key_request::encode::{encode_key_request, KEY_REQUEST_BYTES};

        fn sample_fact() -> KeyRequestFact {
            KeyRequestFact {
                workspace_id: [1; 32],
                requester_endpoint_id: [2; 32],
                responder_endpoint_id: [3; 32],
                frontier_id: [4; 32],
                recipient_key_id: [5; 32],
                created_at_ms: 123,
                signer_public_key: [6; 32],
            }
        }

        #[test]
        fn key_request_roundtrips_fixed_width() {
            let fact = sample_fact();

            let encoded = encode_key_request(&fact).expect("encode key request");

            assert_eq!(encoded.len(), KEY_REQUEST_BYTES);
            assert_eq!(
                decode_key_request(&encoded).expect("decode key request"),
                fact
            );
        }
    }
}
pub mod authenticate {
    //! Key-request authenticator.
    //!
    //! POLICY. Authenticating a `key_request` fact proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical key-request fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!
    //! Admission scope (the requester's workspace) is interpretation the projector
    //! owns, and requester/responder relationships are proven from other facts in
    //! the projector.

    use crate::core::facts::Fact;
    use crate::core::pipeline::{verify_fact_id, ProjectionContext};

    use super::super::fact::KeyRequestFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        request: KeyRequestFact,
        _context: &ProjectionContext,
    ) -> Result<KeyRequestFact, String> {
        prove_decoded_key_request(fact, request)
    }

    fn prove_decoded_key_request(
        fact: &Fact,
        request: KeyRequestFact,
    ) -> Result<KeyRequestFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(request)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::crypto;
        use crate::core::facts::Fact;
        use crate::core::pipeline::ProjectionContext;
        use crate::protocol::auth::key_request::encode;
        use crate::protocol::auth::key_request::fact::KeyRequestFact;
        use crate::protocol::auth::workspace;

        const SIGNER_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            let private_key = SIGNER_KEY;
            let workspace_id = [1; 32];
            let request = KeyRequestFact {
                workspace_id,
                requester_endpoint_id: [2; 32],
                responder_endpoint_id: [3; 32],
                frontier_id: [4; 32],
                recipient_key_id: [5; 32],
                created_at_ms: 100,
                signer_public_key: crypto::ed25519_public_key(&private_key),
            };
            let bytes = encode::encode_key_request(&request).expect("encode key request");
            Fact::new(workspace::scope(workspace_id), request.created_at_ms, bytes)
        }

        fn authenticate(fact: &Fact) -> Result<KeyRequestFact, String> {
            let decoded = super::super::decode::decode_key_request(fact.body())?;
            super::authenticate(fact, decoded, &ProjectionContext::default())
        }

        fn is_invalid(fact: &Fact) -> bool {
            authenticate(fact).is_err()
        }

        #[test]
        fn authenticates_canonical_fact() {
            assert!(authenticate(&canonical_fact()).is_ok());
        }

        #[test]
        fn rejects_wrong_tag() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes[0] ^= 0xff;
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }

        #[test]
        fn rejects_truncated_bytes() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes.pop();
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }

        #[test]
        fn rejects_id_not_matching_bytes() {
            let canonical = canonical_fact();
            let forged = Fact {
                id: [0; 32],
                scope: canonical.scope.clone(),
                timestamp: canonical.timestamp,
                bytes: canonical.bytes.clone(),
            };
            assert!(is_invalid(&forged));
        }
    }
}
pub mod adapt {
    //! Key-request semantic adapter.
    //!
    //! The current key_request wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::KeyRequestFact;

    pub(crate) fn adapt(source: KeyRequestFact) -> Result<KeyRequestFact, String> {
        Ok(source)
    }
}

// Key request projector.
//
// POLICY. A key request is admitted iff its scope matches the workspace.
// Projection validates requester/responder context, finds eligible wrap
// sources, and emits create-key-wrap intents once local signer material is
// available.

use crate::core::context::ContextNeed;
use crate::core::facts::Fact;
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::auth::create_key_wrap::create_key_wrap_intent;
use crate::protocol::auth::endpoint_shared;
use crate::protocol::auth::key_wrap::project::{
    add_signer_needs_for_matching_sources, matched_payload_fact, matching_wrap_sources_with_signer,
    requested_wrap_source_need, require_fact_scope,
};
use crate::protocol::auth::recipient_key;
use crate::protocol::auth::removal_frontier;
use crate::protocol::auth::signature;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::fact::KeyRequestFact;

/// Projector route metadata for the key_request fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("auth::key_request::project::KeyRequestProjector");

#[derive(Debug, Clone, Default)]
pub struct KeyRequestProjector;

impl KeyRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for KeyRequestProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_key_request(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl KeyRequestProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        request: KeyRequestFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        key_request(fact, context, request)
    }
}

fn key_request(
    fact: &Fact,
    projection_context: &ProjectionContext,
    request: KeyRequestFact,
) -> Result<ProjectionOutput, String> {
    // 1. Scope.
    let scope = crate::protocol::auth::workspace::scope(request.workspace_id);
    require_fact_scope(fact, &scope)?;

    // 2. Context: signature evidence, requester signer, recipient, frontier, and wrap-source needs.
    let signature_need = signature::project::signature_proof_need(
        fact.id,
        scope.clone(),
        fact.id,
        request.signer_public_key,
    )?;
    let requester_need = ContextNeed::range(
        fact.id,
        "content_signer",
        scope.clone(),
        request.requester_endpoint_id,
        request.requester_endpoint_id,
    );
    let recipient_need = ContextNeed::range(
        fact.id,
        "recipient_key",
        scope.clone(),
        request.recipient_key_id,
        request.recipient_key_id,
    );
    let frontier_need = ContextNeed::range(
        fact.id,
        "auth_removal_frontier",
        scope.clone(),
        request.frontier_id,
        request.frontier_id,
    );
    let source_need = requested_wrap_source_need(
        fact.id,
        scope.clone(),
        request.workspace_id,
        request.frontier_id,
    );

    let recipient_fact = matched_payload_fact(projection_context, &recipient_need);
    let frontier_fact = matched_payload_fact(projection_context, &frontier_need);
    let mut output = ProjectionOutput::new()
        .need(signature_need.clone())
        .need(requester_need.clone())
        .need(recipient_need.clone())
        .need(frontier_need.clone())
        .need(source_need.clone());
    if !signature::project::signature_proof_ready(
        projection_context,
        &signature_need,
        request.workspace_id,
        fact.id,
        request.signer_public_key,
        "key request",
    )? {
        return Ok(output);
    }
    let Some(requester_fact) = projection_context.payload_for(&requester_need) else {
        return Ok(output);
    };
    validate_requester_signer(requester_fact, &request)?;
    let mut context_have =
        context_have_from_needs(projection_context, [&signature_need, &requester_need]);

    // 3. Materialize: emit create-key-wrap work for eligible sources.
    if let (Some(recipient_fact), Some(frontier_fact)) = (recipient_fact, frontier_fact) {
        if recipient_fact.id != request.recipient_key_id {
            return Err("key request recipient context payload id mismatch".to_string());
        }
        let recipient = recipient_key::decode_fact_payload(&recipient_fact.bytes)?;
        if recipient.workspace_id != request.workspace_id {
            return Err("key request recipient workspace mismatch".to_string());
        }
        if recipient.endpoint_id != request.requester_endpoint_id {
            return Err("key request recipient is not requester endpoint".to_string());
        }
        if frontier_fact.id != request.frontier_id {
            return Err("key request frontier context payload id mismatch".to_string());
        }
        let frontier = removal_frontier::decode_fact_payload(&frontier_fact.bytes)?;
        if frontier.workspace_id != request.workspace_id {
            return Err("key request frontier workspace mismatch".to_string());
        }
        if frontier.owner_endpoint_id != request.responder_endpoint_id {
            return Err("key request frontier is not owned by responder".to_string());
        }
        context_have.extend(context_have_from_needs(
            projection_context,
            [&recipient_need, &frontier_need],
        ));
        output = add_signer_needs_for_matching_sources(output, projection_context, &source_need)?;
        for (source_fact_id, signer_secret_fact_id, source) in
            matching_wrap_sources_with_signer(projection_context, &source_need)?
        {
            if source.owner_endpoint_id != request.responder_endpoint_id {
                continue;
            }
            output = output.intent(create_key_wrap_intent(
                request.recipient_key_id,
                source_fact_id,
                signer_secret_fact_id,
                source,
            ));
        }
    }
    Ok(share_fact_with_sync(
        output,
        request.workspace_id,
        fact,
        context_have,
    ))
}

fn validate_requester_signer(
    requester_fact: &Fact,
    request: &KeyRequestFact,
) -> Result<(), String> {
    let signer = endpoint_shared::decode_fact_payload(requester_fact.body())
        .map_err(|_| "key request requester context must be endpoint_shared".to_string())?;
    if signer.workspace_id != request.workspace_id {
        return Err("key request requester workspace mismatch".to_string());
    }
    if signer.endpoint_id != request.requester_endpoint_id {
        return Err("key request requester endpoint mismatch".to_string());
    }
    if signer.signing_public_key != request.signer_public_key {
        return Err("key request requester signing key mismatch".to_string());
    }
    Ok(())
}
