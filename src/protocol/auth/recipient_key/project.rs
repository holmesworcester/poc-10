pub mod decode {
    //! Byte decoding for recipient key facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{RECIPIENT_KEY_BYTES, TYPE_RECIPIENT_KEY};
    use super::super::fact::RecipientKeyFact;

    pub fn decode_recipient_key(bytes: &[u8]) -> Result<RecipientKeyFact, String> {
        wire::expect_len(bytes, RECIPIENT_KEY_BYTES).map_err(wire_err)?;
        if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_RECIPIENT_KEY {
            return Err("expected recipient key".to_string());
        }
        Ok(RecipientKeyFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            endpoint_id: bytes[33..65].try_into().unwrap(),
            recipient_key: bytes[65..97].try_into().unwrap(),
            previous_recipient_key_id: bytes[97..129].try_into().unwrap(),
            created_at_ms: wire::take_u64be(&bytes[129..137]).map_err(wire_err)?,
            signer_public_key: bytes[137..169].try_into().unwrap(),
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::recipient_key::encode::{
            encode_recipient_key, RECIPIENT_KEY_BYTES,
        };

        fn sample_fact() -> RecipientKeyFact {
            RecipientKeyFact {
                workspace_id: [1; 32],
                endpoint_id: [2; 32],
                recipient_key: [3; 32],
                previous_recipient_key_id: [4; 32],
                created_at_ms: 123,
                signer_public_key: [5; 32],
            }
        }

        #[test]
        fn recipient_key_roundtrips_fixed_width() {
            let fact = sample_fact();

            let encoded = encode_recipient_key(&fact).expect("encode recipient key");

            assert_eq!(encoded.len(), RECIPIENT_KEY_BYTES);
            assert_eq!(
                decode_recipient_key(&encoded).expect("decode recipient key"),
                fact
            );
        }
    }
}
pub mod authenticate {
    //! Recipient-key authenticator.
    //!
    //! POLICY. Authenticating a `recipient_key` fact proves, over its canonical bytes
    //! alone:
    //!   1. LAYOUT. The bytes decode to a canonical recipient-key fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!   4. FIELDS. A recipient key cannot supersede itself
    //!      (`previous_recipient_key_id != fact_id`).
    //!
    //! Admission scope is unsigned local metadata, so the workspace-scope check is
    //! interpretation the projector owns. Supersession against an earlier key and
    //! signer matching are proven from other facts, also in the projector.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::RecipientKeyFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        recipient: RecipientKeyFact,
        _context: &ProjectionContext,
    ) -> Result<RecipientKeyFact, String> {
        prove_decoded_recipient_key(fact, recipient)
    }

    fn prove_decoded_recipient_key(
        fact: &Fact,
        recipient: RecipientKeyFact,
    ) -> Result<RecipientKeyFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // 4. A recipient key cannot supersede itself.
        if recipient.previous_recipient_key_id == fact.id {
            return Err(
                "recipient key cannot supersede itself (previous_recipient_key_id == fact_id)"
                    .to_string(),
            );
        }
        Ok(recipient)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::crypto;
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::recipient_key::author::authored_recipient_key_fact;
        use crate::protocol::auth::recipient_key::fact::{
            RecipientKeyFact, NO_PREVIOUS_RECIPIENT_KEY,
        };

        const SIGNER_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            let private_key = SIGNER_KEY;
            let signer_public_key = crypto::ed25519_public_key(&private_key);
            authored_recipient_key_fact(
                [1; 32],
                [2; 32],
                [3; 32],
                NO_PREVIOUS_RECIPIENT_KEY,
                100,
                signer_public_key,
            )
            .expect("signed recipient_key fact")
        }

        fn authenticate(fact: &Fact) -> Result<RecipientKeyFact, String> {
            let decoded = super::super::decode::decode_recipient_key(fact.body())?;
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
    //! Recipient key semantic adapter.
    //!
    //! The current recipient_key wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::RecipientKeyFact;

    pub(crate) fn adapt(source: RecipientKeyFact) -> Result<RecipientKeyFact, String> {
        Ok(source)
    }
}

// Recipient key projector.
//
// POLICY. A recipient key is admitted iff its scope matches the workspace and
// supersession of any previous recipient key validates. Projection shares the
// fact, publishes recipient context, and emits proactive key-wrap work when
// eligible local wrap sources and signer secrets are available.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::Fact;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::create_key_wrap::create_key_wrap_intent;
use crate::protocol::auth::endpoint_shared;
use crate::protocol::auth::key_wrap::project::{
    add_signer_needs_for_matching_sources, matched_payload_fact, matching_wrap_sources_with_signer,
    proactive_wrap_source_need, require_fact_scope,
};
use crate::protocol::auth::signature;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::fact::{RecipientKeyFact, NO_PREVIOUS_RECIPIENT_KEY};

/// Projector route metadata for the recipient_key fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::recipient_key::project::RecipientKeyProjector");

#[derive(Debug, Clone, Default)]
pub struct RecipientKeyProjector;

impl RecipientKeyProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for RecipientKeyProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_recipient_key(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl RecipientKeyProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        recipient: RecipientKeyFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        recipient_key(fact, context, recipient)
    }
}

fn recipient_key(
    fact: &Fact,
    projection_context: &ProjectionContext,
    recipient: RecipientKeyFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = crate::protocol::auth::workspace::scope(recipient.workspace_id);
    require_fact_scope(fact, &scope)?;

    // 2. Context: signature evidence, signer, supersession, and previous-key validation.
    let signature_need = signature::project::signature_proof_need(
        fact.id,
        scope.clone(),
        fact.id,
        recipient.signer_public_key,
    )?;
    let signer_need = ContextNeed::range(
        fact.id,
        "content_signer",
        scope.clone(),
        recipient.endpoint_id,
        recipient.endpoint_id,
    );
    let superseded_need = ContextNeed::range(
        fact.id,
        "recipient_superseded",
        scope.clone(),
        fact.id,
        fact.id,
    );
    let mut context_have = context_have_from_needs(projection_context, [&superseded_need]);
    let is_superseded = !context_have.is_empty();
    let mut output = ProjectionOutput::new()
        .need(signature_need.clone())
        .need(signer_need.clone())
        .need(superseded_need);
    if !signature::project::signature_proof_ready(
        projection_context,
        &signature_need,
        recipient.workspace_id,
        fact.id,
        recipient.signer_public_key,
        "recipient key",
    )? {
        return Ok(output);
    }

    if recipient.previous_recipient_key_id != NO_PREVIOUS_RECIPIENT_KEY {
        let previous_need = ContextNeed::range(
            fact.id,
            "recipient_key",
            scope.clone(),
            recipient.previous_recipient_key_id,
            recipient.previous_recipient_key_id,
        );
        output = output.need(previous_need.clone());
        let Some(previous_fact) = matched_payload_fact(projection_context, &previous_need) else {
            return Ok(output);
        };
        validate_previous_recipient_key(previous_fact, &recipient)?;
        context_have.push(previous_fact.id);
        output = output.offer(ContextOffer::range(
            fact.id,
            "recipient_superseded",
            scope.clone(),
            recipient.previous_recipient_key_id,
            recipient.previous_recipient_key_id,
        ));
    }
    let Some(signer_fact) = projection_context.payload_for(&signer_need) else {
        return Ok(output);
    };
    validate_recipient_signer(signer_fact, &recipient)?;
    context_have.extend(context_have_from_needs(
        projection_context,
        [&signature_need],
    ));
    context_have.extend(context_have_from_needs(projection_context, [&signer_need]));

    // 3. Materialize: publish recipient context and proactive key-wrap work.
    output = share_fact_with_sync(
        output.offer(ContextOffer::range(
            fact.id,
            "recipient_key",
            scope.clone(),
            fact.id,
            fact.id,
        )),
        recipient.workspace_id,
        fact,
        context_have,
    );

    if is_superseded {
        return Ok(output);
    }

    let min_frontier_created_at_ms =
        if recipient.previous_recipient_key_id == NO_PREVIOUS_RECIPIENT_KEY {
            0
        } else {
            recipient.created_at_ms
        };
    let wrap_need = proactive_wrap_source_need(
        fact.id,
        scope.clone(),
        recipient.workspace_id,
        min_frontier_created_at_ms,
    );
    output = output.need(wrap_need.clone());

    output = add_signer_needs_for_matching_sources(output, projection_context, &wrap_need)?;
    for (source_fact_id, signer_secret_fact_id, source) in
        matching_wrap_sources_with_signer(projection_context, &wrap_need)?
    {
        output = output.intent(create_key_wrap_intent(
            fact.id,
            source_fact_id,
            signer_secret_fact_id,
            source,
        ));
    }
    Ok(output)
}

fn validate_previous_recipient_key(
    previous_fact: &Fact,
    recipient: &RecipientKeyFact,
) -> Result<(), String> {
    if previous_fact.id != recipient.previous_recipient_key_id {
        return Err("recipient key supersession previous context payload id mismatch".to_string());
    }
    let previous = super::decode_fact_payload(&previous_fact.bytes).map_err(|_| {
        "recipient key supersession previous dependency is not a recipient key".to_string()
    })?;
    if previous.workspace_id != recipient.workspace_id {
        return Err(
            "recipient key supersession previous_recipient_key workspace does not match"
                .to_string(),
        );
    }
    if previous.endpoint_id != recipient.endpoint_id {
        return Err(
            "recipient key supersession previous_recipient_key endpoint does not match \
             (cross-endpoint supersession is rejected)"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_recipient_signer(
    signer_fact: &Fact,
    recipient: &RecipientKeyFact,
) -> Result<(), String> {
    let signer = endpoint_shared::decode_fact_payload(signer_fact.body())
        .map_err(|_| "recipient key signer context must be endpoint_shared".to_string())?;
    if signer.workspace_id != recipient.workspace_id {
        return Err("recipient key signer workspace mismatch".to_string());
    }
    if signer.endpoint_id != recipient.endpoint_id {
        return Err("recipient key signer endpoint mismatch".to_string());
    }
    if signer.signing_public_key != recipient.signer_public_key {
        return Err("recipient key signer public key mismatch".to_string());
    }
    Ok(())
}
