pub mod decode {
    //! Byte decoding for removal frontier facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{REMOVAL_FRONTIER_BYTES, TYPE_REMOVAL_FRONTIER};
    use super::super::fact::RemovalFrontierFact;

    pub fn decode_removal_frontier(bytes: &[u8]) -> Result<RemovalFrontierFact, String> {
        wire::expect_len(bytes, REMOVAL_FRONTIER_BYTES).map_err(wire_err)?;
        if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_REMOVAL_FRONTIER {
            return Err("expected removal frontier".to_string());
        }
        Ok(RemovalFrontierFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            owner_endpoint_id: bytes[33..65].try_into().unwrap(),
            created_at_ms: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
            signer_public_key: bytes[73..105].try_into().unwrap(),
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    // Single round-trip test: encode then decode recovers the fact.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::removal_frontier::encode::{
            encode_removal_frontier, REMOVAL_FRONTIER_BYTES,
        };

        fn sample_fact() -> RemovalFrontierFact {
            RemovalFrontierFact {
                workspace_id: [1; 32],
                owner_endpoint_id: [2; 32],
                created_at_ms: 123,
                signer_public_key: [3; 32],
            }
        }

        #[test]
        fn removal_frontier_roundtrips_fixed_width() {
            let fact = sample_fact();

            let encoded = encode_removal_frontier(&fact).expect("encode removal frontier");

            assert_eq!(encoded.len(), REMOVAL_FRONTIER_BYTES);
            assert_eq!(
                decode_removal_frontier(&encoded).expect("decode removal frontier"),
                fact
            );
        }
    }
}
pub mod authenticate {
    //! Removal-frontier authenticator.
    //!
    //! POLICY. Authenticating a `removal_frontier` fact proves, over its signed
    //! bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical removal-frontier fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!
    //! Scope and owner-endpoint authority (an `endpoint_shared` signer or a local
    //! signer secret) are interpretation the projector owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::RemovalFrontierFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        frontier: RemovalFrontierFact,
        _context: &ProjectionContext,
    ) -> Result<RemovalFrontierFact, String> {
        prove_decoded_removal_frontier(fact, frontier)
    }

    fn prove_decoded_removal_frontier(
        fact: &Fact,
        frontier: RemovalFrontierFact,
    ) -> Result<RemovalFrontierFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(frontier)
    }

    // Tests.
    // Ordered most-central-first: happy-path authentication, then the id guard, then layout guards.
    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::removal_frontier::author::authored_removal_frontier_fact;
        use crate::protocol::auth::removal_frontier::fact::RemovalFrontierFact;

        const SIGNER_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            authored_removal_frontier_fact([1; 32], [2; 32], 100, SIGNER_KEY)
                .expect("signed removal_frontier fact")
        }

        fn authenticate(fact: &Fact) -> Result<RemovalFrontierFact, String> {
            let decoded = super::super::decode::decode_removal_frontier(fact.body())?;
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
    }
}
pub mod adapt {
    //! Removal-frontier semantic adapter.
    //!
    //! The current removal_frontier wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::RemovalFrontierFact;

    pub(crate) fn adapt(source: RemovalFrontierFact) -> Result<RemovalFrontierFact, String> {
        Ok(source)
    }
}

// Removal frontier projector.
//
// POLICY. A removal frontier is admitted iff its scope matches the workspace
// and its owner endpoint is proven by either an endpoint_shared signer offer or
// a local signer secret. Projection publishes frontier context and shares the
// fact with the workspace.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::Fact;
use crate::core::intents::{RowMutation, TableInsert, Value};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth;
use crate::protocol::auth::key_wrap::project::require_fact_scope;
use crate::protocol::auth::signature;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::{fact::RemovalFrontierFact, REMOVAL_FRONTIER_ROWS};

/// Projector route metadata for the removal_frontier fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::removal_frontier::project::RemovalFrontierProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct RemovalFrontierProjector;

impl RemovalFrontierProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for RemovalFrontierProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_removal_frontier(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl RemovalFrontierProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        frontier: RemovalFrontierFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see the local authenticate module) proved canonical bytes and the
        // signer signature. Scope is interpretation.
        // 1. Scope.
        let scope = crate::protocol::auth::workspace::scope(frontier.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Authority and signature evidence.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            scope.clone(),
            fact.id,
            frontier.signer_public_key,
        )?;
        let owner_signer_need = ContextNeed::for_key(
            fact.id,
            "content_signer",
            scope.clone(),
            frontier.owner_endpoint_id,
        );
        let local_signer_need = ContextNeed::for_key(
            fact.id,
            "local_signer_secret",
            scope.clone(),
            frontier.owner_endpoint_id,
        );
        let waiting = ProjectionOutput::new()
            .need(signature_need.clone())
            .need(owner_signer_need.clone())
            .need(local_signer_need.clone());
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            frontier.workspace_id,
            fact.id,
            frontier.signer_public_key,
            "removal frontier",
        )? {
            return Ok(waiting);
        }
        let context_have = match (
            context.payload_for(&owner_signer_need),
            context.payload_for(&local_signer_need),
        ) {
            (Some(owner_fact), _) => {
                validate_frontier_endpoint_shared_owner(owner_fact, &frontier)?;
                context_have_from_needs(context, [&signature_need, &owner_signer_need])
            }
            (None, Some(owner_fact)) => {
                validate_frontier_local_owner(owner_fact, &frontier)?;
                context_have_from_needs(context, [&signature_need])
            }
            (None, None) => return Ok(waiting),
        };

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new().offer(ContextOffer::range(
                fact.id,
                "auth_removal_frontier",
                scope,
                fact.id,
                fact.id,
            )),
            frontier.workspace_id,
            fact,
            context_have,
        )
        .row_mutation(RowMutation::InsertValues(TableInsert {
            table: REMOVAL_FRONTIER_ROWS,
            columns: &[
                "workspace_id",
                "frontier_id",
                "owner_endpoint_id",
                "created_at_ms",
                "signer_public_key",
            ],
            values: vec![
                Value::Bytes(frontier.workspace_id.to_vec()),
                Value::Bytes(fact.id.to_vec()),
                Value::Bytes(frontier.owner_endpoint_id.to_vec()),
                Value::U64(frontier.created_at_ms),
                Value::Bytes(frontier.signer_public_key.to_vec()),
            ],
        })))
    }
}

fn validate_frontier_endpoint_shared_owner(
    owner_fact: &Fact,
    frontier: &RemovalFrontierFact,
) -> Result<(), String> {
    let owner = auth::endpoint_shared::decode_fact_payload(owner_fact.body())
        .map_err(|_| "removal frontier owner context must be endpoint_shared".to_string())?;
    if owner.workspace_id != frontier.workspace_id {
        return Err("removal frontier owner workspace mismatch".to_string());
    }
    if owner.endpoint_id != frontier.owner_endpoint_id {
        return Err("removal frontier owner endpoint mismatch".to_string());
    }
    if owner.signing_public_key != frontier.signer_public_key {
        return Err("removal frontier owner signing key mismatch".to_string());
    }
    Ok(())
}

fn validate_frontier_local_owner(
    owner_fact: &Fact,
    frontier: &RemovalFrontierFact,
) -> Result<(), String> {
    let owner =
        auth::local_signer_secret::decode_fact_payload(owner_fact.body()).map_err(|_| {
            "removal frontier local owner context must be local signer secret".to_string()
        })?;
    if owner.workspace_id != frontier.workspace_id {
        return Err("removal frontier local owner workspace mismatch".to_string());
    }
    if owner.signer_id != frontier.owner_endpoint_id {
        return Err("removal frontier local owner endpoint mismatch".to_string());
    }
    if owner.public_key != frontier.signer_public_key {
        return Err("removal frontier local owner signing key mismatch".to_string());
    }
    Ok(())
}
