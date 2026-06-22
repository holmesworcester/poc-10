pub mod decode {
    //! Byte decoding for local key secret facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, field order, and that the
    //! decoded material is canonical. Id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{
        encode_local_key_secret, LOCAL_KEY_SECRET_BYTES, TYPE_LOCAL_KEY_SECRET,
    };
    use super::super::fact::LocalKeySecretFact;

    pub fn decode_local_key_secret(bytes: &[u8]) -> Result<LocalKeySecretFact, String> {
        wire::expect_len(bytes, LOCAL_KEY_SECRET_BYTES).map_err(wire_err)?;
        if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_LOCAL_KEY_SECRET {
            return Err("expected local key secret".to_string());
        }
        let fact = LocalKeySecretFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            frontier_id: bytes[33..65].try_into().unwrap(),
            owner_endpoint_id: bytes[65..97].try_into().unwrap(),
            created_at_ms: wire::take_u64be(&bytes[97..105]).map_err(wire_err)?,
            key_secret: bytes[105..137].try_into().unwrap(),
        };
        encode_local_key_secret(&fact)?;
        Ok(fact)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    // Single round-trip test: encode then decode recovers the fact.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::local_key_secret::encode::{
            encode_local_key_secret, LOCAL_KEY_SECRET_BYTES,
        };

        fn sample_fact() -> LocalKeySecretFact {
            LocalKeySecretFact {
                workspace_id: [1; 32],
                frontier_id: [2; 32],
                owner_endpoint_id: [3; 32],
                created_at_ms: 123,
                key_secret: [4; 32],
            }
        }

        #[test]
        fn local_key_secret_roundtrips_fixed_width() {
            let fact = sample_fact();

            let encoded = encode_local_key_secret(&fact).expect("encode local key secret");

            assert_eq!(encoded.len(), LOCAL_KEY_SECRET_BYTES);
            assert_eq!(
                decode_local_key_secret(&encoded).expect("decode local key secret"),
                fact
            );
        }
    }
}
pub mod authenticate {
    //! Local key secret authenticator.
    //!
    //! POLICY. Authenticating a `local_key_secret` fact proves, over its bytes
    //! alone:
    //!   1. LAYOUT. The bytes decode to a canonical local key secret fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! These are local-only secrets, never signed envelopes, so there is no
    //! fact-boundary signature. Admission scope (`Local`), the removal-frontier
    //! match, retirement, and materialization are all interpretation the projector
    //! owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::LocalKeySecretFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        secret: LocalKeySecretFact,
        _context: &ProjectionContext,
    ) -> Result<LocalKeySecretFact, String> {
        prove_decoded_local_key_secret(fact, secret)
    }

    fn prove_decoded_local_key_secret(
        fact: &Fact,
        secret: LocalKeySecretFact,
    ) -> Result<LocalKeySecretFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(secret)
    }

    // Tests.
    // Ordered most-central-first: happy-path authentication, then the id guard, then layout guards.
    #[cfg(test)]
    mod tests {
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::local_key_secret::encode;
        use crate::protocol::auth::local_key_secret::fact::LocalKeySecretFact;

        fn canonical_fact() -> Fact {
            let secret = LocalKeySecretFact {
                workspace_id: [1; 32],
                frontier_id: [2; 32],
                owner_endpoint_id: [3; 32],
                created_at_ms: 123,
                key_secret: [4; 32],
            };
            let bytes = encode::encode_local_key_secret(&secret).expect("encode local key secret");
            Fact::new(FactScope::Local, 123, bytes)
        }

        fn authenticate(fact: &Fact) -> Result<LocalKeySecretFact, String> {
            let decoded = super::super::decode::decode_local_key_secret(fact.body())?;
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
    //! Local key secret semantic adapter.
    //!
    //! The current local_key_secret wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::LocalKeySecretFact;

    pub(crate) fn adapt(source: LocalKeySecretFact) -> Result<LocalKeySecretFact, String> {
        Ok(source)
    }
}

// Local key secret projector.
//
// POLICY. A local key secret is admitted iff it is local-scoped and ties to its
// removal frontier. Projection publishes frontier-root wrap-source and
// secret-coverage offers while live, and self-purges when retirement context
// for this secret arrives.

use crate::core::context::{ContextNeed, ContextOfferClaim};
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{TableDeleteWhere, TableInsert, Value};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectedRowMutation, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::key_wrap::project::{
    frontier_root_wrap_source_offer_claims, require_local_scope,
};
use crate::protocol::auth::local_history_node_secret::project::secret_offer_claim;
use crate::protocol::auth::local_secret_retirement;
use crate::protocol::auth::removal_frontier;

use super::{fact::LocalKeySecretFact, LOCAL_KEY_SECRET_ROWS};

/// Projector route metadata for the local_key_secret fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::local_key_secret::project::LocalKeySecretProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct LocalKeySecretProjector;

impl LocalKeySecretProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalKeySecretProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_local_key_secret(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl LocalKeySecretProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        secret: LocalKeySecretFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_local_key_secret(fact, context, secret)
    }
}

fn project_local_key_secret(
    fact: &Fact,
    projection_context: &ProjectionContext,
    secret: LocalKeySecretFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = crate::protocol::auth::workspace::scope(secret.workspace_id);
    require_local_scope(fact)?;
    // 2. Context: retirement and removal-frontier match.
    let retirement_need = local_secret_retirement::secret_retired_need(fact.id, fact.id);
    if let Some(retirement_fact) = projection_context.payload_for(&retirement_need) {
        validate_local_key_retirement(retirement_fact, fact.id, &secret)?;
        return Ok(ProjectionOutput::new()
            .row_mutation(ProjectedRowMutation::DeleteWhere(TableDeleteWhere {
                table: LOCAL_KEY_SECRET_ROWS,
                columns: &["workspace_id", "frontier_id", "secret_id"],
                values: vec![
                    Value::Bytes(secret.workspace_id.to_vec()),
                    Value::Bytes(secret.frontier_id.to_vec()),
                    Value::Bytes(fact.id.to_vec()),
                ],
            }))
            .purge_self(fact.id));
    }

    let frontier_need = ContextNeed::range(
        fact.id,
        "auth_removal_frontier",
        scope.clone(),
        secret.frontier_id,
        secret.frontier_id,
    );
    let Some(frontier_fact) = projection_context.payload_for(&frontier_need) else {
        return Ok(ProjectionOutput::new()
            .need(frontier_need)
            .need(retirement_need));
    };
    validate_local_key_frontier(frontier_fact, &secret)?;

    // 3. Materialize: publish wrap-source and coverage offers.
    let mut output = ProjectionOutput::new()
        .need(frontier_need)
        .need(retirement_need);
    for offer in frontier_root_wrap_source_offer_claims(
        scope.clone(),
        secret.workspace_id,
        secret.frontier_id,
        secret.owner_endpoint_id,
        secret.created_at_ms,
    ) {
        output = output.offer(offer);
    }
    Ok(output
        .row_mutation(ProjectedRowMutation::InsertValues(TableInsert {
            table: LOCAL_KEY_SECRET_ROWS,
            columns: &[
                "workspace_id",
                "frontier_id",
                "secret_id",
                "owner_endpoint_id",
                "created_at_ms",
                "key_secret",
            ],
            values: vec![
                Value::Bytes(secret.workspace_id.to_vec()),
                Value::Bytes(secret.frontier_id.to_vec()),
                Value::Bytes(fact.id.to_vec()),
                Value::Bytes(secret.owner_endpoint_id.to_vec()),
                Value::U64(secret.created_at_ms),
                Value::Bytes(secret.key_secret.to_vec()),
            ],
        }))
        .offer(ContextOfferClaim::range(
            "local_secret_source",
            FactScope::Local,
            fact.id,
            fact.id,
        ))
        .offer(secret_offer_claim(
            scope,
            secret.workspace_id,
            secret.frontier_id,
            0,
            u64::MAX,
            0,
            [0; 32],
        )))
}

fn validate_local_key_retirement(
    retirement_fact: &Fact,
    target_id: crate::core::facts::FactId,
    secret: &LocalKeySecretFact,
) -> Result<(), String> {
    if retirement_fact.scope != FactScope::Local {
        return Err("local key secret retirement context must be local".to_string());
    }
    let retirement = local_secret_retirement::decode_fact_payload(retirement_fact.body())
        .map_err(|_| "local key secret retirement context is not a retirement fact".to_string())?;
    if retirement.workspace_id != secret.workspace_id {
        return Err("local key secret retirement workspace mismatch".to_string());
    }
    if retirement.target_secret_id != target_id {
        return Err("local key secret retirement target mismatch".to_string());
    }
    Ok(())
}

fn validate_local_key_frontier(
    frontier_fact: &Fact,
    secret: &LocalKeySecretFact,
) -> Result<(), String> {
    if frontier_fact.id != secret.frontier_id {
        return Err("local key secret frontier context payload id mismatch".to_string());
    }
    let frontier = removal_frontier::decode_fact_payload(&frontier_fact.bytes)
        .map_err(|_| "local key secret frontier context must be a removal frontier".to_string())?;
    if frontier.workspace_id != secret.workspace_id {
        return Err("local key secret frontier workspace mismatch".to_string());
    }
    if frontier.owner_endpoint_id != secret.owner_endpoint_id {
        return Err("local key secret frontier owner mismatch".to_string());
    }
    Ok(())
}
