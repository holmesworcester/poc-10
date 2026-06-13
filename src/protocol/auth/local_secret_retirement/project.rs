pub mod decode {
    //! Byte decoding for local secret-retirement facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order, then
    //! re-runs field validation to reject non-canonical facts. Id checks live in
    //! the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{
        validate_fact, LOCAL_SECRET_RETIREMENT_BYTES, TYPE_LOCAL_SECRET_RETIREMENT,
    };
    use super::super::fact::LocalSecretRetirementFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<LocalSecretRetirementFact, String> {
        wire::expect_len(bytes, LOCAL_SECRET_RETIREMENT_BYTES).map_err(wire_err)?;
        if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_LOCAL_SECRET_RETIREMENT {
            return Err("expected local secret retirement".to_string());
        }
        let fact = LocalSecretRetirementFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            target_secret_id: bytes[33..65].try_into().unwrap(),
            reason_kind: wire::take_u8(&bytes[65..66]).map_err(wire_err)?,
            floor_minute: wire::take_u64be(&bytes[66..74]).map_err(wire_err)?,
            created_at_ms: wire::take_u64be(&bytes[74..82]).map_err(wire_err)?,
        };
        validate_fact(&fact)?;
        Ok(fact)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::local_secret_retirement::encode::{
            encode_fact, LOCAL_SECRET_RETIREMENT_BYTES,
        };
        use crate::protocol::auth::local_secret_retirement::fact::RETIRE_REASON_CHOP;

        fn sample_fact() -> LocalSecretRetirementFact {
            LocalSecretRetirementFact {
                workspace_id: [1; 32],
                target_secret_id: [2; 32],
                reason_kind: RETIRE_REASON_CHOP,
                floor_minute: 10,
                created_at_ms: 123,
            }
        }

        #[test]
        fn local_secret_retirement_roundtrips_fixed_width() {
            let fact = sample_fact();

            let encoded = encode_fact(&fact).expect("encode local secret retirement");

            assert_eq!(encoded.len(), LOCAL_SECRET_RETIREMENT_BYTES);
            assert_eq!(
                decode_fact(&encoded).expect("decode local secret retirement"),
                fact
            );
        }
    }
}
pub mod authenticate {
    //! Local secret-retirement authenticator.
    //!
    //! POLICY. Authenticating a `local_secret_retirement` fact proves, over its
    //! bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical local secret-retirement fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! These are local-only context facts, never signed envelopes, so there is no
    //! fact-boundary signature. Admission scope (`Local`), the target
    //! secret-source match, and materialization are all interpretation the
    //! projector owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::LocalSecretRetirementFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        retirement: LocalSecretRetirementFact,
        _context: &ProjectionContext,
    ) -> Result<LocalSecretRetirementFact, String> {
        prove_decoded_local_secret_retirement(fact, retirement)
    }

    fn prove_decoded_local_secret_retirement(
        fact: &Fact,
        retirement: LocalSecretRetirementFact,
    ) -> Result<LocalSecretRetirementFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(retirement)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::local_secret_retirement::encode;
        use crate::protocol::auth::local_secret_retirement::fact::{
            LocalSecretRetirementFact, RETIRE_REASON_CHOP,
        };

        fn canonical_fact() -> Fact {
            let retirement = LocalSecretRetirementFact {
                workspace_id: [1; 32],
                target_secret_id: [2; 32],
                reason_kind: RETIRE_REASON_CHOP,
                floor_minute: 10,
                created_at_ms: 123,
            };
            let bytes = encode::encode_fact(&retirement).expect("encode local secret retirement");
            Fact::new(FactScope::Local, 123, bytes)
        }

        fn authenticate(fact: &Fact) -> Result<LocalSecretRetirementFact, String> {
            let decoded = super::super::decode::decode_fact(fact.body())?;
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
    //! Local secret-retirement semantic adapter.
    //!
    //! The current local_secret_retirement wire shape is already the active
    //! semantic shape. This identity adapter keeps the staged route explicit and
    //! gives future versioned facts a dedicated conversion point.

    use super::super::fact::LocalSecretRetirementFact;

    pub(crate) fn adapt(
        source: LocalSecretRetirementFact,
    ) -> Result<LocalSecretRetirementFact, String> {
        Ok(source)
    }
}

// Local secret-retirement projector.
//
// POLICY. A local_secret_retirement is admitted iff:
//   1. STRUCTURAL. The fact is local-scoped and names a supported retirement
//      reason plus target secret-source id.
//   2. CONTEXT. Projection waits for the target `local_secret_source` context
//      and validates it belongs to the same workspace.
//   3. MATERIALIZE. Once validated, projection publishes exact retirement
//      context for the target; the target secret projector owns self-purge.

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::{local_history_node_secret, local_key_secret};

use super::fact::LocalSecretRetirementFact;

const LOCAL_SECRET_RETIRED_ROLE: &str = "local_secret_source_retired";

pub fn secret_retired_need(owner: FactId, target_secret_id: FactId) -> ContextNeed {
    exact_local_need(owner, LOCAL_SECRET_RETIRED_ROLE, target_secret_id)
}

pub fn secret_retired_offer(owner: FactId, target_secret_id: FactId) -> ContextOffer {
    exact_local_offer(owner, LOCAL_SECRET_RETIRED_ROLE, target_secret_id)
}

fn exact_local_need(owner: FactId, role: &'static str, key: FactId) -> ContextNeed {
    let key = ContextKey::from_bytes(key);
    ContextNeed {
        owner,
        role: Role::expect(role),
        scope: FactScope::Local,
        start_key: key.clone(),
        end_key: key,
    }
}

fn exact_local_offer(owner: FactId, role: &'static str, key: FactId) -> ContextOffer {
    let key = ContextKey::from_bytes(key);
    ContextOffer {
        owner,
        role: Role::expect(role),
        scope: FactScope::Local,
        start_key: key.clone(),
        end_key: key,
    }
}

/// Projector route metadata for the local_secret_retirement fact.
pub const PROJECTOR_INFO: FactProjectorInfo = FactProjectorInfo::projector(
    "auth::local_secret_retirement::project::LocalSecretRetirementProjector",
);

#[derive(Debug, Clone, Default)]
pub struct LocalSecretRetirementProjector;

impl LocalSecretRetirementProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalSecretRetirementProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl LocalSecretRetirementProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        retirement: LocalSecretRetirementFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("local secret retirement fact must have local scope".to_string());
        }

        // 2. Context.
        let target_need = ContextNeed::range(
            fact.id,
            "local_secret_source",
            FactScope::Local,
            retirement.target_secret_id,
            retirement.target_secret_id,
        );
        let Some(target) = context.payload_for(&target_need) else {
            return Ok(ProjectionOutput::new().need(target_need));
        };
        validate_target_secret(target, &retirement)?;

        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .need(target_need)
            .offer(secret_retired_offer(fact.id, retirement.target_secret_id)))
    }
}

fn validate_target_secret(
    target: &Fact,
    retirement: &LocalSecretRetirementFact,
) -> Result<(), String> {
    if target.id != retirement.target_secret_id {
        return Err("local secret retirement target context payload id mismatch".to_string());
    }
    if target.scope != FactScope::Local {
        return Err("local secret retirement target context must be local".to_string());
    }
    if let Ok(secret) = local_key_secret::decode_fact_payload(target.body()) {
        if secret.workspace_id != retirement.workspace_id {
            return Err("local key secret retirement workspace mismatch".to_string());
        }
        return Ok(());
    }
    if let Ok(secret) = local_history_node_secret::decode_fact_payload(target.body()) {
        if secret.workspace_id != retirement.workspace_id {
            return Err("local history secret retirement workspace mismatch".to_string());
        }
        return Ok(());
    }
    Err("local secret retirement target context is not key material".to_string())
}
