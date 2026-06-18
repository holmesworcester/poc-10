pub mod decode {
    //! Byte decoding for sync shared-fact declarations.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. The
    //! actual fact bytes stay in the core fact store.

    use crate::core::wire;

    use super::super::encode::{ENCODED_BYTES, TYPE_SHARED_FACT};
    use super::super::fact::SharedFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<SharedFact, String> {
        wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_SHARED_FACT {
            return Err("expected sync shared fact".to_string());
        }
        Ok(SharedFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            fact_id: bytes[33..65].try_into().unwrap(),
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::sync::shared_fact::encode::{encode_fact, ENCODED_BYTES};

        #[test]
        fn shared_fact_roundtrips_fixed_width() {
            let fact = SharedFact {
                workspace_id: [1; 32],
                fact_id: [2; 32],
            };

            let encoded = encode_fact(&fact).expect("encode shared fact");

            assert_eq!(encoded.len(), ENCODED_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode shared fact"), fact);
        }
    }
}
pub mod authenticate {
    //! Sync shared-fact authenticator.
    //!
    //! POLICY. Authenticating a `sync shared_fact` proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical shared-fact offer.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! It proves nothing else. Admission scope (the offer's workspace) is unsigned
    //! local metadata, so the workspace-scope check is interpretation the projector
    //! owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::SharedFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        shared: SharedFact,
        _context: &ProjectionContext,
    ) -> Result<SharedFact, String> {
        prove_decoded_shared_fact(fact, shared)
    }

    fn prove_decoded_shared_fact(fact: &Fact, shared: SharedFact) -> Result<SharedFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(shared)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::sync::shared_fact::encode;
        use crate::protocol::sync::shared_fact::fact::SharedFact;

        fn canonical_fact() -> Fact {
            let shared = SharedFact {
                workspace_id: [1; 32],
                fact_id: [2; 32],
            };
            Fact::new(
                FactScope::Global,
                0,
                encode::encode_fact(&shared).expect("encode shared fact"),
            )
        }

        fn authenticate(fact: &Fact) -> Result<SharedFact, String> {
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

        // Admission scope is interpretation, checked by the projector, not the
        // authenticator: a shared fact with a Local scope authenticates here and is
        // rejected downstream.
    }
}
pub mod adapt {
    //! Sync shared-fact semantic adapter.
    //!
    //! The current shared_fact wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::SharedFact;

    pub(crate) fn adapt(source: SharedFact) -> Result<SharedFact, String> {
        Ok(source)
    }
}

// Projector for sync shared-fact offers.
//
// POLICY. A sync shared_fact is admitted iff:
//   1. STRUCTURAL. The body decodes and the outer fact scope matches its
//      workspace id.
//   2. CONTEXT. No incoming context is required; this fact advertises a shared
//      payload id that is already present.
//   3. MATERIALIZE. Publish an exact-fact offer for range-request dependency
//      matching.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use std::collections::BTreeSet;

use crate::protocol::sync::share_fact_with_sync as share_sync;

/// Projector route metadata for the shared_fact fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("sync::shared_fact::project::SyncSharedFactProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct SyncSharedFactProjector;

impl SyncSharedFactProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncSharedFactProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, projection_context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, projection_context)
    }
}

impl SyncSharedFactProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        shared: super::fact::SharedFact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(shared.workspace_id);
        require_fact_scope(fact, &scope)?;
        // 3. Materialize.
        Ok(
            ProjectionOutput::new().offer(crate::core::context::ContextOffer::range(
                fact.id,
                "sync_exact_fact",
                scope,
                shared.fact_id,
                shared.fact_id,
            )),
        )
    }
}

pub fn share_fact_with_sync(
    output: ProjectionOutput,
    workspace_id: FactId,
    fact: &Fact,
    context_have: Vec<FactId>,
) -> ProjectionOutput {
    output.intent(share_sync::share_fact_with_sync_intent_for_fact(
        workspace_id,
        fact.id,
        fact.timestamp,
        context_have,
    ))
}

pub fn retract_fact_from_sync(
    output: ProjectionOutput,
    workspace_id: FactId,
    fact_id: FactId,
    timestamp_ms: u64,
) -> ProjectionOutput {
    output.intent(share_sync::retract_fact_from_sync_intent(
        workspace_id,
        fact_id,
        timestamp_ms,
    ))
}

pub fn context_have_from_needs<'a>(
    context: &ProjectionContext,
    needs: impl IntoIterator<Item = &'a ContextNeed>,
) -> Vec<FactId> {
    let mut ids = BTreeSet::new();
    for need in needs {
        for (_offer, payload) in context.matched_payloads_for(need) {
            ids.insert(payload.id);
        }
    }
    ids.into_iter().collect()
}

pub fn context_have_from_optional_needs<'a>(
    context: &ProjectionContext,
    needs: impl IntoIterator<Item = Option<&'a ContextNeed>>,
) -> Vec<FactId> {
    context_have_from_needs(context, needs.into_iter().flatten())
}

fn require_fact_scope(fact: &Fact, expected: &FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sync context fact scope does not match body workspace".to_string())
    }
}
