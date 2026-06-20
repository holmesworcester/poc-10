pub mod decode {
    //! Byte decoding for the sync have-id fact.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order.

    use crate::core::wire;

    use super::super::encode::{ENCODED_BYTES, TYPE_SYNC_HAVE_ID};
    use super::super::fact::SyncHaveIdFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<SyncHaveIdFact, String> {
        wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_SYNC_HAVE_ID {
            return Err("expected sync have-id fact".to_string());
        }
        let mut connection_id = [0; 32];
        connection_id.copy_from_slice(&bytes[1..33]);
        let timestamp = wire::take_u64be(&bytes[33..41]).map_err(wire_err)?;
        let mut fact_id = [0; 32];
        fact_id.copy_from_slice(&bytes[41..73]);
        Ok(SyncHaveIdFact {
            connection_id,
            timestamp,
            fact_id,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    // Most-central-first: the round-trip leads, then the tag/length guard.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::sync::have_id::encode::{encode_fact, ENCODED_BYTES};

        fn fact() -> SyncHaveIdFact {
            SyncHaveIdFact {
                connection_id: [4; 32],
                timestamp: 777,
                fact_id: [8; 32],
            }
        }

        #[test]
        fn sync_have_id_roundtrips() {
            let bytes = encode_fact(&fact()).expect("encode");
            assert_eq!(bytes.len(), ENCODED_BYTES);
            assert_eq!(decode_fact(&bytes).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag_and_length() {
            let mut bytes = encode_fact(&fact()).expect("encode");
            bytes[0] = TYPE_SYNC_HAVE_ID.wrapping_add(1);
            assert!(decode_fact(&bytes).is_err());

            let mut short = encode_fact(&fact()).expect("encode");
            short.pop();
            assert!(decode_fact(&short).is_err());
        }
    }
}
pub mod authenticate {
    //! Sync have-id authenticator.
    //!
    //! POLICY. Authenticating a `sync_have_id` fact proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical have-id advertisement.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! It proves nothing else. A have-id fact carries no fact-boundary signature;
    //! whether the advertised id is already present is idempotent handler work the
    //! projector and its intents own.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::SyncHaveIdFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        have: SyncHaveIdFact,
        _context: &ProjectionContext,
    ) -> Result<SyncHaveIdFact, String> {
        prove_decoded_have_id(fact, have)
    }

    fn prove_decoded_have_id(fact: &Fact, have: SyncHaveIdFact) -> Result<SyncHaveIdFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(have)
    }

    // Tests.
    // Most-central-first: the happy path then the id check, then decode-layer guards.
    #[cfg(test)]
    mod tests {
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::sync::have_id::author::advertisement_fact;
        use crate::protocol::sync::have_id::fact::SyncHaveIdFact;

        fn canonical_fact() -> Fact {
            let advertised = Fact::new(FactScope::Global, 777, vec![42]);
            advertisement_fact([7; 32], &advertised).expect("have-id advertisement fact")
        }

        fn authenticate(fact: &Fact) -> Result<SyncHaveIdFact, String> {
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
    //! Sync have-id semantic adapter.
    //!
    //! The current have_id wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::SyncHaveIdFact;

    pub(crate) fn adapt(source: SyncHaveIdFact) -> Result<SyncHaveIdFact, String> {
        Ok(source)
    }
}

// Poc-10 sync have-id projector.
//
// POLICY. A sync_have_id fact is admitted iff:
//   1. STRUCTURAL. The advertisement payload decodes.
//   2. CONTEXT. No matched context is required; idempotent handler work decides
//      whether the advertised id is already present.
//   3. MATERIALIZE. Write the have-id row and emit deferred need-id work.
//
// Replay keeps this retained negotiation fact as evidence but does not rebuild
// stale need/have state.

use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::sync::send_needed_fact_id::{send_needed_fact_id_intent, SendNeededFactId};

use super::sync_have_id_row;

/// Projector route metadata for the have_id fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("sync::have_id::project::SyncHaveIdProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct SyncHaveIdProjector;

impl SyncHaveIdProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncHaveIdProjector {
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

impl SyncHaveIdProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        have: super::fact::SyncHaveIdFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
        }
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .row_mutation(RowMutation::InsertValues(sync_have_id_row(fact.id, &have)))
            .intent(send_needed_fact_id_intent(SendNeededFactId {
                have_fact_id: fact.id,
            })))
    }
}

// Tests.
// Replay keeps this negotiation fact as evidence without rebuilding need/have state.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::project_fact::ProjectionMode;
    use crate::protocol::sync::send_needed_fact_id::SEND_NEEDED_FACT_ID;

    #[test]
    fn replay_projection_does_not_rebuild_sync_negotiation_state() {
        let fact = Fact::new(FactScope::Local, 1, vec![1]);
        let have = super::super::fact::SyncHaveIdFact {
            connection_id: [2; 32],
            timestamp: 3,
            fact_id: [4; 32],
        };

        let live = SyncHaveIdProjector::new()
            .project_semantic(&fact, have, &ProjectionContext::default())
            .expect("live have-id projection");
        assert!(live
            .effects
            .intents
            .iter()
            .any(|intent| intent.kind.as_str() == SEND_NEEDED_FACT_ID));

        let replayed = SyncHaveIdProjector::new()
            .project_semantic(
                &fact,
                have,
                &ProjectionContext::default().with_mode(ProjectionMode::Replay),
            )
            .expect("replay have-id projection");
        assert!(replayed.effects.row_mutations.is_empty());
        assert!(replayed.effects.intents.is_empty());
    }
}
