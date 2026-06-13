pub mod decode {
    //! Byte decoding for the sync need-id fact.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order.

    use crate::core::wire;

    use super::super::encode::{ENCODED_BYTES, TYPE_SYNC_NEED_ID};
    use super::super::fact::SyncNeedIdFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<SyncNeedIdFact, String> {
        wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_SYNC_NEED_ID {
            return Err("expected sync need-id fact".to_string());
        }
        let mut connection_id = [0; 32];
        connection_id.copy_from_slice(&bytes[1..33]);
        let mut fact_id = [0; 32];
        fact_id.copy_from_slice(&bytes[33..65]);
        Ok(SyncNeedIdFact {
            connection_id,
            fact_id,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::sync::need_id::encode::{encode_fact, ENCODED_BYTES};

        fn fact() -> SyncNeedIdFact {
            SyncNeedIdFact {
                connection_id: [4; 32],
                fact_id: [8; 32],
            }
        }

        #[test]
        fn sync_need_id_roundtrips() {
            let bytes = encode_fact(&fact()).expect("encode");
            assert_eq!(bytes.len(), ENCODED_BYTES);
            assert_eq!(decode_fact(&bytes).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag_and_length() {
            let mut bytes = encode_fact(&fact()).expect("encode");
            bytes[0] = TYPE_SYNC_NEED_ID.wrapping_add(1);
            assert!(decode_fact(&bytes).is_err());

            let mut short = encode_fact(&fact()).expect("encode");
            short.pop();
            assert!(decode_fact(&short).is_err());
        }
    }
}
pub mod authenticate {
    //! Sync need-id authenticator.
    //!
    //! POLICY. Authenticating a `sync_need_id` fact proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical need-id request.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! It proves nothing else. A need-id fact carries no fact-boundary signature;
    //! whether this store can answer the request is idempotent handler work the
    //! projector and its intents own.

    use crate::core::facts::Fact;
    use crate::core::pipeline::{verify_fact_id, ProjectionContext};

    use super::super::fact::SyncNeedIdFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        need: SyncNeedIdFact,
        _context: &ProjectionContext,
    ) -> Result<SyncNeedIdFact, String> {
        prove_decoded_need_id(fact, need)
    }

    fn prove_decoded_need_id(fact: &Fact, need: SyncNeedIdFact) -> Result<SyncNeedIdFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(need)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::pipeline::ProjectionContext;
        use crate::protocol::sync::need_id::author::fact as need_id_fact;
        use crate::protocol::sync::need_id::fact::SyncNeedIdFact;

        fn canonical_fact() -> Fact {
            need_id_fact(
                SyncNeedIdFact {
                    connection_id: [4; 32],
                    fact_id: [8; 32],
                },
                777,
            )
            .expect("need-id fact")
        }

        fn authenticate(fact: &Fact) -> Result<SyncNeedIdFact, String> {
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
    //! Sync need-id semantic adapter.
    //!
    //! The current need_id wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::SyncNeedIdFact;

    pub(crate) fn adapt(source: SyncNeedIdFact) -> Result<SyncNeedIdFact, String> {
        Ok(source)
    }
}

// Poc-10 sync need-id projector.
//
// POLICY. A sync_need_id fact is admitted iff:
//   1. STRUCTURAL. The request payload decodes.
//   2. CONTEXT. No matched context is required; idempotent handler work decides
//      whether this store can answer.
//   3. MATERIALIZE. Write the need-id row and emit deferred send-requested-fact
//      work.
//
// Replay keeps this retained negotiation fact as evidence but does not rebuild
// stale need/have state.

use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::sync::send_requested_fact::{send_requested_fact_intent, SendRequestedFact};

use super::sync_need_id_row;

/// Projector route metadata for the need_id fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("sync::need_id::project::SyncNeedIdProjector");

#[derive(Debug, Clone, Default)]
pub struct SyncNeedIdProjector;

impl SyncNeedIdProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncNeedIdProjector {
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

impl SyncNeedIdProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        need: super::fact::SyncNeedIdFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
        }
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .row_mutation(RowMutation::PutRow(sync_need_id_row(fact.id, &need)?))
            .intent(send_requested_fact_intent(SendRequestedFact {
                need_fact_id: fact.id,
            })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::ProjectionMode;
    use crate::protocol::sync::send_requested_fact::SEND_REQUESTED_FACT;

    #[test]
    fn replay_projection_does_not_rebuild_sync_negotiation_state() {
        let fact = Fact::new(FactScope::Local, 1, vec![1]);
        let need = super::super::fact::SyncNeedIdFact {
            connection_id: [2; 32],
            fact_id: [3; 32],
        };

        let live = SyncNeedIdProjector::new()
            .project_semantic(&fact, need, &ProjectionContext::default())
            .expect("live need-id projection");
        assert!(live
            .effects
            .intents
            .iter()
            .any(|intent| intent.kind.as_str() == SEND_REQUESTED_FACT));

        let replayed = SyncNeedIdProjector::new()
            .project_semantic(
                &fact,
                need,
                &ProjectionContext::default().with_mode(ProjectionMode::Replay),
            )
            .expect("replay need-id projection");
        assert!(replayed.effects.row_mutations.is_empty());
        assert!(replayed.effects.intents.is_empty());
    }
}
