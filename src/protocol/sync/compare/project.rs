pub mod decode {
    //! Byte decoding for the sync compare fact.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. The
    //! range is validated on decode so an inverted range cannot make it past the
    //! codec.

    use crate::core::wire;

    use super::super::encode::{ENCODED_BYTES, TYPE_SYNC_COMPARE};
    use super::super::fact::{RangeSummary, SyncCompareFact, TimestampRange};

    pub fn decode_fact(bytes: &[u8]) -> Result<SyncCompareFact, String> {
        wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_SYNC_COMPARE {
            return Err("expected sync compare fact".to_string());
        }
        let mut connection_id = [0; 32];
        connection_id.copy_from_slice(&bytes[1..33]);
        let start = wire::take_u64be(&bytes[33..41]).map_err(wire_err)?;
        let end = wire::take_u64be(&bytes[41..49]).map_err(wire_err)?;
        if start > end {
            return Err("sync compare range is inverted".to_string());
        }
        let count = wire::take_u64be(&bytes[49..57]).map_err(wire_err)?;
        let mut fingerprint = [0; 32];
        fingerprint.copy_from_slice(&bytes[57..89]);
        let response_requested = match wire::take_u8(&bytes[89..90]).map_err(wire_err)? {
            0 => false,
            1 => true,
            _ => return Err("sync compare response flag is invalid".to_string()),
        };
        Ok(SyncCompareFact {
            connection_id,
            range: TimestampRange { start, end },
            summary: RangeSummary { count, fingerprint },
            response_requested,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::sync::compare::encode::{encode_fact, ENCODED_BYTES};

        fn fact() -> SyncCompareFact {
            SyncCompareFact {
                connection_id: [4; 32],
                range: TimestampRange { start: 10, end: 20 },
                summary: RangeSummary {
                    count: 3,
                    fingerprint: [7; 32],
                },
                response_requested: true,
            }
        }

        #[test]
        fn sync_compare_roundtrips() {
            let bytes = encode_fact(&fact()).expect("encode");
            assert_eq!(bytes.len(), ENCODED_BYTES);
            assert_eq!(decode_fact(&bytes).expect("decode"), fact());
        }

        #[test]
        fn rejects_inverted_range_on_decode() {
            let mut bytes = encode_fact(&fact()).expect("encode");
            // Swap start/end bytes to make start > end.
            bytes[33..41].copy_from_slice(&u64::MAX.to_be_bytes());
            bytes[41..49].copy_from_slice(&0u64.to_be_bytes());
            assert!(decode_fact(&bytes).is_err());
        }

        #[test]
        fn rejects_invalid_response_flag() {
            let mut bytes = encode_fact(&fact()).expect("encode");
            bytes[89] = 2;
            assert!(decode_fact(&bytes).is_err());
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut bytes = encode_fact(&fact()).expect("encode");
            bytes[0] = TYPE_SYNC_COMPARE.wrapping_add(1);
            assert!(decode_fact(&bytes).is_err());
        }

        #[test]
        fn rejects_truncated_or_extended_bytes() {
            let bytes = encode_fact(&fact()).expect("encode");
            let mut short = bytes.clone();
            short.pop();
            assert!(decode_fact(&short).is_err());
            let mut long = bytes;
            long.push(0);
            assert!(decode_fact(&long).is_err());
        }
    }
}
pub mod authenticate {
    //! Sync-compare authenticator.
    //!
    //! POLICY. Authenticating a `sync_compare` fact proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical sync-compare fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! It proves nothing else. A compare is an unsigned peer summary; whether it
    //! answers a request or continues a response round is deferred handler work the
    //! projector and its intents own.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::SyncCompareFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        compare: SyncCompareFact,
        _context: &ProjectionContext,
    ) -> Result<SyncCompareFact, String> {
        prove_decoded_compare(fact, compare)
    }

    fn prove_decoded_compare(
        fact: &Fact,
        compare: SyncCompareFact,
    ) -> Result<SyncCompareFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(compare)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::sync::compare::author::start_compare_fact_with_summary;
        use crate::protocol::sync::compare::fact::{RangeSummary, SyncCompareFact};

        fn canonical_fact() -> Fact {
            start_compare_fact_with_summary(
                [7; 32],
                RangeSummary {
                    count: 2,
                    fingerprint: [9; 32],
                },
            )
            .expect("start compare fact")
        }

        fn authenticate(fact: &Fact) -> Result<SyncCompareFact, String> {
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
        // authenticator: a compare with a Local scope authenticates here and is
        // rejected downstream.
    }
}
pub mod adapt {
    //! Sync compare semantic adapter.
    //!
    //! The current compare wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::SyncCompareFact;

    pub(crate) fn adapt(source: SyncCompareFact) -> Result<SyncCompareFact, String> {
        Ok(source)
    }
}

// Poc-10 sync compare projector.
//
// POLICY. A sync_compare fact is admitted iff:
//   1. STRUCTURAL. The compare payload decodes with its range summary.
//   2. CONTEXT. No matched context is required; this is a peer summary.
//   3. MATERIALIZE. Write the compare row and emit deferred compare work. The
//      handler decides whether this row answers a peer request or continues a
//      response round.

use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::sync::send_compare_response::{
    send_sync_compare_response_intent, SendSyncCompareResponse,
};

use super::sync_compare_row;

/// Projector route metadata for the compare fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("sync::compare::project::SyncCompareProjector");

#[derive(Debug, Clone, Default)]
pub struct SyncCompareProjector;

impl SyncCompareProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncCompareProjector {
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

impl SyncCompareProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        compare: super::fact::SyncCompareFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 3. Materialize.
        let output = ProjectionOutput::new()
            .row_mutation(RowMutation::PutRow(sync_compare_row(fact.id, &compare)?));
        if context.is_replay() {
            return Ok(output);
        }
        Ok(
            output.intent(send_sync_compare_response_intent(SendSyncCompareResponse {
                compare_fact_id: fact.id,
            })),
        )
    }
}
