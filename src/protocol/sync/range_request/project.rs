pub mod decode {
    //! Byte decoding for sync range requests.
    //!
    //! Decoding proves only the fixed layout: tag, length, field order, and that
    //! the range is not inverted. It does not decide whether the peer may receive
    //! the range.

    use crate::core::wire;

    use super::super::encode::{encode_fact, ENCODED_BYTES, TYPE_SYNC_RANGE_REQUEST};
    use super::super::fact::SyncRangeRequestFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<SyncRangeRequestFact, String> {
        wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_SYNC_RANGE_REQUEST {
            return Err("expected sync range request".to_string());
        }
        let fact = SyncRangeRequestFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            connection_id: bytes[33..65].try_into().unwrap(),
            start: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
            end: wire::take_u64be(&bytes[73..81]).map_err(wire_err)?,
        };
        encode_fact(&fact)?;
        Ok(fact)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    //
    // Invariants:
    // - Range-request bytes have one fixed-width representation.
    // - Decode preserves workspace, connection, and inclusive timestamp bounds.
    // - Inverted ranges are rejected before projection.
    //
    // The tests read from the full layout proof to the range-order guard.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::sync::range_request::encode::{encode_fact, ENCODED_BYTES};

        #[test]
        fn sync_range_request_roundtrips_fixed_width() {
            let fact = SyncRangeRequestFact {
                workspace_id: [1; 32],
                connection_id: [2; 32],
                start: 10,
                end: 20,
            };

            let encoded = encode_fact(&fact).expect("encode sync range request");

            assert_eq!(encoded.len(), ENCODED_BYTES);
            assert_eq!(
                decode_fact(&encoded).expect("decode sync range request"),
                fact
            );
        }

        #[test]
        fn sync_range_request_rejects_inverted_range() {
            let mut encoded = vec![0; ENCODED_BYTES];
            encoded[0] = super::super::super::encode::TYPE_SYNC_RANGE_REQUEST;
            encoded[1..33].copy_from_slice(&[1; 32]);
            encoded[33..65].copy_from_slice(&[2; 32]);
            crate::core::wire::put_u64be(20, &mut encoded[65..73]).expect("start");
            crate::core::wire::put_u64be(10, &mut encoded[73..81]).expect("end");

            let err = decode_fact(&encoded).expect_err("inverted range should reject");

            assert_eq!(err, "sync range request is inverted");
        }
    }
}
pub mod authenticate {
    //! Sync range-request authenticator.
    //!
    //! POLICY. Authenticating a `sync_range_request` fact proves, over its bytes
    //! alone:
    //!   1. LAYOUT. The bytes decode to a canonical range-request fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! It proves nothing else. Admission scope (the requested workspace) is unsigned
    //! local metadata, so the workspace-scope check is interpretation the projector
    //! owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::SyncRangeRequestFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        request: SyncRangeRequestFact,
        _context: &ProjectionContext,
    ) -> Result<SyncRangeRequestFact, String> {
        prove_decoded_range_request(fact, request)
    }

    fn prove_decoded_range_request(
        fact: &Fact,
        request: SyncRangeRequestFact,
    ) -> Result<SyncRangeRequestFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(request)
    }

    // Tests.
    //
    // Invariants:
    // - Authentication admits canonical range requests.
    // - The fact id is bound to the canonical bytes.
    // - Decode-owned tag and length failures still reject at the authentication
    //   boundary.
    // - Admission scope is unsigned metadata and is checked by projection, not
    //   authentication.
    //
    // The tests read from canonical admission to id and layout guards.
    #[cfg(test)]
    mod tests {
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::sync::range_request::encode;
        use crate::protocol::sync::range_request::fact::SyncRangeRequestFact;

        fn canonical_fact() -> Fact {
            let request = SyncRangeRequestFact {
                workspace_id: [1; 32],
                connection_id: [2; 32],
                start: 10,
                end: 20,
            };
            Fact::new(
                FactScope::Global,
                10,
                encode::encode_fact(&request).expect("encode sync range request"),
            )
        }

        fn authenticate(fact: &Fact) -> Result<SyncRangeRequestFact, String> {
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

        // Admission scope is interpretation, checked by the projector, not the
        // authenticator: a range request with a Local scope authenticates here and
        // is rejected downstream.
    }
}
pub mod adapt {
    //! Sync range-request semantic adapter.
    //!
    //! The current range_request wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::SyncRangeRequestFact;

    pub(crate) fn adapt(source: SyncRangeRequestFact) -> Result<SyncRangeRequestFact, String> {
        Ok(source)
    }
}

// Projector for sync range requests.
//
// POLICY. A sync range_request fact is admitted iff:
//   1. STRUCTURAL. The request payload decodes and its fact scope matches the
//      requested workspace.
//   2. MATERIALIZE. The fact records no rows; full-range connect sync and
//      progressive send own transfer for this protocol slice.

use crate::core::facts::{Fact, FactScope};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

/// Projector route metadata for the range_request fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("sync::range_request::project::SyncRangeRequestProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct SyncRangeRequestProjector;

impl SyncRangeRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncRangeRequestProjector {
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

impl SyncRangeRequestProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        request: super::fact::SyncRangeRequestFact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(request.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Materialize.
        Ok(ProjectionOutput::new())
    }
}

fn require_fact_scope(fact: &Fact, expected: &FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sync context fact scope does not match body workspace".to_string())
    }
}

// Tests.
//
// Invariants:
// - Range-request projection accepts only the workspace scope named in the body.
// - Projection intentionally emits no rows, needs, offers, intents, wakes, or
//   purges; compare/send handlers own transfer planning.
//
// The tests prove the empty materialization contract first, then the scope guard.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sync::range_request::encode;
    use crate::protocol::sync::range_request::fact::SyncRangeRequestFact;

    fn range_request_fact() -> Fact {
        let request = SyncRangeRequestFact {
            workspace_id: [1; 32],
            connection_id: [2; 32],
            start: 10,
            end: 20,
        };
        Fact::new(
            crate::protocol::auth::workspace::scope(request.workspace_id),
            100,
            encode::encode_fact(&request).expect("encode range request"),
        )
    }

    #[test]
    fn range_request_with_matching_workspace_scope_projects_empty_output() {
        let fact = range_request_fact();

        let output = SyncRangeRequestProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project range request");

        assert!(output.needs.is_empty());
        assert!(output.offers.is_empty());
        assert!(output.row_mutations.is_empty());
        assert!(output.effects.intents.is_empty());
        assert!(output.effects.purged_facts.is_empty());
        assert!(output.time_wakes.is_empty());
    }

    #[test]
    fn range_request_projection_rejects_scope_that_does_not_match_workspace() {
        let canonical = range_request_fact();
        let wrong_scope = Fact {
            scope: FactScope::Global,
            ..canonical
        };

        let err = SyncRangeRequestProjector::new()
            .project(&wrong_scope, &ProjectionContext::default())
            .expect_err("wrong scope should reject");

        assert_eq!(err, "sync context fact scope does not match body workspace");
    }
}
