pub mod decode {
    //! Byte decoding for received connection-frame observation facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, field order, and that the
    //! origin addr is canonical. Id checks live in the local `authenticate` module.

    use crate::core::wire::{self, FixedLayout};
    use crate::protocol::connection::fact_receipt::fact::normalize_origin_addr_bytes;
    use crate::protocol::connection::fact_receipt::fact::OriginAddr;

    use super::super::encode::{
        CONNECTION_FRAME_OBSERVATION_FACT_BYTES, FRAME_FACT_OFFSET, ORIGIN_OFFSET,
        RECEIVED_AT_OFFSET, TYPE_CONNECTION_FRAME_OBSERVATION,
    };
    use super::super::fact::ConnectionFrameObservationFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionFrameObservationFact, String> {
        wire::expect_len(bytes, CONNECTION_FRAME_OBSERVATION_FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_CONNECTION_FRAME_OBSERVATION {
            return Err("expected connection frame observation".to_string());
        }
        let origin_addr =
            OriginAddr::decode(&bytes[ORIGIN_OFFSET..RECEIVED_AT_OFFSET]).map_err(wire_err)?;
        let canonical_origin_addr = normalize_origin_addr_bytes(origin_addr.bytes())?;
        if canonical_origin_addr != origin_addr.bytes() {
            return Err("connection frame observation origin addr is not canonical".to_string());
        }
        Ok(ConnectionFrameObservationFact {
            frame_fact_id: bytes[FRAME_FACT_OFFSET..ORIGIN_OFFSET].try_into().unwrap(),
            origin_addr,
            received_at_local_ms: wire::take_u64be(
                &bytes[RECEIVED_AT_OFFSET..CONNECTION_FRAME_OBSERVATION_FACT_BYTES],
            )
            .map_err(wire_err)?,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::connection::frame_observation::encode::{
            encode_fact, CONNECTION_FRAME_OBSERVATION_FACT_BYTES,
        };

        #[test]
        fn connection_frame_observation_roundtrips_fixed_width() {
            let fact = ConnectionFrameObservationFact {
                frame_fact_id: [1; 32],
                origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
                received_at_local_ms: 123,
            };

            let encoded = encode_fact(&fact).expect("encode");

            assert_eq!(encoded.len(), CONNECTION_FRAME_OBSERVATION_FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact);
        }

        #[test]
        fn connection_frame_observation_normalizes_origin_addr() {
            let fact = ConnectionFrameObservationFact {
                frame_fact_id: [1; 32],
                origin_addr: OriginAddr::new(b"127.0.0.1_41001").expect("origin"),
                received_at_local_ms: 123,
            };

            let decoded = decode_fact(&encode_fact(&fact).expect("encode")).expect("decode");

            assert_eq!(decoded.origin_addr.bytes(), b"127.0.0.1:41001");
        }
    }
}
pub mod authenticate {
    //! Connection-frame observation authenticator.
    //!
    //! POLICY. Authenticating a `connection_frame_observation` fact proves, over its
    //! bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical frame-observation payload.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! Observations are unsigned local metadata: there is no fact-boundary signature
    //! and no intrinsic field rule. Admission scope (`Local`) is unsigned metadata,
    //! so the local-scope check stays in the projector, as does publishing
    //! observation context for the observed frame fact.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::ConnectionFrameObservationFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        observed: ConnectionFrameObservationFact,
        _context: &ProjectionContext,
    ) -> Result<ConnectionFrameObservationFact, String> {
        prove_decoded_frame_observation(fact, observed)
    }

    fn prove_decoded_frame_observation(
        fact: &Fact,
        observed: ConnectionFrameObservationFact,
    ) -> Result<ConnectionFrameObservationFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(observed)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::connection::frame_observation::author::fact_from_observation;
        use crate::protocol::connection::frame_observation::fact::ConnectionFrameObservationFact;

        fn canonical_fact() -> Fact {
            fact_from_observation([1; 32], b"127.0.0.1:41001", 100)
                .expect("connection_frame_observation fact")
        }

        fn authenticate(fact: &Fact) -> Result<ConnectionFrameObservationFact, String> {
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
    //! Connection-frame observation semantic adapter.
    //!
    //! The current frame_observation wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::ConnectionFrameObservationFact;

    pub(crate) fn adapt(
        source: ConnectionFrameObservationFact,
    ) -> Result<ConnectionFrameObservationFact, String> {
        Ok(source)
    }
}

// Connection-frame observation projector.
//
// POLICY. A `connection_frame_observation` fact is admitted iff:
//   1. STRUCTURAL. The fact is local-only and its payload names one frame fact
//      plus canonical receive metadata.
//   2. CONTEXT. No external authority is loaded; the matching frame projector
//      validates and opens the frame bytes.
//   3. MATERIALIZE. Publish local `connection_frame_observation` context keyed
//      by the observed frame fact id.

use crate::core::context::ContextOffer;
use crate::core::facts::{Fact, FactScope};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use super::fact::ConnectionFrameObservationFact;

/// Projector route metadata for the frame_observation fact.
pub const PROJECTOR_INFO: FactProjectorInfo = FactProjectorInfo::projector(
    "connection::frame_observation::project::ConnectionFrameObservationProjector",
);

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::update::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct ConnectionFrameObservationProjector;

impl ConnectionFrameObservationProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFrameObservationProjector {
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

impl ConnectionFrameObservationProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        observed: ConnectionFrameObservationFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection frame observation must have local scope".to_string());
        }

        // 2. Context.
        // 3. Materialize.
        Ok(ProjectionOutput::new().offer(ContextOffer::range(
            fact.id,
            "connection_frame_observation",
            FactScope::Local,
            observed.frame_fact_id,
            observed.frame_fact_id,
        )))
    }
}
