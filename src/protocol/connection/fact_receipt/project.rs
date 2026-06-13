pub mod decode {
    //! Byte decoding for connection fact receipts.
    //!
    //! Decoding proves only the fixed layout: tag, length, field order, canonical
    //! origin-address form, and a known receive path. It adds no semantic
    //! validation; received-payload admission belongs to the owning fact projector.

    use crate::core::wire;
    use crate::core::wire::{FixedLayout, FixedSlot};

    use super::super::encode::{
        CONNECTION_FACT_RECEIPT_BYTES, CONNECTION_ID_OFFSET, FRAME_HASH_OFFSET,
        HAS_CONNECTION_OFFSET, HAS_REQUEST_OFFSET, LOCAL_ENDPOINT_OFFSET, ORIGIN_OFFSET,
        RECEIVED_AT_OFFSET, RECEIVED_FACT_OFFSET, RECEIVE_PATH_OFFSET, REQUEST_ID_OFFSET,
        SENDER_ENDPOINT_OFFSET, TYPE_CONNECTION_FACT_RECEIPT,
    };
    use super::super::fact::{
        normalize_origin_addr_bytes, ConnectionFactReceipt, OriginAddr, ORIGIN_ADDR_BYTES,
        RECEIVE_PATH_CONNECTION, RECEIVE_PATH_CONNECTION_FRAME, RECEIVE_PATH_CONNECTION_REQUEST,
    };

    pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionFactReceipt, String> {
        wire::expect_len(bytes, CONNECTION_FACT_RECEIPT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_CONNECTION_FACT_RECEIPT {
            return Err("expected connection fact receipt".to_string());
        }
        let origin_addr =
            FixedSlot::<ORIGIN_ADDR_BYTES>::decode(&bytes[ORIGIN_OFFSET..LOCAL_ENDPOINT_OFFSET])
                .map_err(wire_err)?
                .bytes()
                .to_vec();
        let canonical_origin_addr = normalize_origin_addr_bytes(&origin_addr)?;
        if canonical_origin_addr != origin_addr {
            return Err("connection fact receipt origin addr is not canonical".to_string());
        }
        let receive_path =
            wire::take_u8(&bytes[RECEIVE_PATH_OFFSET..HAS_CONNECTION_OFFSET]).map_err(wire_err)?;
        validate_receive_path(receive_path)?;
        let has_connection = wire::take_bool8(&bytes[HAS_CONNECTION_OFFSET..CONNECTION_ID_OFFSET])
            .map_err(wire_err)?;
        let connection_id = has_connection.then(|| {
            bytes[CONNECTION_ID_OFFSET..HAS_REQUEST_OFFSET]
                .try_into()
                .unwrap()
        });
        let has_request =
            wire::take_bool8(&bytes[HAS_REQUEST_OFFSET..REQUEST_ID_OFFSET]).map_err(wire_err)?;
        let request_id = has_request.then(|| {
            bytes[REQUEST_ID_OFFSET..FRAME_HASH_OFFSET]
                .try_into()
                .unwrap()
        });
        Ok(ConnectionFactReceipt {
            received_fact_id: bytes[RECEIVED_FACT_OFFSET..ORIGIN_OFFSET]
                .try_into()
                .unwrap(),
            origin_addr: OriginAddr::new(&origin_addr).map_err(wire_err)?,
            local_endpoint_id: bytes[LOCAL_ENDPOINT_OFFSET..SENDER_ENDPOINT_OFFSET]
                .try_into()
                .unwrap(),
            sender_endpoint_id: bytes[SENDER_ENDPOINT_OFFSET..RECEIVE_PATH_OFFSET]
                .try_into()
                .unwrap(),
            receive_path,
            connection_id,
            request_id,
            frame_hash: bytes[FRAME_HASH_OFFSET..RECEIVED_AT_OFFSET]
                .try_into()
                .unwrap(),
            received_at_local_ms: wire::take_u64be(
                &bytes[RECEIVED_AT_OFFSET..CONNECTION_FACT_RECEIPT_BYTES],
            )
            .map_err(wire_err)?,
        })
    }

    pub(crate) fn validate_receive_path(path: u8) -> Result<(), String> {
        match path {
            RECEIVE_PATH_CONNECTION_REQUEST
            | RECEIVE_PATH_CONNECTION_FRAME
            | RECEIVE_PATH_CONNECTION => Ok(()),
            other => Err(format!("unknown connection receive path {other}")),
        }
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::connection::fact_receipt::encode::{
            encode_fact, CONNECTION_FACT_RECEIPT_BYTES, ORIGIN_OFFSET, TYPE_CONNECTION_FACT_RECEIPT,
        };

        fn fact() -> ConnectionFactReceipt {
            ConnectionFactReceipt {
                received_fact_id: [1; 32],
                origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
                local_endpoint_id: [2; 32],
                sender_endpoint_id: [3; 32],
                receive_path: RECEIVE_PATH_CONNECTION,
                connection_id: Some([4; 32]),
                request_id: Some([6; 32]),
                frame_hash: [5; 32],
                received_at_local_ms: 1_700_000_001,
            }
        }

        #[test]
        fn fact_receipt_roundtrips_fixed_width() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), CONNECTION_FACT_RECEIPT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn fact_receipt_encode_normalizes_friendly_origin_addr() {
            let mut fact = fact();
            fact.origin_addr = OriginAddr::new(b"127.0.0.1_41001").expect("origin");
            let encoded = encode_fact(&fact).expect("encode");
            let decoded = decode_fact(&encoded).expect("decode");

            assert_eq!(decoded.origin_addr.bytes(), b"127.0.0.1:41001");
        }

        #[test]
        fn fact_receipt_decode_rejects_noncanonical_origin_addr() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            let friendly = b"127.0.0.1_41001";
            encoded[ORIGIN_OFFSET..ORIGIN_OFFSET + 4]
                .copy_from_slice(&(friendly.len() as u32).to_be_bytes());
            encoded[ORIGIN_OFFSET + 4..ORIGIN_OFFSET + 4 + friendly.len()]
                .copy_from_slice(friendly);

            let err = decode_fact(&encoded).expect_err("noncanonical origin should fail");
            assert!(err.contains("not canonical"), "{err}");
        }

        #[test]
        fn fact_receipt_roundtrips_without_connection() {
            let fact = ConnectionFactReceipt {
                receive_path: RECEIVE_PATH_CONNECTION_REQUEST,
                connection_id: None,
                request_id: None,
                ..fact()
            };
            let encoded = encode_fact(&fact).expect("encode");
            assert_eq!(decode_fact(&encoded).expect("decode"), fact);
        }

        #[test]
        fn rejects_wrong_tag_or_length() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = TYPE_CONNECTION_FACT_RECEIPT.wrapping_add(1);
            assert!(decode_fact(&encoded).is_err());

            let mut short = encode_fact(&fact()).expect("encode");
            short.pop();
            assert!(decode_fact(&short).is_err());
        }

        #[test]
        fn rejects_unknown_receive_path() {
            let fact = ConnectionFactReceipt {
                receive_path: 99,
                ..fact()
            };
            assert!(encode_fact(&fact).is_err());
        }

        #[test]
        fn rejects_invalid_origin_addr() {
            let fact = ConnectionFactReceipt {
                origin_addr: OriginAddr::new(b"not-a-socket-addr").expect("origin"),
                ..fact()
            };
            assert!(encode_fact(&fact).is_err());
        }
    }
}
pub mod authenticate {
    //! Connection fact-receipt authenticator.
    //!
    //! POLICY. Authenticating a `connection_fact_receipt` fact proves, over its
    //! bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical fact-receipt payload.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! Receipts are unsigned local evidence: there is no fact-boundary signature and
    //! no intrinsic field rule. Admission scope (`Local`) is unsigned metadata, so
    //! the local-scope check stays in the projector, as does publishing receipt
    //! context for the received fact.

    use crate::core::facts::Fact;
    use crate::core::pipeline::{verify_fact_id, ProjectionContext};

    use super::super::fact::ConnectionFactReceipt;

    pub(crate) fn authenticate(
        fact: &Fact,
        received: ConnectionFactReceipt,
        _context: &ProjectionContext,
    ) -> Result<ConnectionFactReceipt, String> {
        prove_decoded_fact_receipt(fact, received)
    }

    fn prove_decoded_fact_receipt(
        fact: &Fact,
        received: ConnectionFactReceipt,
    ) -> Result<ConnectionFactReceipt, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(received)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::{Fact, FactScope};
        use crate::core::pipeline::ProjectionContext;
        use crate::protocol::connection::fact_receipt::encode;
        use crate::protocol::connection::fact_receipt::fact::{
            ConnectionFactReceipt, OriginAddr, RECEIVE_PATH_CONNECTION,
        };

        fn canonical_fact() -> Fact {
            let receipt = ConnectionFactReceipt {
                received_fact_id: [1; 32],
                origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
                local_endpoint_id: [2; 32],
                sender_endpoint_id: [3; 32],
                receive_path: RECEIVE_PATH_CONNECTION,
                connection_id: Some([4; 32]),
                request_id: Some([6; 32]),
                frame_hash: [5; 32],
                received_at_local_ms: 1_700_000_001,
            };
            Fact::new(
                FactScope::Local,
                100,
                encode::encode_fact(&receipt).expect("encode receipt"),
            )
        }

        fn authenticate(fact: &Fact) -> Result<ConnectionFactReceipt, String> {
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
    //! Connection fact-receipt semantic adapter.
    //!
    //! The current fact_receipt wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::ConnectionFactReceipt;

    pub(crate) fn adapt(source: ConnectionFactReceipt) -> Result<ConnectionFactReceipt, String> {
        Ok(source)
    }
}

// Connection fact-receipt projector.
//
// Receipts publish local observation context for the semantic fact they
// mention. Projection does not inspect the received payload; it only validates
// that the receipt is local, decodes cleanly, and can offer
// `connection_fact_receipt` context keyed by `received_fact_id`.
//
// POLICY. A connection_fact_receipt is admitted iff:
//   1. STRUCTURAL. The fact is local-only and its receipt payload decodes.
//   2. CONTEXT. No authority context is loaded here; higher-level projectors
//      validate the receipt against their target fact.
//   3. MATERIALIZE. Publish a local connection_fact_receipt offer for the
//      received fact so the owning projector can continue.
//
// Change this projector when receipt context shape changes. Request, response,
// and frame-child projectors own the path-specific proof that consumes the
// offer.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};

pub fn connection_fact_receipt_for_path(
    input: super::fact::ReceiptPathInput<'_>,
) -> Result<Fact, String> {
    let fact = super::fact::ConnectionFactReceipt {
        received_fact_id: input.received_fact_id,
        origin_addr: super::fact::OriginAddr::new(input.origin_addr)
            .map_err(|err| format!("connection fact receipt origin addr: {err}"))?,
        local_endpoint_id: input.local_endpoint_id,
        sender_endpoint_id: input.sender_endpoint_id,
        receive_path: input.receive_path,
        connection_id: input.connection_id,
        request_id: input.request_id,
        frame_hash: input.frame_hash,
        received_at_local_ms: input.received_at_local_ms,
    };
    Ok(Fact::new(
        FactScope::Local,
        input.received_at_local_ms,
        super::encode::encode_fact(&fact)?,
    ))
}

pub(crate) fn validate_local_receipt_scope(fact: &Fact) -> Result<(), String> {
    if fact.scope != FactScope::Local {
        return Err("connection fact receipt must have local scope".to_string());
    }
    Ok(())
}

/// Projector route metadata for the fact_receipt fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("connection::fact_receipt::project::ConnectionFactReceiptProjector");

#[derive(Debug, Clone, Default)]
pub struct ConnectionFactReceiptProjector;

impl ConnectionFactReceiptProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFactReceiptProjector {
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

impl ConnectionFactReceiptProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        received: super::fact::ConnectionFactReceipt,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        validate_local_receipt_scope(fact)?;
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "connection_fact_receipt",
                crate::core::facts::FactScope::Local,
                received.received_fact_id,
                received.received_fact_id,
            ))
            .row_mutation(RowMutation::PutRow(super::connection_fact_receipt_row(
                fact.id, &received,
            )?)))
    }
}
