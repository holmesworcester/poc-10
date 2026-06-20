pub mod decode {
    //! Byte decoding for local connection ephemeral-secret facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Keypair
    //! validation lives in the local `authenticate` module, and admission policy in `project.rs`.

    use crate::core::crypto::{X25519_PRIVATE_KEY_BYTES, X25519_PUBLIC_KEY_BYTES};
    use crate::core::wire;

    use super::super::encode::{FACT_BYTES, TYPE_CONNECTION_EPHEMERAL_SECRET};
    use super::super::fact::ConnectionEphemeralSecretFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionEphemeralSecretFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_CONNECTION_EPHEMERAL_SECRET {
            return Err("expected connection ephemeral secret fact".to_string());
        }
        let mut owner_endpoint = [0; 32];
        owner_endpoint.copy_from_slice(&bytes[1..33]);
        let mut ephemeral_private_key = [0; X25519_PRIVATE_KEY_BYTES];
        ephemeral_private_key.copy_from_slice(&bytes[33..65]);
        let mut ephemeral_public_key = [0; X25519_PUBLIC_KEY_BYTES];
        ephemeral_public_key.copy_from_slice(&bytes[65..97]);
        let created_at_ms = wire::take_u64be(&bytes[97..105]).map_err(wire_err)?;
        Ok(ConnectionEphemeralSecretFact {
            owner_endpoint,
            ephemeral_private_key,
            ephemeral_public_key,
            created_at_ms,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::connection::ephemeral_secret::encode::{
            encode_fact, FACT_BYTES, TYPE_CONNECTION_EPHEMERAL_SECRET,
        };

        fn fact() -> ConnectionEphemeralSecretFact {
            ConnectionEphemeralSecretFact {
                owner_endpoint: [1; 32],
                ephemeral_private_key: [2; X25519_PRIVATE_KEY_BYTES],
                ephemeral_public_key: [3; X25519_PUBLIC_KEY_BYTES],
                created_at_ms: 4,
            }
        }

        #[test]
        fn roundtrip_fixed_width() {
            let bytes = encode_fact(&fact()).expect("encode");
            assert_eq!(bytes.len(), FACT_BYTES);
            assert_eq!(decode_fact(&bytes).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag_or_length() {
            let mut bytes = encode_fact(&fact()).expect("encode");
            bytes[0] = TYPE_CONNECTION_EPHEMERAL_SECRET.wrapping_add(1);
            assert!(decode_fact(&bytes).is_err());

            let mut short = encode_fact(&fact()).expect("encode");
            short.pop();
            assert!(decode_fact(&short).is_err());
        }
    }
}
pub mod authenticate {
    //! Connection ephemeral-secret authenticator.
    //!
    //! POLICY. Authenticating a `connection_ephemeral_secret` fact proves, over its
    //! bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical ephemeral-secret fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   FIELDS. The stored public key re-derives from the private key.
    //!
    //! It proves nothing else. Admission scope (`Local`) and the close gate are
    //! interpretation the projector owns.

    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::ConnectionEphemeralSecretFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        secret: ConnectionEphemeralSecretFact,
        _context: &ProjectionContext,
    ) -> Result<ConnectionEphemeralSecretFact, String> {
        prove_decoded_ephemeral_secret(fact, secret)
    }

    fn prove_decoded_ephemeral_secret(
        fact: &Fact,
        secret: ConnectionEphemeralSecretFact,
    ) -> Result<ConnectionEphemeralSecretFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // Intrinsic fields.
        if crypto::x25519_public_key(&secret.ephemeral_private_key) != secret.ephemeral_public_key {
            return Err("connection ephemeral public key does not match private key".to_string());
        }
        Ok(secret)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::crypto;
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::connection::ephemeral_secret::encode;
        use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;

        const PRIVATE_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            let secret = ConnectionEphemeralSecretFact {
                owner_endpoint: [1; 32],
                ephemeral_private_key: PRIVATE_KEY,
                ephemeral_public_key: crypto::x25519_public_key(&PRIVATE_KEY),
                created_at_ms: 4,
            };
            Fact::new(
                FactScope::Local,
                100,
                encode::encode_fact(&secret).expect("encode ephemeral secret"),
            )
        }

        fn authenticate(fact: &Fact) -> Result<ConnectionEphemeralSecretFact, String> {
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
    //! Connection ephemeral-secret semantic adapter.
    //!
    //! The current ephemeral_secret wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::ConnectionEphemeralSecretFact;

    pub(crate) fn adapt(
        source: ConnectionEphemeralSecretFact,
    ) -> Result<ConnectionEphemeralSecretFact, String> {
        Ok(source)
    }
}

// Connection ephemeral-secret projector.
//
// Ephemeral secrets are local handshake capabilities. Projection turns live
// local secret facts into durable local rows plus exact context offers that
// request/connection projectors can match by secret fact id. When a connection
// close fact names the secret, the same owner deletes its row and purges its
// own fact bytes.
//
// POLICY. A connection_ephemeral_secret is admitted iff:
//   1. STRUCTURAL. The local-only body decodes and the stored public key
//      re-derives from the private key.
//   2. CONTEXT. If exact close context is present, it must be a local
//      connection_close fact.
//   3. MATERIALIZE. Live secrets publish a local ephemeral-secret offer and
//      write the row keyed by this fact id. Closed secrets delete the row and
//      purge their own fact bytes.
//
// Change this file when the local capability proof or materialized row changes.
// Request and connection projectors own the context checks that consume this
// offer.

use crate::core::context::ContextOffer;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{RowMutation, Value};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use super::{connection_ephemeral_secret_row, CONNECTION_EPHEMERAL_SECRET_TABLE};
use crate::protocol::connection::close;

/// Projector route metadata for the ephemeral_secret fact.
pub const PROJECTOR_INFO: FactProjectorInfo = FactProjectorInfo::projector(
    "connection::ephemeral_secret::project::ConnectionEphemeralSecretProjector",
);

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);
pub const CONNECTION_EPHEMERAL_SECRET_ROLE: &str = "connection_ephemeral_secret";
pub const CONNECTION_EPHEMERAL_SECRET_PUBLIC_KEY_ROLE: &str =
    "connection_ephemeral_secret_public_key";

#[derive(Debug, Clone, Default)]
pub struct ConnectionEphemeralSecretProjector;

impl ConnectionEphemeralSecretProjector {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod project_tests {
    use super::*;
    use crate::core::crypto;
    use crate::core::facts::FactId;
    use crate::protocol::connection::ephemeral_secret::encode;
    use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;

    fn secret_fact() -> (Fact, ConnectionEphemeralSecretFact) {
        let ephemeral_private_key = [2; 32];
        let secret = ConnectionEphemeralSecretFact {
            owner_endpoint: [1; 32],
            ephemeral_private_key,
            ephemeral_public_key: crypto::x25519_public_key(&ephemeral_private_key),
            created_at_ms: 3,
        };
        (
            Fact::new(
                FactScope::Local,
                3,
                encode::encode_fact(&secret).expect("ephemeral secret"),
            ),
            secret,
        )
    }

    fn assert_exact_offer(output: &ProjectionOutput, role: &str, key: FactId) {
        let offer = output
            .offers
            .iter()
            .find(|offer| offer.role.as_str() == role)
            .expect("offer role");
        assert_eq!(offer.start_key.as_bytes(), key);
        assert_eq!(offer.end_key.as_bytes(), key);
    }

    #[test]
    fn live_secret_offers_fact_id_and_public_key_context() {
        let (fact, secret) = secret_fact();
        let output = ConnectionEphemeralSecretProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project ephemeral secret");

        assert_exact_offer(&output, CONNECTION_EPHEMERAL_SECRET_ROLE, fact.id);
        assert_exact_offer(
            &output,
            CONNECTION_EPHEMERAL_SECRET_PUBLIC_KEY_ROLE,
            secret.ephemeral_public_key,
        );
    }
}

impl Projector for ConnectionEphemeralSecretProjector {
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

impl ConnectionEphemeralSecretProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        secret: super::fact::ConnectionEphemeralSecretFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see the local authenticate module) proved canonical bytes and that
        // the public key re-derives from the private key. Scope is interpretation.
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection ephemeral secret fact must have local scope".to_string());
        }

        // 2. Close gate.
        let close_need = close::ephemeral_secret_closed_need(fact.id, fact.id);
        if let Some(close_fact) = _context.payload_for(&close_need) {
            if close_fact.scope != FactScope::Local {
                return Err("connection ephemeral close context must be local".to_string());
            }
            let close = close::decode_fact_payload(close_fact.body()).map_err(|_| {
                "connection ephemeral close context is not a connection close".to_string()
            })?;
            if close.connection_id == [0; 32] {
                return Err("connection ephemeral close context has empty connection".to_string());
            }
            return Ok(ProjectionOutput::new()
                .row_mutation(RowMutation::DeleteWhere(
                    CONNECTION_EPHEMERAL_SECRET_TABLE
                        .delete_by_key(vec![Value::Bytes(fact.id.to_vec())]),
                ))
                .purge_self(fact.id));
        }

        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .need(close_need)
            .offer(ContextOffer::range(
                fact.id,
                CONNECTION_EPHEMERAL_SECRET_ROLE,
                FactScope::Local,
                fact.id,
                fact.id,
            ))
            .offer(ContextOffer::range(
                fact.id,
                CONNECTION_EPHEMERAL_SECRET_PUBLIC_KEY_ROLE,
                FactScope::Local,
                secret.ephemeral_public_key,
                secret.ephemeral_public_key,
            ))
            .row_mutation(RowMutation::InsertValues(connection_ephemeral_secret_row(
                fact.id, &secret,
            ))))
    }
}
