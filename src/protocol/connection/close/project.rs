pub mod decode {
    //! Byte decoding for connection-close facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id
    //! checks and context validation live in the local `authenticate` module and `project.rs`.

    use crate::core::wire;

    use super::super::encode::{FACT_BYTES, TYPE_CONNECTION_CLOSE};
    use super::super::fact::ConnectionCloseFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionCloseFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_CONNECTION_CLOSE {
            return Err("expected connection close fact".to_string());
        }
        let mut connection_id = [0; 32];
        connection_id.copy_from_slice(&bytes[1..33]);
        let closed_at_ms = wire::take_u64be(&bytes[33..41]).map_err(wire_err)?;
        Ok(ConnectionCloseFact {
            connection_id,
            closed_at_ms,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    //
    // Invariants:
    // - Close bytes have one fixed-width representation.
    // - Decode preserves the target connection id and close timestamp.
    // - Tag and length guards reject malformed close facts.
    //
    // The tests read from the complete layout proof to layout guards.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::connection::close::encode::{
            encode_fact, FACT_BYTES, TYPE_CONNECTION_CLOSE,
        };

        fn fact() -> ConnectionCloseFact {
            ConnectionCloseFact {
                connection_id: [1; 32],
                closed_at_ms: 2,
            }
        }

        #[test]
        fn connection_close_roundtrips_fixed_width() {
            let bytes = encode_fact(&fact()).expect("encode");
            assert_eq!(bytes.len(), FACT_BYTES);
            assert_eq!(decode_fact(&bytes).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag_or_length() {
            let mut bytes = encode_fact(&fact()).expect("encode");
            bytes[0] = TYPE_CONNECTION_CLOSE.wrapping_add(1);
            assert!(decode_fact(&bytes).is_err());

            let mut short = encode_fact(&fact()).expect("encode");
            short.pop();
            assert!(decode_fact(&short).is_err());
        }
    }
}
pub mod authenticate {
    //! Connection-close authenticator.
    //!
    //! POLICY. Authenticating a `connection_close` fact proves, over its bytes
    //! alone:
    //!   1. LAYOUT. The bytes decode to a canonical connection-close fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   FIELDS. The named connection id is non-empty.
    //!
    //! It proves nothing else. Admission scope (`Local`) and the connection
    //! context proof are interpretation the projector owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::ConnectionCloseFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        close: ConnectionCloseFact,
        _context: &ProjectionContext,
    ) -> Result<ConnectionCloseFact, String> {
        prove_decoded_close(fact, close)
    }

    fn prove_decoded_close(
        fact: &Fact,
        close: ConnectionCloseFact,
    ) -> Result<ConnectionCloseFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // Intrinsic fields.
        if close.connection_id == [0; 32] {
            return Err("connection close connection_id cannot be empty".to_string());
        }
        Ok(close)
    }

    // Tests.
    //
    // Invariants:
    // - Authentication admits a canonical close fact naming a non-empty connection.
    // - The fact id is bound to the canonical bytes.
    // - Decode-owned tag and length failures still reject at the authentication
    //   boundary.
    //
    // The tests read from canonical admission to layout and id guards.
    #[cfg(test)]
    mod tests {
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::connection::close::encode;
        use crate::protocol::connection::close::fact::ConnectionCloseFact;

        fn canonical_fact() -> Fact {
            let close = ConnectionCloseFact {
                connection_id: [1; 32],
                closed_at_ms: 2,
            };
            let bytes = encode::encode_fact(&close).expect("encode connection_close fact");
            Fact::new(FactScope::Local, 100, bytes)
        }

        fn authenticate(fact: &Fact) -> Result<ConnectionCloseFact, String> {
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
    //! Connection-close semantic adapter.
    //!
    //! The current close wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::ConnectionCloseFact;

    pub(crate) fn adapt(source: ConnectionCloseFact) -> Result<ConnectionCloseFact, String> {
        Ok(source)
    }
}

// Connection-close projector.
//
// Close projection validates that a local close fact names a materialized
// established connection. It then publishes close context keyed by the
// connection id and by both ephemeral-secret fact ids carried by that state.
//
// POLICY. A connection_close is admitted iff:
//   1. STRUCTURAL. The fact is local and names a non-empty connection id.
//   2. CONTEXT. The exact local connection context for that id is present.
//   3. MATERIALIZE. Publish close offers only; target facts own their own row
//      deletion and self-purge when those offers wake them.

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use crate::protocol::connection::connection;

const CONNECTION_CLOSED_ROLE: &str = "connection_closed";
const CONNECTION_EPHEMERAL_SECRET_CLOSED_ROLE: &str = "connection_ephemeral_secret_closed";

pub fn connection_closed_need(owner: FactId, connection_id: FactId) -> ContextNeed {
    exact_local_need(owner, CONNECTION_CLOSED_ROLE, connection_id)
}

pub fn connection_closed_offer(owner: FactId, connection_id: FactId) -> ContextOffer {
    exact_local_offer(owner, CONNECTION_CLOSED_ROLE, connection_id)
}

pub fn ephemeral_secret_closed_need(owner: FactId, secret_id: FactId) -> ContextNeed {
    exact_local_need(owner, CONNECTION_EPHEMERAL_SECRET_CLOSED_ROLE, secret_id)
}

pub fn ephemeral_secret_closed_offer(owner: FactId, secret_id: FactId) -> ContextOffer {
    exact_local_offer(owner, CONNECTION_EPHEMERAL_SECRET_CLOSED_ROLE, secret_id)
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
        value: Vec::new(),
    }
}

/// Projector route metadata for the close fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("connection::close::project::ConnectionCloseProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct ConnectionCloseProjector;

impl ConnectionCloseProjector {
    pub fn new() -> Self {
        Self
    }
}

// Tests.
//
// Invariants:
// - Close projection accepts only Local close facts.
// - A close fact parks on exact local connection context before it can publish
//   connection_closed context.
// - Once local connection context exists, projection retains the need and emits
//   the close offer without rows, intents, time wakes, or purges.
// - Non-local connection context is rejected rather than materialized.
//
// The tests read from the wait-then-offer contract to scope/context guards.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::project_fact::MatchedContext;
    use crate::protocol::connection::close::encode;
    use crate::protocol::connection::close::fact::ConnectionCloseFact;

    fn close_fact() -> (Fact, ConnectionCloseFact) {
        let close = ConnectionCloseFact {
            connection_id: [8; 32],
            closed_at_ms: 500,
        };
        let fact = Fact::new(
            FactScope::Local,
            close.closed_at_ms,
            encode::encode_fact(&close).expect("encode close"),
        );
        (fact, close)
    }

    fn matched_connection(
        close_fact_id: FactId,
        connection_id: FactId,
        scope: FactScope,
    ) -> MatchedContext {
        let payload = Fact {
            id: connection_id,
            scope,
            timestamp: 100,
            bytes: b"connection-context".to_vec(),
        };
        MatchedContext {
            need: connection::project::connection_need(close_fact_id, connection_id),
            offer: connection::project::connection_offer(connection_id, connection_id),
            payload,
        }
    }

    #[test]
    fn close_parks_until_target_connection_context_exists() {
        let (fact, close) = close_fact();
        let expected_need = connection::project::connection_need(fact.id, close.connection_id);

        let output = ConnectionCloseProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project close without connection context");

        assert_eq!(output.needs, vec![expected_need]);
        assert!(output.offers.is_empty());
        assert!(output.effects.row_mutations.is_empty());
        assert!(output.effects.intents.is_empty());
        assert!(output.effects.purged_facts.is_empty());
        assert!(output.time_wakes.is_empty());
    }

    #[test]
    fn close_with_local_connection_context_emits_connection_closed_offer_only() {
        let (fact, close) = close_fact();
        let expected_need = connection::project::connection_need(fact.id, close.connection_id);
        let context = ProjectionContext::from_matches(vec![matched_connection(
            fact.id,
            close.connection_id,
            FactScope::Local,
        )]);

        let output = ConnectionCloseProjector::new()
            .project(&fact, &context)
            .expect("project close with connection context");

        assert_eq!(output.needs, vec![expected_need]);
        assert_eq!(
            output.offers,
            vec![connection_closed_offer(fact.id, close.connection_id)]
        );
        assert!(output.effects.row_mutations.is_empty());
        assert!(output.effects.intents.is_empty());
        assert!(output.effects.purged_facts.is_empty());
        assert!(output.time_wakes.is_empty());
    }

    #[test]
    fn close_projection_rejects_non_local_close_fact() {
        let (canonical, _) = close_fact();
        let non_local = Fact {
            scope: FactScope::Global,
            ..canonical
        };

        let err = ConnectionCloseProjector::new()
            .project(&non_local, &ProjectionContext::default())
            .expect_err("non-local close should reject");

        assert_eq!(err, "connection close fact must have local scope");
    }

    #[test]
    fn close_projection_rejects_non_local_connection_context() {
        let (fact, close) = close_fact();
        let context = ProjectionContext::from_matches(vec![matched_connection(
            fact.id,
            close.connection_id,
            FactScope::Global,
        )]);

        let err = ConnectionCloseProjector::new()
            .project(&fact, &context)
            .expect_err("non-local connection context should reject");

        assert_eq!(err, "connection close context must be local");
    }
}

impl Projector for ConnectionCloseProjector {
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

impl ConnectionCloseProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        close: super::fact::ConnectionCloseFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see the local authenticate module) proved canonical bytes and the
        // non-empty connection id. Scope is interpretation.
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection close fact must have local scope".to_string());
        }

        // 2. Context.
        let connection_need = connection::project::connection_need(fact.id, close.connection_id);
        let Some(connection_fact) = context.payload_for(&connection_need) else {
            return Ok(ProjectionOutput::new().need(connection_need));
        };
        if connection_fact.scope != FactScope::Local {
            return Err("connection close context must be local".to_string());
        }
        // 3. Materialize close context for the target owners.
        Ok(ProjectionOutput::new()
            .need(connection_need)
            .offer(connection_closed_offer(fact.id, close.connection_id)))
    }
}
