//! Poc-10 connection ephemeral-secret projector.
//!
//! Decodes the canonical body, checks the recorded public key matches the
//! recorded private key (the legacy invariant), and emits a single `PutRow`
//! keyed by the secret fact id.
//!
//! This fact is local-only (`FactScope::Local`): the ephemeral private key
//! never leaves the originating node.

use crate::core::crypto;
use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::matchers;

use super::layout;
use super::rows::connection_ephemeral_secret_row;

#[derive(Debug, Clone, Default)]
pub struct ConnectionEphemeralSecretProjector;

impl ConnectionEphemeralSecretProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionEphemeralSecretProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let secret = layout::decode_fact(fact.body())?;
        if crypto::x25519_public_key(&secret.ephemeral_private_key) != secret.ephemeral_public_key {
            return Err("connection ephemeral public key does not match private key".to_string());
        }
        Ok(ProjectionOutput::new()
            .offer(matchers::connection_ephemeral_secret_offer(
                fact.id, fact.id,
            ))
            .intent(
                AtomicIntent::PutRow(connection_ephemeral_secret_row(fact.id, &secret)?)
                    .into_intent(),
            ))
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto::{self, X25519_PRIVATE_KEY_BYTES, X25519_PUBLIC_KEY_BYTES};
    use topo::core::facts::{Fact, FactScope};
    use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::facts::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
    use topo::protocol::facts::connection::ephemeral_secret::{layout, project, rows};

    fn secret_fact() -> ConnectionEphemeralSecretFact {
        let private_key = [7u8; X25519_PRIVATE_KEY_BYTES];
        let public_key = crypto::x25519_public_key(&private_key);
        ConnectionEphemeralSecretFact {
            owner_endpoint: [1; 32],
            ephemeral_private_key: private_key,
            ephemeral_public_key: public_key,
            created_at_ms: 9,
        }
    }

    #[test]
    fn connection_ephemeral_secret_projector_materializes_row_through_atomic_intent() {
        let secret = secret_fact();
        let fact = Fact::new(
            FactScope::Local,
            0,
            layout::encode_fact(&secret).expect("encode secret"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::ConnectionEphemeralSecretProjector::new(),
                &[],
                &store,
                &[rows::CONNECTION_EPHEMERAL_SECRET_ROWS],
                10,
            )
            .expect("project connection ephemeral secret");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 1);
        assert!(bus.intents().is_empty());

        let stored = store
            .table_rows(rows::CONNECTION_EPHEMERAL_SECRET_ROWS)
            .expect("connection ephemeral secret rows");
        assert_eq!(stored.len(), 1);
        let row = rows::decode_connection_ephemeral_secret_row(&stored[0].0, &stored[0].1)
            .expect("decode connection ephemeral secret row");
        assert_eq!(row.secret_id, fact.id);
        assert_eq!(row.owner_endpoint, secret.owner_endpoint);
        assert_eq!(row.ephemeral_private_key, secret.ephemeral_private_key);
        assert_eq!(row.ephemeral_public_key, secret.ephemeral_public_key);
        assert_eq!(row.created_at_ms, secret.created_at_ms);
    }

    #[test]
    fn connection_ephemeral_secret_projector_rejects_mismatched_public_key() {
        let mut secret = secret_fact();
        secret.ephemeral_public_key = [0u8; X25519_PUBLIC_KEY_BYTES];
        let fact = Fact::new(
            FactScope::Local,
            0,
            layout::encode_fact(&secret).expect("encode secret"),
        );
        let mut bus = WakeLoop::new();
        assert!(bus.submit_fact(fact));
        let err = bus
            .drain(&project::ConnectionEphemeralSecretProjector::new(), &[], 10)
            .expect_err("mismatched public key must fail projection");
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn connection_ephemeral_secret_projector_rejects_malformed_bytes() {
        let fact = Fact::new(FactScope::Local, 0, vec![0; 4]);
        let mut bus = WakeLoop::new();
        assert!(bus.submit_fact(fact));
        let err = bus
            .drain(&project::ConnectionEphemeralSecretProjector::new(), &[], 10)
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.contains("connection ephemeral secret") || err.contains("Length"),
            "{err}"
        );
    }
}
