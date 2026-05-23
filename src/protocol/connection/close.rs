//! Connection close fact family.
//!
//! A close fact is the local event that retires a materialized connection. It
//! names a connection-response fact id, waits for exact local connection
//! context, then publishes close context for that connection and for the
//! initiator/responder ephemeral-secret fact ids referenced by the response.
//!
//! The close fact does not delete material itself. The target fact families keep
//! standing close needs, then delete their own rows and purge their own fact
//! bytes after close context arrives. Change this family for close fact bytes or
//! close-context coordinates; change the target projectors for target-specific
//! cleanup.

pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use crate::core::facts::{FactId, FactScope};

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
    }
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionCloseFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionCloseFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
