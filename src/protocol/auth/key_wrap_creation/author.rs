//! Local key-wrap creation fact construction helpers.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::key_wrap::project::WrapSourceDescriptor;

use super::{encode, fact::KeyWrapCreationFact};

pub fn key_wrap_creation_fact(
    recipient_key_id: FactId,
    source_fact_id: FactId,
    signer_secret_fact_id: FactId,
    source: WrapSourceDescriptor,
) -> Result<Fact, String> {
    let creation = KeyWrapCreationFact {
        workspace_id: source.workspace_id,
        frontier_id: source.frontier_id,
        recipient_key_id,
        source_fact_id,
        signer_secret_fact_id,
        owner_endpoint_id: source.owner_endpoint_id,
        frontier_created_at_ms: source.frontier_created_at_ms,
        source: source.kind,
    };
    let timestamp = creation.frontier_created_at_ms;
    Ok(Fact::new(
        FactScope::Local,
        timestamp,
        encode::encode_fact(&creation)?,
    ))
}
