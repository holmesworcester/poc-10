//! Poc-10 connection-request projector.
//!
//! Decodes the canonical request body and emits one `PutRow` keyed by the
//! request fact id. The row captures the endpoint pair and the three
//! dependency edges (invite event, invite secret, initiator ephemeral secret)
//! that downstream handlers need to resolve the request.
//!
//! Legacy parity gaps (intentional, see commit message):
//!
//! - The legacy projector validated a signed envelope produced by the invite
//!   secret key. The target `signed_fact` wrapping for connection requests is
//!   not yet wired here; this projector accepts the raw fact body.
//! - The legacy projector also walked declared dependency context to check the
//!   invite-secret payload, the bootstrap hash, the ephemeral key match, and
//!   the receive-side bootstrap authorization. Those sibling fact modules
//!   (invite, ephemeral secret, receive metadata) have not yet been ported, so
//!   the target projector restricts itself to the row layout it owns.
//! - The legacy projector emitted `pending_connection_attempt`/
//!   `pending_connection_response` work rows. Those belong to handlers, not the
//!   fact-side projector, and land in a later wave.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::connection_request_row;

#[derive(Debug, Clone, Default)]
pub struct ConnectionRequestProjector;

impl ConnectionRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionRequestProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let request = layout::decode_fact(&fact.bytes)?;
        if request.from_endpoint == request.to_endpoint {
            return Err("connection request endpoints must differ".to_string());
        }
        Ok(ProjectionOutput::new().intent(
            AtomicIntent::PutRow(connection_request_row(fact.id, &request)?).into_intent(),
        ))
    }
}
