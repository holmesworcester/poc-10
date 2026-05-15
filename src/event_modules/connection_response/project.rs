//! Poc-10 connection-response projector.
//!
//! Decodes the canonical response body and emits one `PutRow` keyed by the
//! response fact id (which is the connection id). The row carries the endpoint
//! pair, the answered request id, the responder ephemeral public key, the
//! public handshake hash, and the connection secret.
//!
//! Legacy parity gaps (intentional, see commit message):
//!
//! - The legacy projector validated a signed envelope over the response body
//!   and required the request dependency to confirm the endpoint pair and
//!   bootstrap context. The target `signed_fact` envelope and the sibling
//!   connection_request projector are not yet wired into context here.
//! - The legacy projector reconciled receive metadata to bind a transport
//!   route. Route state belongs to transit handlers in the target tree.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::connection_response_row;

#[derive(Debug, Clone, Default)]
pub struct ConnectionResponseProjector;

impl ConnectionResponseProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionResponseProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let response = layout::decode_fact(&fact.bytes)?;
        if response.from_endpoint == response.to_endpoint {
            return Err("connection response endpoints must differ".to_string());
        }
        if response.request_id == fact.id {
            return Err("connection response cannot answer itself".to_string());
        }
        Ok(ProjectionOutput::new().intent(
            AtomicIntent::PutRow(connection_response_row(fact.id, &response)?).into_intent(),
        ))
    }
}
