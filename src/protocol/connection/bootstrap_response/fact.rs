//! Bootstrap-response fact payload.
//!
//! This fact is local ephemeral receive input. It preserves exactly one sealed
//! network response frame together with the observed origin and receive time so
//! projection can open it using endpoint context and create the canonical
//! response receipt.

use crate::protocol::connection::fact_receipt::fact::OriginAddr;

pub type SealedConnectionResponseFrame = [u8; super::layout::SEALED_CONNECTION_RESPONSE_BYTES];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionBootstrapResponseFact {
    pub origin_addr: OriginAddr,
    pub received_at_local_ms: u64,
    pub sealed_response_frame: SealedConnectionResponseFrame,
}
