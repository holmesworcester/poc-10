//! Bootstrap-request fact payload.
//!
//! This fact is local ephemeral receive input. It preserves exactly one sealed
//! network request frame together with the observed origin and receive time so
//! projection can open it using endpoint context and create the canonical
//! request receipt.

use crate::protocol::connection::fact_receipt::fact::OriginAddr;

pub type SealedConnectionRequestFrame = [u8; super::layout::SEALED_CONNECTION_REQUEST_BYTES];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionBootstrapRequestFact {
    pub origin_addr: OriginAddr,
    pub received_at_local_ms: u64,
    pub sealed_request_frame: SealedConnectionRequestFrame,
}
