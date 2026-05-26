//! Connection-bootstrap fact payload.
//!
//! Bootstrap facts are local ephemeral receive inputs. They preserve the sealed
//! network bytes together with the observed origin and receive time so
//! projection can open them using endpoint context and then create the
//! canonical request or response fact receipt.

use crate::core::wire::FixedSlot;
use crate::protocol::connection::fact_receipt::fact::OriginAddr;

pub type BootstrapFrame = FixedSlot<{ super::layout::SEALED_BOOTSTRAP_FRAME_BYTES }>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionBootstrapFact {
    pub origin_addr: OriginAddr,
    pub received_at_local_ms: u64,
    pub frame: BootstrapFrame,
}
