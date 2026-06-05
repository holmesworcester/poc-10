//! Bundled connection-frame fact construction helpers.

use crate::core::facts::{Fact, FactScope};
use crate::protocol::connection_frame;

use super::encode;
use super::fact::ConnectionFrameBundleFact;

pub fn fact_from_wire(frame: &[u8], local_timestamp_ms: u64) -> Result<Fact, String> {
    let fact = ConnectionFrameBundleFact {
        frame: connection_frame::exact_frame_slot(frame)?,
    };
    Ok(Fact::new(
        FactScope::Local,
        local_timestamp_ms,
        encode::encode_fact(&fact)?,
    ))
}
