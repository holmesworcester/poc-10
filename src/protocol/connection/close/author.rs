//! Connection-close fact construction helpers.

use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::ConnectionCloseFact;

pub fn close_fact(connection_id: FactId, closed_at_ms: u64) -> Result<Fact, String> {
    if connection_id == [0; 32] {
        return Err("connection_id cannot be empty".to_string());
    }
    let close = ConnectionCloseFact {
        connection_id,
        closed_at_ms,
    };
    Ok(Fact::new(
        FactScope::Local,
        closed_at_ms,
        encode::encode_fact(&close)?,
    ))
}
