//! User-facing constructor for connection close facts.
//!
//! Closing a connection creates a local close fact only. Projection validates
//! the referenced connection, and target facts perform their own row deletion
//! and purge scheduling when close context arrives.

use crate::core::command::{AuthoredFacts, CommandClock};
use crate::core::facts::FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseConnectionReceipt {
    pub close_id: FactId,
    pub connection_id: FactId,
    pub closed_at_ms: u64,
}

pub fn close(
    clock: &dyn CommandClock,
    connection_id: FactId,
) -> Result<AuthoredFacts<CloseConnectionReceipt>, String> {
    let closed_at_ms = clock.next_timestamp();
    let fact = super::author::close_fact(connection_id, closed_at_ms)?;
    Ok(AuthoredFacts::new(CloseConnectionReceipt {
        close_id: fact.id,
        connection_id,
        closed_at_ms,
    })
    .with_facts(vec![fact]))
}
