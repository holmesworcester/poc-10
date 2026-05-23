//! User-facing constructor for connection close facts.
//!
//! Closing a connection creates a local close fact only. Projection validates
//! the referenced connection, and target facts perform their own row deletion
//! and purge scheduling when close context arrives.

use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::facts::{Fact, FactId, FactScope};

use super::fact::ConnectionCloseFact;
use super::layout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseConnectionReceipt {
    pub close_id: FactId,
    pub connection_id: FactId,
    pub closed_at_ms: u64,
}

pub fn close(
    ctx: &CommandContext<'_>,
    connection_id: FactId,
) -> Result<CommandOutput<CloseConnectionReceipt>, String> {
    if connection_id == [0; 32] {
        return Err("connection_id cannot be empty".to_string());
    }
    let closed_at_ms = ctx.next_timestamp();
    let close = ConnectionCloseFact {
        connection_id,
        closed_at_ms,
    };
    let fact = Fact::new(FactScope::Local, closed_at_ms, layout::encode_fact(&close)?);
    Ok(CommandOutput::new(CloseConnectionReceipt {
        close_id: fact.id,
        connection_id,
        closed_at_ms,
    })
    .with_facts(vec![fact]))
}
