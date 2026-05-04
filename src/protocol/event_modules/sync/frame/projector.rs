//! Projector for sync frame events.
//!
//! Projection queues the exact frame bytes for the owning connection. The
//! connection worker later performs wrapping and hands opaque bytes to core TCP;
//! sync projectors never perform IO.

use crate::protocol::event_modules::types::event_id;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::codec;
use crate::protocol::event_modules::connection::schema;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let connection_id = codec::connection_id(bytes)?;
    Ok(ProjectionOutput::rows(vec![schema::outbox_row(
        connection_id,
        event_id(bytes),
        bytes.to_vec(),
    )]))
}
