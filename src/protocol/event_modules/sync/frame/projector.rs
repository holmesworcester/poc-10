use crate::protocol::event_modules::types::event_id;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::codec;
use crate::protocol::event_modules::connection::tables;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let connection_id = codec::connection_id(bytes)?;
    Ok(ProjectionOutput::rows(vec![tables::outbox_row(
        connection_id,
        event_id(bytes),
        bytes.to_vec(),
    )]))
}
