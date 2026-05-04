use crate::core::store::{event_id, ProjectionOutput};

use super::codec;
use crate::protocol::event_modules::connection::outbox;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let connection_id = codec::connection_id(bytes)?;
    Ok(ProjectionOutput::rows(vec![outbox::projector::queue(
        connection_id,
        event_id(bytes),
        bytes.to_vec(),
    )]))
}
