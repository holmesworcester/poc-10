use crate::protocol::event_modules::worker::ProjectionOutput;

use super::codec;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    codec::validate(bytes)?;
    Ok(ProjectionOutput::default())
}
