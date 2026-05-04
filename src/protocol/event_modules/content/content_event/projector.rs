use crate::core::store::ProjectionOutput;

use super::codec;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    codec::validate(bytes)?;
    Ok(ProjectionOutput::default())
}
