use crate::store::{ProjectionOutput, TableRow};

use super::codec;
use super::tables;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    if bytes.first().copied() == Some(codec::TYPE_STAGED_DEPENDENT_EVENT) {
        let event = codec::decode_staged(bytes)?;
        return Ok(ProjectionOutput::rows(vec![TableRow {
            table: tables::STAGED_DEPENDENT_EVENTS,
            key: event.index.to_be_bytes().to_vec(),
            value: event.dependent_bytes,
        }]));
    }
    codec::decode(bytes)?;
    Ok(ProjectionOutput::default())
}
