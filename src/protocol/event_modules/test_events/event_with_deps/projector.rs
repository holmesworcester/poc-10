//! Projector for dependency-cascade test events.
//!
//! Staged events write their inner shared event bytes into a local replay table.
//! Actual shared dependency events need no projection rows; their purpose is to
//! exercise admission, blocking, and unblocking in the common worker.

use crate::core::store::TableRow;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::codec;
use super::schema;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    if bytes.first().copied() == Some(codec::TYPE_STAGED_EVENT_WITH_DEPS) {
        let event = codec::decode_staged(bytes)?;
        return Ok(ProjectionOutput::rows(vec![TableRow {
            table: schema::STAGED_EVENTS_WITH_DEPS,
            key: event.index.to_be_bytes().to_vec(),
            value: event.inner_bytes,
        }]));
    }
    codec::decode(bytes)?;
    Ok(ProjectionOutput::default())
}
