//! Projector for the local endpoint event.
//!
//! Projection writes two rows under the stable `local` key: the public endpoint
//! id and the local secret. The separation is not a security boundary; it keeps
//! row meanings explicit for queries and tests.

use crate::core::store::TableRow;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::codec;
use super::schema;
use super::types::EndpointId;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let event = codec::decode(bytes)?;
    Ok(ProjectionOutput::rows(local_endpoint(
        event.endpoint,
        event.secret,
    )))
}

pub fn local_endpoint(endpoint: EndpointId, secret: [u8; 32]) -> Vec<TableRow> {
    vec![
        TableRow {
            table: schema::LOCAL_ENDPOINT,
            key: b"local".to_vec(),
            value: endpoint.to_vec(),
        },
        TableRow {
            table: schema::LOCAL_ENDPOINT_SECRET,
            key: b"local".to_vec(),
            value: secret.to_vec(),
        },
    ]
}
