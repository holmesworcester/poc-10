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

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::endpoint::commands;

    use super::*;

    #[test]
    fn project_writes_public_endpoint_and_secret_as_local_rows() {
        let local = commands::create_local_keypair().value;
        let bytes = codec::encode(&local);
        let output = project(&bytes).expect("project endpoint");

        assert_eq!(output.rows.len(), 2);
        assert!(output
            .rows
            .iter()
            .any(|row| row.table == schema::LOCAL_ENDPOINT
                && row.key == b"local"
                && row.value == local.endpoint));
        assert!(output
            .rows
            .iter()
            .any(|row| row.table == schema::LOCAL_ENDPOINT_SECRET
                && row.key == b"local"
                && row.value == local.secret));
    }
}
