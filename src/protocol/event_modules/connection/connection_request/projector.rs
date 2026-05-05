//! Projector for connection request events.
//!
//! The projector writes the request bytes for later validation. When the common
//! worker supplies receive metadata, the same projection also learns the
//! subjective local connection fact: "this endpoint received the request from
//! this route." That keeps route learning atomic with connection establishment
//! without turning socket addresses into separate semantic events.

use super::super::schema as projection;
use super::super::types;
use super::codec;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = event.record.canonical_bytes.clone();
    let receive = event.record.receive;
    let event = codec::decode(&bytes)?;
    let request_id = types::event_id(&bytes);
    let mut rows = vec![projection::connection_event_row(request_id, bytes)];
    if let Some(receive) = receive {
        let connection_id = types::connection_id(&request_id, &receive.local_endpoint);
        rows.push(projection::connection_row(
            connection_id,
            event.from_endpoint,
        ));
        if receive.remember_route {
            rows.push(projection::transport_target_row(
                connection_id,
                receive.origin,
            ));
        }
    }

    Ok(ProjectionOutput::rows(rows))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::protocol::event_modules::connection::connection_request::types::RequestEvent;
    use crate::protocol::event_modules::connection::{schema, types};
    use crate::protocol::event_modules::types::ReceiveMetadata;
    use crate::protocol::event_modules::worker::EventContext;

    use super::codec;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn request_record() -> Record {
        codec::record_from_bytes(codec::encode(&RequestEvent {
            from_endpoint: [1; 32],
            nonce: [2; 32],
            bootstrap_hash: [3; 32],
        }))
        .expect("request record")
    }

    fn context_for(record: &Record) -> EventWithContext<'_> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: types::event_id(&record.canonical_bytes),
                dependencies: Vec::new(),
                labels: Vec::new(),
            },
        }
    }

    #[test]
    fn projects_request_bytes_without_receive_metadata() {
        let record = request_record();
        let output = project(&context_for(&record)).expect("project request");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[0].key, types::event_id(&record.canonical_bytes));
        assert_eq!(output.rows[0].value, record.canonical_bytes);
    }

    #[test]
    fn projects_received_request_connection_and_route_rows() {
        let mut record = request_record();
        let origin = "127.0.0.1:9000".parse::<SocketAddr>().expect("addr");
        record.receive = Some(ReceiveMetadata {
            origin,
            local_endpoint: [9; 32],
            remember_route: true,
        });
        let output = project(&context_for(&record)).expect("project received request");

        assert_eq!(output.rows.len(), 3);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[1].table, schema::CONNECTIONS);
        assert_eq!(output.rows[2].table, schema::TRANSPORT_TARGETS);
        assert_eq!(
            output.rows[1].key,
            types::connection_id(&types::event_id(&record.canonical_bytes), &[9; 32])
        );
        assert_eq!(output.rows[1].value, [1; 32]);
        assert_eq!(output.rows[2].value, origin.to_string().into_bytes());
    }
}
