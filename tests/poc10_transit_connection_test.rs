use topo::core::handler_dispatch::HandlerOutput;
use topo::core::intents::{Intent, IntentExecution, IntentKind};

type Id = [u8; 32];

const TRANSIT_WRAP_CONNECTION_BATCH: &str = "transit_wrap_connection_batch";
const CONNECTION_SEND_FRAME: &str = "connection_send_frame";
const CONNECTION_MARK_SENT: &str = "connection_mark_sent";

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransitWrapConnectionBatch {
    connection_id: Id,
    sender_endpoint: Id,
    recipient_endpoint: Id,
    connection_secret_id: Id,
    transit_out_keys: Vec<Vec<u8>>,
    canonical_events: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectionSendFrame {
    target_addr: String,
    transit_out_keys: Vec<Vec<u8>>,
    frame: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectionMarkSent {
    transit_out_keys: Vec<Vec<u8>>,
}

fn transit_wrap_connection_batch_intent(input: TransitWrapConnectionBatch) -> Intent {
    let mut payload = Vec::new();
    push_id(&mut payload, &input.connection_id);
    push_id(&mut payload, &input.sender_endpoint);
    push_id(&mut payload, &input.recipient_endpoint);
    push_id(&mut payload, &input.connection_secret_id);
    push_vecs(&mut payload, &input.transit_out_keys);
    push_vecs(&mut payload, &input.canonical_events);

    Intent::new(
        IntentKind::new(TRANSIT_WRAP_CONNECTION_BATCH).unwrap(),
        IntentExecution::Deferred,
        input.connection_id,
        payload,
    )
}

fn decode_transit_wrap_connection_batch(
    intent: &Intent,
) -> Result<TransitWrapConnectionBatch, String> {
    if intent.kind.as_str() != TRANSIT_WRAP_CONNECTION_BATCH {
        return Err("expected transit_wrap_connection_batch intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("transit wrap intent must be deferred".to_string());
    }
    let mut reader = Reader::new(&intent.payload);
    let connection_id = reader.id()?;
    let sender_endpoint = reader.id()?;
    let recipient_endpoint = reader.id()?;
    let connection_secret_id = reader.id()?;
    let transit_out_keys = reader.vecs()?;
    let canonical_events = reader.vecs()?;
    reader.finish()?;
    if intent.key != connection_id {
        return Err("transit wrap idempotence key must be the connection id".to_string());
    }
    Ok(TransitWrapConnectionBatch {
        connection_id,
        sender_endpoint,
        recipient_endpoint,
        connection_secret_id,
        transit_out_keys,
        canonical_events,
    })
}

fn connection_send_frame_intent(input: ConnectionSendFrame) -> Intent {
    let mut payload = Vec::new();
    push_bytes(&mut payload, input.target_addr.as_bytes());
    push_vecs(&mut payload, &input.transit_out_keys);
    push_bytes(&mut payload, &input.frame);

    Intent::new(
        IntentKind::new(CONNECTION_SEND_FRAME).unwrap(),
        IntentExecution::Deferred,
        input.target_addr.into_bytes(),
        payload,
    )
}

fn decode_connection_send_frame(intent: &Intent) -> Result<ConnectionSendFrame, String> {
    if intent.kind.as_str() != CONNECTION_SEND_FRAME {
        return Err("expected connection_send_frame intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("connection send intent must be deferred".to_string());
    }
    let mut reader = Reader::new(&intent.payload);
    let target_addr = String::from_utf8(reader.bytes()?.to_vec())
        .map_err(|_| "connection send target must be utf8".to_string())?;
    let transit_out_keys = reader.vecs()?;
    let frame = reader.bytes()?.to_vec();
    reader.finish()?;
    if intent.key != target_addr.as_bytes() {
        return Err("connection send idempotence key must be the target address".to_string());
    }
    Ok(ConnectionSendFrame {
        target_addr,
        transit_out_keys,
        frame,
    })
}

fn connection_mark_sent_intent(input: ConnectionMarkSent) -> Intent {
    let mut payload = Vec::new();
    push_vecs(&mut payload, &input.transit_out_keys);
    Intent::new(
        IntentKind::new(CONNECTION_MARK_SENT).unwrap(),
        IntentExecution::Deferred,
        b"transit_out".to_vec(),
        payload,
    )
}

fn decode_connection_mark_sent(intent: &Intent) -> Result<ConnectionMarkSent, String> {
    if intent.kind.as_str() != CONNECTION_MARK_SENT {
        return Err("expected connection_mark_sent intent".to_string());
    }
    let mut reader = Reader::new(&intent.payload);
    let transit_out_keys = reader.vecs()?;
    reader.finish()?;
    Ok(ConnectionMarkSent { transit_out_keys })
}

fn fake_connection_drain_handler(
    connection_id: Id,
    sender_endpoint: Id,
    recipient_endpoint: Id,
    connection_secret_id: Id,
    transit_out_keys: Vec<Vec<u8>>,
    canonical_events: Vec<Vec<u8>>,
) -> HandlerOutput {
    HandlerOutput::new().intent(transit_wrap_connection_batch_intent(
        TransitWrapConnectionBatch {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            connection_secret_id,
            transit_out_keys,
            canonical_events,
        },
    ))
}

fn fake_transit_wrap_handler(intent: &Intent, target_addr: &str) -> Result<HandlerOutput, String> {
    let batch = decode_transit_wrap_connection_batch(intent)?;
    let frame = fake_crypto_wrap(
        batch.connection_id,
        batch.sender_endpoint,
        batch.recipient_endpoint,
        batch.connection_secret_id,
        &batch.canonical_events,
    );
    Ok(
        HandlerOutput::new().intent(connection_send_frame_intent(ConnectionSendFrame {
            target_addr: target_addr.to_string(),
            transit_out_keys: batch.transit_out_keys,
            frame,
        })),
    )
}

fn fake_connection_send_handler(intent: &Intent) -> Result<HandlerOutput, String> {
    let send = decode_connection_send_frame(intent)?;
    assert!(
        !send.frame.starts_with(b"event:"),
        "connection transport must receive opaque transit bytes, not canonical events"
    );
    Ok(
        HandlerOutput::new().intent(connection_mark_sent_intent(ConnectionMarkSent {
            transit_out_keys: send.transit_out_keys,
        })),
    )
}

fn fake_crypto_wrap(
    connection_id: Id,
    sender_endpoint: Id,
    recipient_endpoint: Id,
    connection_secret_id: Id,
    canonical_events: &[Vec<u8>],
) -> Vec<u8> {
    let mut frame = b"transit-frame-v1".to_vec();
    frame.extend_from_slice(&connection_id);
    frame.extend_from_slice(&sender_endpoint);
    frame.extend_from_slice(&recipient_endpoint);
    frame.extend_from_slice(&connection_secret_id);
    push_vecs(&mut frame, canonical_events);
    frame
}

#[test]
fn connection_drain_emits_transit_wrap_not_network_send() {
    let output = fake_connection_drain_handler(
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        vec![b"out-key-1".to_vec(), b"out-key-2".to_vec()],
        vec![b"event:a".to_vec(), b"event:b".to_vec()],
    );

    assert_eq!(output.facts, Vec::new());
    assert_eq!(output.intents.len(), 1);
    assert_eq!(
        output.intents[0].kind.as_str(),
        TRANSIT_WRAP_CONNECTION_BATCH,
        "connection drain chooses route and pending canonical bytes, then delegates packaging"
    );
    assert_ne!(
        output.intents[0].kind.as_str(),
        CONNECTION_SEND_FRAME,
        "connection drain must not bypass transit packaging"
    );

    let decoded = decode_transit_wrap_connection_batch(&output.intents[0]).unwrap();
    assert_eq!(
        decoded.canonical_events,
        vec![b"event:a".to_vec(), b"event:b".to_vec()]
    );
}

#[test]
fn transit_wrap_emits_opaque_connection_send_frame() {
    let drain = fake_connection_drain_handler(
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        vec![b"out-key".to_vec()],
        vec![b"event:a".to_vec()],
    );

    let wrapped = fake_transit_wrap_handler(&drain.intents[0], "127.0.0.1:44000").unwrap();

    assert_eq!(wrapped.intents.len(), 1);
    assert_eq!(wrapped.intents[0].kind.as_str(), CONNECTION_SEND_FRAME);
    let send = decode_connection_send_frame(&wrapped.intents[0]).unwrap();
    assert_eq!(send.target_addr, "127.0.0.1:44000");
    assert_eq!(send.transit_out_keys, vec![b"out-key".to_vec()]);
    assert!(send.frame.starts_with(b"transit-frame-v1"));
    assert_ne!(send.frame, b"event:a".to_vec());
}

#[test]
fn connection_send_ack_marks_only_transit_out_keys() {
    let drain = fake_connection_drain_handler(
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        vec![b"out-key".to_vec()],
        vec![b"event:a".to_vec()],
    );
    let wrapped = fake_transit_wrap_handler(&drain.intents[0], "127.0.0.1:44000").unwrap();

    let sent = fake_connection_send_handler(&wrapped.intents[0]).unwrap();

    assert_eq!(sent.intents.len(), 1);
    assert_eq!(sent.intents[0].kind.as_str(), CONNECTION_MARK_SENT);
    let mark = decode_connection_mark_sent(&sent.intents[0]).unwrap();
    assert_eq!(mark.transit_out_keys, vec![b"out-key".to_vec()]);
}

#[test]
fn intent_kind_names_keep_crypto_and_transport_boundaries_separate() {
    for kind in [
        TRANSIT_WRAP_CONNECTION_BATCH,
        CONNECTION_SEND_FRAME,
        CONNECTION_MARK_SENT,
    ] {
        IntentKind::new(kind).expect("intent kind is registry-safe");
    }

    assert!(
        TRANSIT_WRAP_CONNECTION_BATCH.starts_with("transit_"),
        "cryptographic packaging belongs to transit handlers"
    );
    assert!(
        CONNECTION_SEND_FRAME.starts_with("connection_"),
        "network send/drain belongs to connection handlers"
    );
}

fn push_id(out: &mut Vec<u8>, id: &Id) {
    out.extend_from_slice(id);
}

fn push_vecs(out: &mut Vec<u8>, values: &[Vec<u8>]) {
    out.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        push_bytes(out, value);
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn id(&mut self) -> Result<Id, String> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn vecs(&mut self) -> Result<Vec<Vec<u8>>, String> {
        let len = self.u32()? as usize;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(self.bytes()?.to_vec());
        }
        Ok(values)
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "intent payload length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated intent payload".to_string());
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("intent payload has trailing bytes".to_string())
        }
    }
}
