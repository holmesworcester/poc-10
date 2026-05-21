//! Package exact facts into one connection transit frame.

use crate::core::intents::{
    HandlerContext, HandlerError, HandlerFactId, HandlerResult, IntentHandler,
};
use crate::core::intents::{Intent, IntentKind};
use crate::core::{effects::PipelineEffects, facts::Fact};
use crate::protocol::facts::{
    connection::response,
    identity::endpoint,
    sync::shared_fact,
    transport::transit::{
        create,
        frame::{self, TransitFactBundle},
        layout::TRANSIT_LARGE_PLAINTEXT_BYTES,
    },
};
use crate::protocol::intents::payload::{PayloadError, PayloadReader, PayloadWriter};
use crate::protocol::intents::transport::send_network_frame::{self, SendNetworkFrame};

pub type HandlerId = [u8; 32];

pub const SEND_FACTS_ON_CONNECTION: &str = "send_facts_on_connection";
pub const SHAREABLE_BUCKET_TIMESTAMPS: u64 = 4096;

const EXPLICIT_FACTS_PAYLOAD: u8 = 1;
const SHAREABLE_RANGE_PAYLOAD: u8 = 2;
const INNER_BUNDLE_HEADER_BYTES: usize = 4 + 1 + 4;
const INNER_FACT_LEN_BYTES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFactsOnConnection {
    pub connection_id: HandlerId,
    /// Ordered fact ids that must travel together for the receiver to project
    /// the requested range item without a follow-up key/dependency round trip.
    pub fact_ids: Vec<HandlerId>,
}

pub fn send_facts_on_connection_intent(input: SendFactsOnConnection) -> Intent {
    let mut payload = PayloadWriter::with_capacity(37 + input.fact_ids.len() * 32);
    payload.u8(EXPLICIT_FACTS_PAYLOAD);
    payload.fixed(&input.connection_id);
    payload.u32be(
        input
            .fact_ids
            .len()
            .try_into()
            .expect("fact id count fits u32"),
    );
    for fact_id in &input.fact_ids {
        payload.fixed(fact_id);
    }

    Intent::new(
        IntentKind::new(SEND_FACTS_ON_CONNECTION).expect("valid send_facts_on_connection kind"),
        connection_fact_ids_key(input.connection_id, &input.fact_ids),
        payload.finish(),
    )
}

pub fn send_shareable_bucket_on_connection_intent(
    connection_id: HandlerId,
    timestamp_ms: u64,
) -> Intent {
    let start_timestamp_ms = timestamp_ms - (timestamp_ms % SHAREABLE_BUCKET_TIMESTAMPS);
    let end_timestamp_ms = start_timestamp_ms.saturating_add(SHAREABLE_BUCKET_TIMESTAMPS - 1);
    let mut payload = PayloadWriter::with_capacity(1 + 32 + 8 + 8);
    payload.u8(SHAREABLE_RANGE_PAYLOAD);
    payload.fixed(&connection_id);
    payload.u64be(start_timestamp_ms);
    payload.u64be(end_timestamp_ms);
    Intent::new(
        IntentKind::new(SEND_FACTS_ON_CONNECTION).expect("valid send_facts_on_connection kind"),
        shareable_range_key(connection_id, start_timestamp_ms, end_timestamp_ms),
        payload.finish(),
    )
}

pub fn decode_send_facts_on_connection(intent: &Intent) -> Result<SendFactsOnConnection, String> {
    match decode_send_facts_on_connection_work(intent)? {
        SendFactsOnConnectionWork::Explicit(input) => Ok(input),
        SendFactsOnConnectionWork::ShareableRange(_) => {
            Err("expected explicit send_facts_on_connection payload".into())
        }
    }
}

fn decode_send_facts_on_connection_work(
    intent: &Intent,
) -> Result<SendFactsOnConnectionWork, String> {
    if intent.kind.as_str() != SEND_FACTS_ON_CONNECTION {
        return Err("expected send_facts_on_connection intent".into());
    }
    let mut reader = PayloadReader::new(&intent.payload);
    let payload_kind = reader.u8().map_err(payload_error)?;
    let connection_id = reader.array::<32>().map_err(payload_error)?;
    match payload_kind {
        EXPLICIT_FACTS_PAYLOAD => {
            let count = reader.u32be().map_err(payload_error)? as usize;
            let mut fact_ids = Vec::with_capacity(count);
            for _ in 0..count {
                fact_ids.push(reader.array::<32>().map_err(payload_error)?);
            }
            reader.finish().map_err(payload_error)?;
            if fact_ids.is_empty() {
                return Err("send_facts_on_connection must name at least one fact".into());
            }
            if intent.key != connection_fact_ids_key(connection_id, &fact_ids) {
                return Err("send_facts_on_connection key does not match payload".into());
            }
            Ok(SendFactsOnConnectionWork::Explicit(SendFactsOnConnection {
                connection_id,
                fact_ids,
            }))
        }
        SHAREABLE_RANGE_PAYLOAD => {
            let start_timestamp_ms = reader.u64be().map_err(payload_error)?;
            let end_timestamp_ms = reader.u64be().map_err(payload_error)?;
            reader.finish().map_err(payload_error)?;
            if start_timestamp_ms > end_timestamp_ms {
                return Err("send_facts_on_connection shareable range is inverted".into());
            }
            if intent.key
                != shareable_range_key(connection_id, start_timestamp_ms, end_timestamp_ms)
            {
                return Err("send_facts_on_connection key does not match shareable range".into());
            }
            Ok(SendFactsOnConnectionWork::ShareableRange(
                SendShareableRangeOnConnection {
                    connection_id,
                    start_timestamp_ms,
                    end_timestamp_ms,
                },
            ))
        }
        _ => Err("unknown send_facts_on_connection payload kind".into()),
    }
}

fn connection_fact_ids_key(connection_id: HandlerId, fact_ids: &[HandlerId]) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-facts-on-connection:v1:");
    hash.update(&connection_id);
    for fact_id in fact_ids {
        hash.update(fact_id);
    }
    hash.finalize().as_bytes().to_vec()
}

fn shareable_range_key(
    connection_id: HandlerId,
    start_timestamp_ms: u64,
    end_timestamp_ms: u64,
) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-shareable-range-on-connection:v1:");
    hash.update(&connection_id);
    hash.update(&start_timestamp_ms.to_be_bytes());
    hash.update(&end_timestamp_ms.to_be_bytes());
    hash.finalize().as_bytes().to_vec()
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid send_facts_on_connection payload: {err}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SendShareableRangeOnConnection {
    connection_id: HandlerId,
    start_timestamp_ms: u64,
    end_timestamp_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SendFactsOnConnectionWork {
    Explicit(SendFactsOnConnection),
    ShareableRange(SendShareableRangeOnConnection),
}

#[derive(Debug, Clone, Default)]
pub struct SendFactsOnConnectionHandler;

impl SendFactsOnConnectionHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendFactsOnConnectionHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(match decode_send_facts_on_connection_work(intent)? {
            SendFactsOnConnectionWork::Explicit(input) => {
                let mut ids = Vec::with_capacity(1 + input.fact_ids.len());
                ids.push(input.connection_id);
                ids.extend(input.fact_ids);
                ids
            }
            SendFactsOnConnectionWork::ShareableRange(input) => vec![input.connection_id],
        })
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let work = decode_send_facts_on_connection_work(intent)?;
        let connection_id = work.connection_id();
        let connection_fact = context.require_fact(&connection_id)?;
        let connection = response::layout::decode_fact(connection_fact.body())?;
        if connection_fact.id != connection_id {
            return Err("send_facts_on_connection connection fact id mismatch".into());
        }
        let batches = fact_batches(facts_for_work(work, context)?)?;

        let local_endpoint = endpoint::local_endpoint::local_endpoint(context.store()?)?
            .ok_or_else(|| {
                HandlerError::fatal("send_facts_on_connection requires local endpoint state")
            })?;
        let (sender_endpoint, receiver_endpoint) = if local_endpoint.endpoint
            == connection.from_endpoint
        {
            (connection.from_endpoint, connection.to_endpoint)
        } else if local_endpoint.endpoint == connection.to_endpoint {
            (connection.to_endpoint, connection.from_endpoint)
        } else {
            return Err("send_facts_on_connection local endpoint is not part of connection".into());
        };

        let mut output = PipelineEffects::new();
        for batch in batches {
            let fact_ids = batch.iter().map(|fact| fact.id).collect::<Vec<_>>();
            let mut bundle = TransitFactBundle::new();
            for fact in &batch {
                bundle.push(create::require_sendable_fact(fact)?.to_vec());
            }
            output = output.local_intent(send_network_frame::send_network_frame_intent(
                SendNetworkFrame {
                    routing_key: connection_id,
                    frame: frame::seal_connection_send_frame(
                        connection_id,
                        sender_endpoint,
                        receiver_endpoint,
                        connection.connection_secret,
                        &fact_ids,
                        bundle,
                    )?,
                },
            ));
        }
        Ok(output)
    }
}

impl SendFactsOnConnectionWork {
    fn connection_id(&self) -> HandlerId {
        match self {
            Self::Explicit(input) => input.connection_id,
            Self::ShareableRange(input) => input.connection_id,
        }
    }
}

fn facts_for_work(
    work: SendFactsOnConnectionWork,
    context: &HandlerContext<'_>,
) -> Result<Vec<Fact>, HandlerError> {
    match work {
        SendFactsOnConnectionWork::Explicit(input) => input
            .fact_ids
            .iter()
            .map(|fact_id| context.require_fact(fact_id).cloned())
            .collect(),
        SendFactsOnConnectionWork::ShareableRange(input) => Ok(
            shared_fact::shareable_facts_for_connection(context.store()?, input.connection_id)?
                .into_iter()
                .filter(|fact| {
                    input.start_timestamp_ms <= fact.timestamp
                        && fact.timestamp <= input.end_timestamp_ms
                })
                .collect(),
        ),
    }
}

fn fact_batches(facts: Vec<Fact>) -> Result<Vec<Vec<Fact>>, String> {
    let mut batches = Vec::new();
    let mut batch = Vec::new();
    let mut packed_len = INNER_BUNDLE_HEADER_BYTES;
    for fact in facts {
        let item_len = INNER_FACT_LEN_BYTES + create::require_sendable_fact(&fact)?.len();
        if INNER_BUNDLE_HEADER_BYTES + item_len > TRANSIT_LARGE_PLAINTEXT_BYTES {
            return Err("send_facts_on_connection fact exceeds transport frame capacity".into());
        }
        if !batch.is_empty() && packed_len + item_len > TRANSIT_LARGE_PLAINTEXT_BYTES {
            batches.push(std::mem::take(&mut batch));
            packed_len = INNER_BUNDLE_HEADER_BYTES;
        }
        packed_len += item_len;
        batch.push(fact);
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    Ok(batches)
}
