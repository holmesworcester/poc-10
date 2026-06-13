//! Connection fact-bundle send intent.
//!
//! Sync chooses which fact ids should move on a connection; this handler decides
//! how those fact bytes are packaged. It loads the named connection and payload
//! facts, verifies local endpoint ownership and sendability, batches facts into
//! fixed connection-frame budgets, seals each batch, and emits local
//! `send_network_frame` intents.
//!
//! This is not socket IO and it is not sync visibility policy. Sync owns the
//! shareable index and requested ids, this handler owns byte-level sendability
//! and frame-family selection, each frame fact family owns sealing, and
//! `send_network_frame` owns the final opaque socket write.

use crate::core::intents::{
    HandlerContext, HandlerError, HandlerFactId, HandlerResult, IntentHandler,
};
use crate::core::intents::{Intent, IntentKind};
use crate::core::wire::{
    Reader as PayloadReader, WireError as PayloadError, Writer as PayloadWriter,
};
use crate::core::{effects::RuntimeEffects, facts::Fact};
use crate::protocol::auth::endpoint;
use crate::protocol::connection::connection as connection_fact;
use crate::protocol::connection::send_network_frame::{self, SendNetworkFrame};
use crate::protocol::connection::{frame_bundle, frame_file_slice, frame_small};
use crate::protocol::content;
use crate::protocol::sync::shared_fact;

pub type HandlerId = [u8; 32];

pub const SEND_FACTS_ON_CONNECTION: &str = "send_facts_on_connection";
pub const SHAREABLE_BUCKET_TIMESTAMPS: u64 = 4096;

const EXPLICIT_FACTS_PAYLOAD: u8 = 1;
const SHAREABLE_RANGE_PAYLOAD: u8 = 2;
const SHAREABLE_RANGE_WITH_DEPS_PAYLOAD: u8 = 3;
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
    trigger_fact_id: HandlerId,
) -> Intent {
    let start_timestamp_ms = timestamp_ms - (timestamp_ms % SHAREABLE_BUCKET_TIMESTAMPS);
    let end_timestamp_ms = start_timestamp_ms.saturating_add(SHAREABLE_BUCKET_TIMESTAMPS - 1);
    send_shareable_range_on_connection_intent_with_trigger(
        connection_id,
        start_timestamp_ms,
        end_timestamp_ms,
        false,
        trigger_fact_id,
    )
}

pub fn send_shareable_range_on_connection_intent(
    connection_id: HandlerId,
    start_timestamp_ms: u64,
    end_timestamp_ms: u64,
    include_deps: bool,
) -> Intent {
    send_shareable_range_on_connection_intent_with_trigger(
        connection_id,
        start_timestamp_ms,
        end_timestamp_ms,
        include_deps,
        [0; 32],
    )
}

fn send_shareable_range_on_connection_intent_with_trigger(
    connection_id: HandlerId,
    start_timestamp_ms: u64,
    end_timestamp_ms: u64,
    include_deps: bool,
    trigger_fact_id: HandlerId,
) -> Intent {
    let mut payload = PayloadWriter::with_capacity(1 + 32 + 8 + 8 + 32);
    payload.u8(if include_deps {
        SHAREABLE_RANGE_WITH_DEPS_PAYLOAD
    } else {
        SHAREABLE_RANGE_PAYLOAD
    });
    payload.fixed(&connection_id);
    payload.u64be(start_timestamp_ms);
    payload.u64be(end_timestamp_ms);
    payload.fixed(&trigger_fact_id);
    Intent::new(
        IntentKind::new(SEND_FACTS_ON_CONNECTION).expect("valid send_facts_on_connection kind"),
        shareable_range_key(
            connection_id,
            start_timestamp_ms,
            end_timestamp_ms,
            include_deps,
            trigger_fact_id,
        ),
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
        SHAREABLE_RANGE_PAYLOAD | SHAREABLE_RANGE_WITH_DEPS_PAYLOAD => {
            let start_timestamp_ms = reader.u64be().map_err(payload_error)?;
            let end_timestamp_ms = reader.u64be().map_err(payload_error)?;
            let include_deps = payload_kind == SHAREABLE_RANGE_WITH_DEPS_PAYLOAD;
            let trigger_fact_id = reader.array::<32>().map_err(payload_error)?;
            reader.finish().map_err(payload_error)?;
            if start_timestamp_ms > end_timestamp_ms {
                return Err("send_facts_on_connection shareable range is inverted".into());
            }
            if intent.key
                != shareable_range_key(
                    connection_id,
                    start_timestamp_ms,
                    end_timestamp_ms,
                    include_deps,
                    trigger_fact_id,
                )
            {
                return Err("send_facts_on_connection key does not match shareable range".into());
            }
            Ok(SendFactsOnConnectionWork::ShareableRange(
                SendShareableRangeOnConnection {
                    connection_id,
                    start_timestamp_ms,
                    end_timestamp_ms,
                    include_deps,
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
    include_deps: bool,
    trigger_fact_id: HandlerId,
) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-shareable-range-on-connection:v1:");
    hash.update(&connection_id);
    hash.update(&start_timestamp_ms.to_be_bytes());
    hash.update(&end_timestamp_ms.to_be_bytes());
    hash.update(&[u8::from(include_deps)]);
    hash.update(&trigger_fact_id);
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
    include_deps: bool,
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
            SendFactsOnConnectionWork::Explicit(input) => input.fact_ids,
            SendFactsOnConnectionWork::ShareableRange(_) => Vec::new(),
        })
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let work = decode_send_facts_on_connection_work(intent)?;
        let connection_id = work.connection_id();
        let Some(connection) =
            connection_fact::queries::connection_by_id(context.store()?, &connection_id).map_err(
                |err| {
                    HandlerError::fatal(format!("send_facts_on_connection connection row: {err}"))
                },
            )?
        else {
            return Ok(RuntimeEffects::new());
        };
        let batches = fact_batches(facts_for_work(work, context)?)?;

        let local_endpoint =
            endpoint::author::local_endpoint(context.store()?)?.ok_or_else(|| {
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

        let mut output = RuntimeEffects::new();
        for batch in batches {
            let fact_ids = batch.iter().map(|fact| fact.id).collect::<Vec<_>>();
            let payloads = batch
                .iter()
                .map(|fact| connection_fact::queries::sendable_fact_body(fact).map(Vec::from))
                .collect::<Result<Vec<_>, _>>()?;
            let frame = seal_batch(
                connection_id,
                sender_endpoint,
                receiver_endpoint,
                connection.connection_secret,
                &fact_ids,
                &payloads,
            )?;
            output = output.local_intent(send_network_frame::send_network_frame_intent(
                SendNetworkFrame {
                    routing_key: connection_id,
                    frame,
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
        SendFactsOnConnectionWork::ShareableRange(input) => {
            Ok(shared_fact::shareable_facts_for_connection_range(
                context.store()?,
                input.connection_id,
                input.start_timestamp_ms,
                input.end_timestamp_ms,
                input.include_deps,
            )?)
        }
    }
}

fn fact_batches(facts: Vec<Fact>) -> Result<Vec<Vec<Fact>>, String> {
    let mut batches = Vec::new();
    let mut batch = Vec::new();
    let mut packed_len = frame_small::author::INNER_BUNDLE_HEADER_BYTES;
    for fact in facts {
        let fact_len = connection_fact::queries::sendable_fact_body(&fact)?.len();
        if fact_len == crate::protocol::content::file_slice::encode::CONTENT_FILE_SLICE_BYTES {
            if !batch.is_empty() {
                batches.push(std::mem::take(&mut batch));
                packed_len = frame_small::author::INNER_BUNDLE_HEADER_BYTES;
            }
            batches.push(vec![fact]);
            continue;
        }
        if fact_len > frame_bundle::encode::CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES {
            return Err(
                "send_facts_on_connection fact exceeds connection frame bundle slot".into(),
            );
        }
        let item_len = INNER_FACT_LEN_BYTES + fact_len;
        let would_fit_small =
            packed_len + item_len <= frame_small::encode::CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES;
        let would_fit_bundle =
            batch.len() < frame_bundle::encode::CONNECTION_FRAME_BUNDLE_FACT_SLOTS;
        if !batch.is_empty() && !would_fit_small && !would_fit_bundle {
            batches.push(std::mem::take(&mut batch));
            packed_len = frame_small::author::INNER_BUNDLE_HEADER_BYTES;
        }
        packed_len += item_len;
        batch.push(fact);
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    Ok(batches)
}

fn seal_batch(
    connection_id: HandlerId,
    sender_endpoint: HandlerId,
    receiver_endpoint: HandlerId,
    connection_secret: [u8; 32],
    fact_ids: &[HandlerId],
    payloads: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    if is_file_slice_batch(payloads) {
        return frame_file_slice::author::seal_connection_send_frame(
            connection_id,
            sender_endpoint,
            receiver_endpoint,
            connection_secret,
            fact_ids,
            payloads,
        );
    }
    if inner_bundle_packed_len(payloads)?
        <= frame_small::encode::CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES
    {
        return frame_small::author::seal_connection_send_frame(
            connection_id,
            sender_endpoint,
            receiver_endpoint,
            connection_secret,
            fact_ids,
            payloads,
        );
    }
    frame_bundle::author::seal_connection_send_frame(
        connection_id,
        sender_endpoint,
        receiver_endpoint,
        connection_secret,
        fact_ids,
        payloads,
    )
}

fn is_file_slice_batch(payloads: &[Vec<u8>]) -> bool {
    payloads.len() == 1
        && payloads[0].len() == content::file_slice::encode::CONTENT_FILE_SLICE_BYTES
}

fn inner_bundle_packed_len(payloads: &[Vec<u8>]) -> Result<usize, String> {
    if payloads.is_empty() {
        return Err("connection::frame inner bundle must contain at least one fact".to_string());
    }
    let mut len = frame_small::author::INNER_BUNDLE_HEADER_BYTES;
    for payload in payloads {
        let payload_len = payload.len();
        u32::try_from(payload_len)
            .map_err(|_| format!("connection::frame inner length too large: {payload_len}"))?;
        len = len
            .checked_add(INNER_FACT_LEN_BYTES)
            .and_then(|len| len.checked_add(payload_len))
            .ok_or_else(|| "connection::frame inner bundle length overflow".to_string())?;
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shareable_bucket_intent_identity_includes_trigger_fact() {
        let connection_id = [7; 32];
        let timestamp_ms = SHAREABLE_BUCKET_TIMESTAMPS + 42;

        let first =
            send_shareable_bucket_on_connection_intent(connection_id, timestamp_ms, [1; 32]);
        let second =
            send_shareable_bucket_on_connection_intent(connection_id, timestamp_ms, [2; 32]);

        assert_ne!(first.key, second.key);
        assert_eq!(first.kind, second.kind);
    }
}
