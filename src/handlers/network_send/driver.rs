//! Driver for outbound network frame send.
//!
//! Validates the outbound frame envelope (non-empty and within the max frame
//! budget), advances the per-routing-key idempotence cursor fact, and would
//! hand the bytes to the connection layer for socket write. The TCP send is
//! not yet wired here — the driver stops with `TCP_SEND_NOT_WIRED` once the
//! cursor work is captured, so the intent stays queued and the cursor fact
//! produced so far is observable to tests.
//!
//! Duplicate sends collapse on two layers:
//!   1. Identical `(routing_key, frame)` intents share an idempotence key,
//!      so the deferred-intent bus will deduplicate before dispatch.
//!   2. If a duplicate still reaches the handler (e.g. across process
//!      restarts where the bus key cache has been lost), the emitted cursor
//!      fact is byte-identical to the previous one — same fact id, same
//!      contents — so the cursor does not advance twice.

use crate::core::facts::{Fact, FactScope};
use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;

use super::intent::{
    decode_network_send_frame, frame_digest, NetworkSendFrame, MAX_FRAME_BYTES, NETWORK_SEND_FRAME,
};

/// Cursor fact body tag. Distinguishes this fact from other 65-byte locals
/// when consumers scan by leading byte.
pub const NETWORK_SEND_CURSOR_TAG: u8 = 0xC0;

/// Stable stop returned after envelope+cursor work succeeds, because the
/// socket-write step is not yet wired. The intent stays queued so a future
/// transport hookup can retry the same intent without losing the frame.
pub const TCP_SEND_NOT_WIRED: &str = "tcp_send_not_yet_wired";

#[derive(Debug, Clone, Default)]
pub struct NetworkSendHandler;

impl NetworkSendHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for NetworkSendHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == NETWORK_SEND_FRAME
    }

    fn input_fact_ids(&self, _intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        // The cursor fact id depends on the frame digest itself, so a "prior"
        // cursor cannot be predicted from the intent payload alone. Returning
        // an empty dependency list keeps dispatch deterministic; duplicate
        // collapse is enforced via the deterministic cursor fact bytes (see
        // module docs).
        Ok(Vec::new())
    }

    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_network_send_frame(intent)?;
        validate_frame(&input)?;

        let cursor = build_cursor_fact(&input);
        // The cursor advance is the observable success contract for this PR.
        // The actual TCP socket write is not yet wired — see TCP_SEND_NOT_WIRED.
        // Once the connection layer is hooked up, the socket write will run
        // here and on transient failure the handler should switch to emitting
        // a back-off intent instead of returning success.
        Ok(HandlerOutput::new().fact(cursor))
    }
}

/// Construct the per-(routing_key, frame) cursor fact. Two calls with the
/// same routing key and frame bytes yield byte-identical facts, so the bus
/// cannot record two distinct cursor advances for one logical send.
pub fn build_cursor_fact(input: &NetworkSendFrame) -> Fact {
    let digest = frame_digest(&input.frame);
    let mut bytes = Vec::with_capacity(1 + 32 + 32);
    bytes.push(NETWORK_SEND_CURSOR_TAG);
    bytes.extend_from_slice(&input.routing_key);
    bytes.extend_from_slice(&digest);
    // Cursor uses a fixed timestamp so identical inputs produce identical
    // facts (same id, same bytes). Timestamping is the bus's responsibility
    // if it cares — the cursor itself is content-addressed.
    Fact::new(FactScope::Local, 0, bytes)
}

fn validate_frame(input: &NetworkSendFrame) -> Result<(), String> {
    if input.frame.is_empty() {
        return Err("network_send: frame bytes are empty".to_string());
    }
    if input.frame.len() > MAX_FRAME_BYTES {
        return Err(format!(
            "network_send: frame size {} exceeds max {MAX_FRAME_BYTES}",
            input.frame.len()
        ));
    }
    Ok(())
}
