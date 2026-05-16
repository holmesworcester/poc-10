//! Bootstrap request send handler.
//!
//! This handler owns the one pre-connection network effect: sending a validated
//! `connection_request` fact to the address carried by an invite link. Once the
//! request/response handshake establishes a connection, ordinary transit frames
//! and `network_send` take over.

use std::net::SocketAddr;

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::network_queues::{NetworkTarget, OutboundNetworkRow};
use crate::core::tcp;
use crate::event_modules::connection_request::{addr, layout};

pub const BOOTSTRAP_SEND_REQUEST: &str = "bootstrap_send_request";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapSendRequest {
    pub request_id: [u8; 32],
    pub addr: SocketAddr,
}

pub fn bootstrap_send_request_intent(input: BootstrapSendRequest) -> Result<Intent, String> {
    let mut payload = Vec::with_capacity(1 + 32 + addr::ADDR_BLOCK_BYTES);
    payload.push(1);
    payload.extend_from_slice(&input.request_id);
    payload.extend_from_slice(&addr::encode_optional_addr(Some(input.addr))?);
    Ok(Intent::new(
        IntentKind::new(BOOTSTRAP_SEND_REQUEST).expect("valid bootstrap send intent kind"),
        IntentExecution::Deferred,
        bootstrap_send_request_key(&input),
        payload,
    ))
}

pub fn decode_bootstrap_send_request(intent: &Intent) -> Result<BootstrapSendRequest, String> {
    if intent.kind.as_str() != BOOTSTRAP_SEND_REQUEST {
        return Err("expected bootstrap_send_request intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("bootstrap_send_request intent must be deferred".to_string());
    }
    if intent.payload.len() != 1 + 32 + addr::ADDR_BLOCK_BYTES {
        return Err("bootstrap_send_request payload has wrong length".to_string());
    }
    if intent.payload[0] != 1 {
        return Err("bootstrap_send_request payload version unsupported".to_string());
    }
    let request_id = intent.payload[1..33].try_into().unwrap();
    let mut addr_bytes = [0; addr::ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&intent.payload[33..]);
    let addr = addr::decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "bootstrap_send_request addr is missing".to_string())?;
    let input = BootstrapSendRequest { request_id, addr };
    if intent.key != bootstrap_send_request_key(&input) {
        return Err("bootstrap_send_request key does not match payload".to_string());
    }
    Ok(input)
}

#[derive(Debug, Clone, Default)]
pub struct BootstrapSendRequestHandler;

impl BootstrapSendRequestHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for BootstrapSendRequestHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == BOOTSTRAP_SEND_REQUEST
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(vec![decode_bootstrap_send_request(intent)?.request_id])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_bootstrap_send_request(intent)?;
        let request_fact = context.require_fact(&input.request_id)?;
        layout::decode_fact(&request_fact.bytes)?;
        let target = NetworkTarget::new(input.addr);
        let row = OutboundNetworkRow::new(target, request_fact.bytes.clone());
        tcp::send_once(context.store()?, target, vec![row], (), |_, _| Ok(()))?;
        Ok(HandlerOutput::new())
    }
}

fn bootstrap_send_request_key(input: &BootstrapSendRequest) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:bootstrap-send-request:v1:");
    hash.update(&input.request_id);
    hash.update(input.addr.to_string().as_bytes());
    hash.finalize().as_bytes().to_vec()
}
