//! Commands for creating signed envelopes.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::legacy::protocol::event_modules::types::EventId;
use crate::legacy::protocol::event_modules::worker::CommandOutput;

use super::layout;
use super::types::SignedEnvelope;

pub fn sign_payload(
    signer_event_id: EventId,
    private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> Result<CommandOutput<SignedEnvelope>, String> {
    let inner_type = payload
        .first()
        .copied()
        .ok_or_else(|| "signed envelope payload is empty".to_string())?;
    let signer_public_key = crypto::ed25519_public_key(private_key);
    let mut event = SignedEnvelope {
        signer_event_id,
        signer_public_key,
        inner_type,
        payload,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    event.signature = crypto::ed25519_sign(private_key, &layout::signing_bytes(&event));
    let bytes = layout::encode(&event);
    let record = layout::record_from_bytes(bytes)?;
    Ok(CommandOutput::with_events(event, vec![record]))
}
