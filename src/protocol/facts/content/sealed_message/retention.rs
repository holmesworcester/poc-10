//! Helpers for bounded sealed-message retention purges.

use crate::core::facts::Fact;
use crate::core::store::Store;
use crate::protocol::facts::{content::sealed_message, identity::signed_fact};

pub fn decode_sealed_message_fact(
    fact: &Fact,
) -> Result<sealed_message::fact::SealedMessageFact, String> {
    match fact.bytes.first().copied() {
        Some(sealed_message::layout::TYPE_SEALED_MESSAGE) => {
            sealed_message::layout::decode_sealed_message(&fact.bytes)
        }
        Some(signed_fact::layout::TYPE_SIGNED_FACT) => {
            let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)?;
            if envelope.inner_type != sealed_message::layout::TYPE_SEALED_MESSAGE {
                return Err("signed fact does not contain a sealed message".to_string());
            }
            sealed_message::layout::decode_sealed_message(&envelope.payload)
        }
        _ => Err("expected sealed message fact".to_string()),
    }
}

pub fn delete_message_projection(
    store: &Store,
    message_id: [u8; 32],
    message: &sealed_message::fact::SealedMessageFact,
    context: &str,
) -> Result<(), String> {
    let key = sealed_message::rows::message_key(message.workspace_id, message_id);
    let tombstone = sealed_message::rows::message_tombstone_row(
        message.workspace_id,
        message_id,
        message.author_user_id,
        message.created_at_ms,
    );
    store
        .write_transaction(|tx| {
            tx.insert_table_rows_in_tx(vec![tombstone])?;
            tx.delete_table_rows_in_tx(sealed_message::rows::MESSAGE_ROWS, vec![key.clone()])?;
            tx.delete_table_rows_in_tx(
                sealed_message::rows::OPENED_MESSAGE_ROWS,
                vec![key.clone()],
            )?;
            tx.delete_table_rows_in_tx(sealed_message::rows::SEALED_MESSAGE_ROWS, vec![key])?;
            Ok(())
        })
        .map_err(|err| format!("{context}: {err}"))?;
    Ok(())
}
