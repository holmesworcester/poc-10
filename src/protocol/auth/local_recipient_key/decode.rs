//! Byte decoding for local recipient key facts.
//!
//! Decoding proves only the fixed layout: tag, length, field order, and that the
//! decoded material is canonical. Id checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{
    validate_local_recipient_key, LOCAL_RECIPIENT_KEY_BYTES, TYPE_LOCAL_RECIPIENT_KEY,
};
use super::fact::LocalRecipientKeyFact;

pub fn decode_local_recipient_key(bytes: &[u8]) -> Result<LocalRecipientKeyFact, String> {
    wire::expect_len(bytes, LOCAL_RECIPIENT_KEY_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_LOCAL_RECIPIENT_KEY {
        return Err("expected local recipient key".to_string());
    }
    let fact = LocalRecipientKeyFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        recipient_key_id: bytes[33..65].try_into().unwrap(),
        recipient_key: bytes[65..97].try_into().unwrap(),
        recipient_secret: bytes[97..129].try_into().unwrap(),
    };
    validate_local_recipient_key(&fact)?;
    Ok(fact)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::{self, X25519_PRIVATE_KEY_BYTES};
    use crate::protocol::auth::local_recipient_key::encode::{
        encode_local_recipient_key, LOCAL_RECIPIENT_KEY_BYTES,
    };

    fn sample_fact() -> LocalRecipientKeyFact {
        let recipient_secret = [7; X25519_PRIVATE_KEY_BYTES];
        let recipient_key = crypto::x25519_public_key(&recipient_secret);
        LocalRecipientKeyFact {
            workspace_id: [1; 32],
            recipient_key_id: [2; 32],
            recipient_key,
            recipient_secret,
        }
    }

    #[test]
    fn local_recipient_key_roundtrips_fixed_width() {
        let fact = sample_fact();

        let encoded = encode_local_recipient_key(&fact).expect("encode local recipient key");

        assert_eq!(encoded.len(), LOCAL_RECIPIENT_KEY_BYTES);
        assert_eq!(
            decode_local_recipient_key(&encoded).expect("decode local recipient key"),
            fact
        );
    }
}
