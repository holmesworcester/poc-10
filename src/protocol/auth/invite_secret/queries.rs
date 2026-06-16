//! Read-only decoding for invite-secret projection rows.
//!
//! Query helpers are the only invite module functions that inspect projected
//! row state directly. They never write, construct facts, project, or dispatch
//! intents.

use crate::core::facts::FactId;

use super::INVITE_SECRET_ROW_SCHEMA;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteSecretRow {
    pub bootstrap_hash: [u8; 32],
    pub bootstrap_secret: [u8; 32],
    pub workspace_id: Option<FactId>,
    pub invite_fact_id: Option<FactId>,
}

pub fn decode_invite_secret_row(key: &[u8], value: &[u8]) -> Result<InviteSecretRow, String> {
    let key_fields = INVITE_SECRET_ROW_SCHEMA.decode_key(key)?;
    let value_fields = INVITE_SECRET_ROW_SCHEMA.decode_value(value)?;
    Ok(InviteSecretRow {
        bootstrap_hash: key_fields[0].as_bytes32("bootstrap_hash")?,
        workspace_id: optional_id(key_fields[1].as_bytes32("workspace_id_or_zero")?),
        invite_fact_id: optional_id(key_fields[2].as_bytes32("invite_fact_id_or_zero")?),
        bootstrap_secret: value_fields[0].as_bytes32("bootstrap_secret")?,
    })
}

fn optional_id(id: FactId) -> Option<FactId> {
    if id == [0; 32] {
        None
    } else {
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::invite_secret::fact::InviteSecretFact;

    #[test]
    fn invite_secret_row_roundtrips_through_schema() {
        let fact = InviteSecretFact {
            bootstrap_hash: [1; 32],
            bootstrap_secret: [2; 32],
            workspace_id: Some([3; 32]),
            invite_fact_id: Some([4; 32]),
        };
        let row = super::super::invite_secret_row(&fact).expect("invite secret row");
        let decoded =
            decode_invite_secret_row(&row.key, &row.value).expect("decode invite secret row");
        assert_eq!(decoded.bootstrap_hash, [1; 32]);
        assert_eq!(decoded.bootstrap_secret, [2; 32]);
        assert_eq!(decoded.workspace_id, Some([3; 32]));
        assert_eq!(decoded.invite_fact_id, Some([4; 32]));
    }

    #[test]
    fn invite_secret_row_decodes_unscoped_zeros_as_none() {
        let fact = InviteSecretFact {
            bootstrap_hash: [5; 32],
            bootstrap_secret: [6; 32],
            workspace_id: None,
            invite_fact_id: None,
        };
        let row = super::super::invite_secret_row(&fact).expect("invite secret row");
        let decoded =
            decode_invite_secret_row(&row.key, &row.value).expect("decode invite secret row");
        assert_eq!(decoded.bootstrap_hash, [5; 32]);
        assert_eq!(decoded.bootstrap_secret, [6; 32]);
        assert_eq!(decoded.workspace_id, None);
        assert_eq!(decoded.invite_fact_id, None);
    }

    #[test]
    fn invite_secret_row_key_includes_scope() {
        let first = InviteSecretFact::scoped([7; 32], [1; 32], [2; 32]);
        let second = InviteSecretFact::scoped([7; 32], [3; 32], [4; 32]);

        let first_row = super::super::invite_secret_row(&first).expect("first row");
        let second_row = super::super::invite_secret_row(&second).expect("second row");

        assert_eq!(first.bootstrap_hash, second.bootstrap_hash);
        assert_ne!(first_row.key, second_row.key);
        assert_eq!(first_row.value, second_row.value);
    }
}
