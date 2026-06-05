//! Read-only queries over projected workspace users.
//!
//! User rows are admitted only after auth projection validates the
//! surrounding invite or authority chain. These helpers return the current
//! visible membership in deterministic display order for CLI and command code.
//! They should not infer authority from raw facts.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::core::wire::FixedText;

use super::fact::{UserId, Username, WorkspaceId, USERNAME_BYTES};
use super::{USER_ROWS, USER_ROW_SCHEMA};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub user_invite_id: [u8; 32],
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub username: String,
}

pub fn decode_user_row(key: &[u8], value: &[u8]) -> Result<UserRow, String> {
    let key_fields = USER_ROW_SCHEMA.decode_key(key)?;
    let value_fields = USER_ROW_SCHEMA.decode_value(value)?;
    let username = read_username(value_fields[3].as_bytes("username")?)?;
    Ok(UserRow {
        workspace_id: key_fields[0].as_bytes32("workspace_id")?,
        user_id: key_fields[1].as_bytes32("user_id")?,
        created_at_ms: value_fields[0].as_u64("created_at_ms")?,
        public_key: value_fields[1].as_bytes32("public_key")?,
        user_invite_id: value_fields[2].as_bytes32("user_invite_id")?,
        username,
    })
}

fn read_username(bytes: &[u8]) -> Result<String, String> {
    let padded: [u8; USERNAME_BYTES] = bytes
        .try_into()
        .map_err(|_| "username slot has wrong length".to_string())?;
    let username: Username = FixedText::from_padded(padded).map_err(|err| format!("{err:?}"))?;
    Ok(username.to_string())
}

pub fn users_in_workspace(store: &Store, workspace_id: FactId) -> Result<Vec<UserRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(USER_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load users: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_user_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|left, right| {
        left.username
            .cmp(&right.username)
            .then_with(|| left.user_id.cmp(&right.user_id))
    });
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::ED25519_SIGNATURE_BYTES;
    use crate::protocol::auth::user::fact::UserFact;

    #[test]
    fn user_row_roundtrips_through_schema() {
        let fact = UserFact {
            created_at_ms: 42,
            workspace_id: [1; 32],
            public_key: [2; 32],
            username: Username::new("alice").expect("username"),
            signer_id: [5; 32],
            signer_public_key: [6; 32],
            signature: [7; ED25519_SIGNATURE_BYTES],
        };
        let row = super::super::user_row([8; 32], [9; 32], &fact).expect("user row");
        let decoded = decode_user_row(&row.key, &row.value).expect("decode user row");
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.user_id, [8; 32]);
        assert_eq!(decoded.created_at_ms, 42);
        assert_eq!(decoded.public_key, [2; 32]);
        assert_eq!(decoded.user_invite_id, [9; 32]);
        assert_eq!(decoded.username, "alice");
    }
}
