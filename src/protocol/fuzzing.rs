//! Fuzzing adapters for protocol-owned byte surfaces.
//!
//! These helpers intentionally live behind `cfg(test, fuzzing)`: production
//! routing still goes through the normal registry, while tests and fuzz targets
//! get a single auditable list of registered fact decoders.

use crate::protocol::{auth, connection, content, sync};

type DecodeFn = fn(&[u8]) -> Result<(), String>;

#[derive(Debug, Clone, Copy)]
pub struct RegisteredFactDecoder {
    pub tag: u8,
    pub name: &'static str,
    decode: DecodeFn,
}

impl RegisteredFactDecoder {
    pub fn decode(self, bytes: &[u8]) -> Result<(), String> {
        (self.decode)(bytes)
    }
}

macro_rules! decoder_fn {
    ($name:ident, $decode:path) => {
        fn $name(bytes: &[u8]) -> Result<(), String> {
            $decode(bytes).map(|_| ())
        }
    };
}

decoder_fn!(
    decode_cascade_test_fact,
    sync::cascade_test_fact::decode_fact_payload
);
decoder_fn!(
    decode_connection_close,
    connection::close::decode_fact_payload
);
decoder_fn!(
    decode_connection_ephemeral_secret,
    connection::ephemeral_secret::decode_fact_payload
);
decoder_fn!(
    decode_connection_request,
    connection::request::decode_fact_payload
);
decoder_fn!(
    decode_connection_response,
    connection::response::decode_fact_payload
);
decoder_fn!(decode_content_file, content::file::decode_fact_payload);
decoder_fn!(
    decode_content_file_deletion,
    content::file_deletion::decode_fact_payload
);
decoder_fn!(
    decode_content_file_slice,
    content::file_slice::decode_fact_payload
);
decoder_fn!(
    decode_content_message,
    content::message::decode_fact_payload
);
decoder_fn!(
    decode_content_message_deletion,
    content::message_deletion::decode_fact_payload
);
decoder_fn!(
    decode_content_reaction,
    content::reaction::decode_fact_payload
);
decoder_fn!(
    decode_auth_recipient_key,
    auth::recipient_key::decode_fact_payload
);
decoder_fn!(
    decode_auth_removal_frontier,
    auth::removal_frontier::decode_fact_payload
);
decoder_fn!(
    decode_auth_local_key_secret,
    auth::local_key_secret::decode_fact_payload
);
decoder_fn!(
    decode_auth_local_history_node_secret,
    auth::local_history_node_secret::decode_fact_payload
);
decoder_fn!(
    decode_auth_local_secret_retirement,
    auth::local_secret_retirement::decode_fact_payload
);
decoder_fn!(
    decode_auth_key_request,
    auth::key_request::decode_fact_payload
);
decoder_fn!(
    decode_auth_key_wrap,
    auth::key_wrap::layout::decode_key_wrap
);
decoder_fn!(
    decode_auth_local_recipient_key,
    auth::local_recipient_key::decode_fact_payload
);
decoder_fn!(decode_endpoint, auth::endpoint::decode_fact_payload);
decoder_fn!(decode_invite, auth::invite::decode_fact_payload);
decoder_fn!(decode_workspace, auth::workspace::decode_fact_payload);
decoder_fn!(
    decode_auth_local_signer_secret,
    auth::local_signer_secret::decode_fact_payload
);
decoder_fn!(
    decode_device_invite,
    auth::device_invite::decode_fact_payload
);
decoder_fn!(
    decode_endpoint_shared,
    auth::endpoint_shared::decode_fact_payload
);
decoder_fn!(
    decode_invite_server,
    auth::invite_server::decode_fact_payload
);
decoder_fn!(decode_admin, auth::admin::decode_fact_payload);
decoder_fn!(
    decode_invite_accepted,
    auth::invite_accepted::decode_fact_payload
);
decoder_fn!(
    decode_retention_policy,
    content::retention_policy::decode_fact_payload
);
decoder_fn!(
    decode_sync_range_request,
    sync::range_request::decode_fact_payload
);
decoder_fn!(
    decode_sync_encrypted_root,
    sync::encrypted_root::decode_fact_payload
);
decoder_fn!(
    decode_sync_shared_fact,
    sync::shared_fact::decode_fact_payload
);
decoder_fn!(
    decode_sync_key_wrap_available,
    sync::key_wrap_available::decode_fact_payload
);
decoder_fn!(decode_sync_compare, sync::compare::decode_fact_payload);
decoder_fn!(decode_sync_have_id, sync::have_id::decode_fact_payload);
decoder_fn!(decode_sync_need_id, sync::need_id::decode_fact_payload);
decoder_fn!(
    decode_connection_frame,
    connection::frame::decode_fact_payload
);
decoder_fn!(
    decode_connection_fact_receipt,
    connection::fact_receipt::decode_fact_payload
);
decoder_fn!(decode_user_invite, auth::user_invite::decode_fact_payload);
decoder_fn!(decode_user, auth::user::decode_fact_payload);

pub const REGISTERED_FACT_DECODERS: &[RegisteredFactDecoder] = &[
    RegisteredFactDecoder {
        tag: sync::cascade_test_fact::layout::TYPE_CASCADE_TEST_FACT,
        name: "sync::cascade_test_fact",
        decode: decode_cascade_test_fact,
    },
    RegisteredFactDecoder {
        tag: connection::close::layout::TYPE_CONNECTION_CLOSE,
        name: "connection::close",
        decode: decode_connection_close,
    },
    RegisteredFactDecoder {
        tag: connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET,
        name: "connection::ephemeral_secret",
        decode: decode_connection_ephemeral_secret,
    },
    RegisteredFactDecoder {
        tag: connection::request::layout::TYPE_CONNECTION_REQUEST,
        name: "connection::request",
        decode: decode_connection_request,
    },
    RegisteredFactDecoder {
        tag: connection::response::layout::TYPE_CONNECTION_RESPONSE,
        name: "connection::response",
        decode: decode_connection_response,
    },
    RegisteredFactDecoder {
        tag: content::file::layout::TYPE_CONTENT_FILE,
        name: "content::file",
        decode: decode_content_file,
    },
    RegisteredFactDecoder {
        tag: content::file_deletion::layout::TYPE_CONTENT_FILE_DELETION,
        name: "content::file_deletion",
        decode: decode_content_file_deletion,
    },
    RegisteredFactDecoder {
        tag: content::file_slice::layout::TYPE_CONTENT_FILE_SLICE,
        name: "content::file_slice",
        decode: decode_content_file_slice,
    },
    RegisteredFactDecoder {
        tag: content::message::layout::TYPE_CONTENT_MESSAGE,
        name: "content::message",
        decode: decode_content_message,
    },
    RegisteredFactDecoder {
        tag: content::message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION,
        name: "content::message_deletion",
        decode: decode_content_message_deletion,
    },
    RegisteredFactDecoder {
        tag: content::reaction::layout::TYPE_CONTENT_REACTION,
        name: "content::reaction",
        decode: decode_content_reaction,
    },
    RegisteredFactDecoder {
        tag: auth::recipient_key::layout::TYPE_RECIPIENT_KEY,
        name: "auth::recipient_key",
        decode: decode_auth_recipient_key,
    },
    RegisteredFactDecoder {
        tag: auth::removal_frontier::layout::TYPE_REMOVAL_FRONTIER,
        name: "auth::removal_frontier",
        decode: decode_auth_removal_frontier,
    },
    RegisteredFactDecoder {
        tag: auth::local_key_secret::layout::TYPE_LOCAL_KEY_SECRET,
        name: "auth::local_key_secret",
        decode: decode_auth_local_key_secret,
    },
    RegisteredFactDecoder {
        tag: auth::local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        name: "auth::local_history_node_secret",
        decode: decode_auth_local_history_node_secret,
    },
    RegisteredFactDecoder {
        tag: auth::local_secret_retirement::layout::TYPE_LOCAL_SECRET_RETIREMENT,
        name: "auth::local_secret_retirement",
        decode: decode_auth_local_secret_retirement,
    },
    RegisteredFactDecoder {
        tag: auth::key_request::layout::TYPE_KEY_REQUEST,
        name: "auth::key_request",
        decode: decode_auth_key_request,
    },
    RegisteredFactDecoder {
        tag: auth::key_wrap::layout::TYPE_KEY_WRAP,
        name: "auth::key_wrap",
        decode: decode_auth_key_wrap,
    },
    RegisteredFactDecoder {
        tag: auth::local_recipient_key::layout::TYPE_LOCAL_RECIPIENT_KEY,
        name: "auth::local_recipient_key",
        decode: decode_auth_local_recipient_key,
    },
    RegisteredFactDecoder {
        tag: auth::endpoint::layout::TYPE_LOCAL_ENDPOINT,
        name: "auth::endpoint",
        decode: decode_endpoint,
    },
    RegisteredFactDecoder {
        tag: auth::invite::layout::TYPE_INVITE_SECRET,
        name: "auth::invite",
        decode: decode_invite,
    },
    RegisteredFactDecoder {
        tag: auth::workspace::layout::TYPE_WORKSPACE,
        name: "auth::workspace",
        decode: decode_workspace,
    },
    RegisteredFactDecoder {
        tag: auth::local_signer_secret::layout::TYPE_LOCAL_SIGNER_SECRET,
        name: "auth::local_signer_secret",
        decode: decode_auth_local_signer_secret,
    },
    RegisteredFactDecoder {
        tag: auth::device_invite::layout::TYPE_DEVICE_INVITE,
        name: "auth::device_invite",
        decode: decode_device_invite,
    },
    RegisteredFactDecoder {
        tag: auth::endpoint_shared::layout::TYPE_ENDPOINT_SHARED,
        name: "auth::endpoint_shared",
        decode: decode_endpoint_shared,
    },
    RegisteredFactDecoder {
        tag: auth::invite_server::layout::TYPE_INVITE_SERVER,
        name: "auth::invite_server",
        decode: decode_invite_server,
    },
    RegisteredFactDecoder {
        tag: auth::admin::layout::TYPE_ADMIN,
        name: "auth::admin",
        decode: decode_admin,
    },
    RegisteredFactDecoder {
        tag: auth::invite_accepted::layout::TYPE_INVITE_ACCEPTED,
        name: "auth::invite_accepted",
        decode: decode_invite_accepted,
    },
    RegisteredFactDecoder {
        tag: content::retention_policy::layout::TYPE_RETENTION_POLICY,
        name: "content::retention_policy",
        decode: decode_retention_policy,
    },
    RegisteredFactDecoder {
        tag: sync::range_request::layout::TYPE_SYNC_RANGE_REQUEST,
        name: "sync::range_request",
        decode: decode_sync_range_request,
    },
    RegisteredFactDecoder {
        tag: sync::encrypted_root::layout::TYPE_ENCRYPTED_ROOT,
        name: "sync::encrypted_root",
        decode: decode_sync_encrypted_root,
    },
    RegisteredFactDecoder {
        tag: sync::shared_fact::layout::TYPE_SHARED_FACT,
        name: "sync::shared_fact",
        decode: decode_sync_shared_fact,
    },
    RegisteredFactDecoder {
        tag: sync::key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE,
        name: "sync::key_wrap_available",
        decode: decode_sync_key_wrap_available,
    },
    RegisteredFactDecoder {
        tag: sync::compare::layout::TYPE_SYNC_COMPARE,
        name: "sync::compare",
        decode: decode_sync_compare,
    },
    RegisteredFactDecoder {
        tag: sync::have_id::layout::TYPE_SYNC_HAVE_ID,
        name: "sync::have_id",
        decode: decode_sync_have_id,
    },
    RegisteredFactDecoder {
        tag: sync::need_id::layout::TYPE_SYNC_NEED_ID,
        name: "sync::need_id",
        decode: decode_sync_need_id,
    },
    RegisteredFactDecoder {
        tag: connection::frame::layout::TYPE_CONNECTION_FRAME_SMALL,
        name: "connection::frame::small",
        decode: decode_connection_frame,
    },
    RegisteredFactDecoder {
        tag: connection::frame::layout::TYPE_CONNECTION_FRAME_FILE_SLICE,
        name: "connection::frame::file_slice",
        decode: decode_connection_frame,
    },
    RegisteredFactDecoder {
        tag: connection::frame::layout::TYPE_CONNECTION_FRAME_BUNDLE,
        name: "connection::frame::bundle",
        decode: decode_connection_frame,
    },
    RegisteredFactDecoder {
        tag: connection::fact_receipt::layout::TYPE_CONNECTION_FACT_RECEIPT,
        name: "connection::fact_receipt",
        decode: decode_connection_fact_receipt,
    },
    RegisteredFactDecoder {
        tag: auth::user_invite::layout::TYPE_USER_INVITE,
        name: "auth::user_invite",
        decode: decode_user_invite,
    },
    RegisteredFactDecoder {
        tag: auth::user::layout::TYPE_USER,
        name: "auth::user",
        decode: decode_user,
    },
];

pub fn decode_registered_fact_bytes(bytes: &[u8]) -> Result<(), String> {
    let Some(tag) = bytes.first().copied() else {
        return Err("cannot decode empty fact bytes".to_string());
    };
    let Some(decoder) = REGISTERED_FACT_DECODERS
        .iter()
        .find(|decoder| decoder.tag == tag)
    else {
        return Err(format!("no registered fact decoder for tag {tag}"));
    };
    decoder.decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_fact_decoder_returns_error_for_unknown_or_empty_tags() {
        assert!(decode_registered_fact_bytes(&[]).is_err());
        assert!(decode_registered_fact_bytes(&[255]).is_err());
    }

    #[test]
    fn registered_fact_decoders_are_total_over_arbitrary_bytes() {
        let bytes = b"not a valid fact";
        for decoder in REGISTERED_FACT_DECODERS {
            let _ = decoder.decode(bytes);
        }
    }
}
