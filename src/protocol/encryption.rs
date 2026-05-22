//! Encryption and retention scope: fact and intent modules.
//!
//! Encryption facts describe recipient keys, key wraps, local key material,
//! removal frontiers, local history-node secrets, key requests, and disappearing
//! message settings. Each fact family owns its own layout, projection, and
//! row policy in a named module. Together they decide when content can be
//! opened, when deleted or expired material should be purged, and which key
//! material can be shared with another endpoint.
//!
//! Add new encryption policy in the owning family module. Content modules should
//! ask for encryption context and rows; they should not reconstruct
//! key-eligibility rules.

pub mod disappearing_messages_setting;
pub mod key_request;
pub mod key_wrap;
pub mod local_history_node_secret;
pub mod local_key_secret;
pub mod local_recipient_key;
pub mod recipient_key;
pub mod removal_frontier;

// Intents: work that needs exact fact inputs after projection proves
// eligibility — create a signed key wrap, unwrap a received wrap, or purge
// retired local secrets.
pub mod create_key_wrap;
pub mod purge_retired_recipient_material;
pub mod unwrap_key_wrap;
