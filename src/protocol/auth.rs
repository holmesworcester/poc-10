//! Authentication, authority, and key-material fact modules.
//!
//! Auth facts establish who can act in a workspace and which local secrets the
//! store is allowed to use. Workspaces, users, endpoints, invites, signed
//! envelopes, admin grants, recipient keys, removal frontiers, key wraps, and
//! local key material live in one scope because the proofs overlap: a recipient
//! public key and a removal frontier are meaningful only through endpoint
//! identity and workspace authority.
//!
//! These modules are the source of signing and encryption capabilities exposed
//! through `CommandContext`. Commands borrow already-established local
//! capability; they do not mint authority. Projectors publish context offers
//! such as workspace membership, local signer secret, invite secret, endpoint
//! identity, recipient-key state, and removal-frontier state so content,
//! connection, and sync modules can wait for the correct proof.
//!
//! Change auth here when membership, local endpoint material, invite flow,
//! authority projection, recipient-key projection, key wrapping, or key-material
//! projection changes. Other modules should consume auth rows and context
//! instead of duplicating auth policy.

pub mod admin;
pub mod device_invite;
pub mod endpoint;
pub mod endpoint_shared;
pub mod invite;
pub mod invite_accepted;
pub mod invite_server;
pub mod key_request;
pub mod key_wrap;
pub mod local_history_node_secret;
pub mod local_key_secret;
pub mod local_recipient_key;
pub mod local_secret_retirement;
pub mod local_signer_secret;
pub mod recipient_key;
pub mod removal_frontier;
pub mod signed_envelope;
pub mod user;
pub mod user_invite;
pub mod workspace;

// Intents: work that needs exact fact inputs after projection proves
// eligibility - create a signed key wrap or unwrap a received wrap.
pub mod create_key_wrap;
pub mod unwrap_key_wrap;
