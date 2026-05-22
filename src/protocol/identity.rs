//! Identity and membership fact modules.
//!
//! Identity facts establish who can act in a workspace and which local secrets
//! the store is allowed to use. Workspaces, users, endpoints, invites, accepted
//! invites, shared endpoint records, device invites, and admin grants all live
//! here because other protocol areas depend on them for authority.
//!
//! These modules are the source of signing and encryption capabilities exposed
//! through `CommandContext`. Commands borrow already-established local
//! capability; they do not mint authority. Projectors publish context offers
//! such as workspace membership, local signer secret, invite secret, and
//! endpoint identity so content, encryption, connection, and sync modules can
//! wait for the correct proof.
//!
//! Change identity here when membership, local endpoint material, invite flow,
//! or authority projection changes. Other modules should consume identity rows
//! and context instead of duplicating identity policy.

pub mod admin;
pub mod device_invite;
pub mod endpoint;
pub mod endpoint_shared;
pub mod invite;
pub mod invite_accepted;
pub mod invite_server;
pub mod signed_fact;
pub mod user;
pub mod user_invite;
pub mod workspace;
