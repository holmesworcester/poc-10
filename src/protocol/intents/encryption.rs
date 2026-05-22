//! Encryption intent modules.
//!
//! Encryption intents handle work that needs exact fact inputs after projection
//! has proved eligibility: create a signed key wrap, unwrap a received key wrap
//! with local recipient material, or purge retired local secrets. Keep
//! eligibility checks in encryption projectors and validation helpers; handlers
//! should load the declared facts and perform the deterministic action.

pub mod create_key_wrap;
pub mod purge_retired_recipient_material;
pub mod unwrap_key_wrap;
