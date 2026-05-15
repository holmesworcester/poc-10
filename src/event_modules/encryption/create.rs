//! Re-export aggregator for encryption fact constructors split by family.

pub use super::key_wrap::create::{
    materialize_key_wrap_fact, materialize_signed_key_wrap_fact, unwrap_key_wrap_fact,
    KEY_WRAP_PURPOSE,
};
pub use super::recipient_key::create::validate_retired_recipient_material;
