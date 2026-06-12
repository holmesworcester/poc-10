//! Connection fact-receipt authoring compatibility surface.
//!
//! Receipt facts are emitted by projectors through
//! `fact_receipt::project::connection_fact_receipt_for_path`. Origin-address
//! normalization is part of the receipt fact shape and is re-exported here for
//! older author-side callers.

pub use super::fact::{canonical_origin_addr_bytes, normalize_origin_addr_bytes};
