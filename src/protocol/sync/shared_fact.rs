//! Sync contribution index family.
//!
//! Fact projectors record which facts may be sent for a workspace and which
//! validated context travels with those leaves. Sync handlers use these rows to
//! seed compares, advertise new facts, and build outbound connection frames.
//! The index is connection-scoped sharing policy; it does not change the
//! validity of the underlying facts.

pub mod cli;
pub mod encode;
pub mod fact;
pub mod index;
pub mod project;

pub const TYPE_SHARED_FACT: u8 = encode::TYPE_SHARED_FACT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SharedFact, String> {
    project::decode::decode_fact(bytes)
}

pub use index::{
    connection_id_for_peer_or_connection, connection_ids_for_shareable_fact,
    expand_fact_ids_with_context_for_connection, negentropy_context_have_for_leaf,
    range_summary_for_connection, record_sync_contribution, shareable_fact_for_connection,
    shareable_fact_row, shareable_fact_rows, shareable_facts_for_connection,
    shareable_facts_for_connection_range, sync_status, NegentropyContextHaveRow, NegentropyLeafRow,
    NegentropyNodeRow, ShareableFactRow, NEGENTROPY_CONTEXT_HAVE_ROWS, NEGENTROPY_LEAF_ROWS,
    NEGENTROPY_NODE_ROWS, SHAREABLE_FACT_ROWS,
};
pub(crate) use index::{retained_fact, retained_fact_exists};
