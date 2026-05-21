use crate::core::context::ContextOffer;
use crate::core::facts::{Fact, FactId};
use crate::core::pipeline::PENDING_PROJECTION;
use crate::core::pipeline_storage::{insert_fact_and_pending_in_tx, purge_fact_in_tx};
use crate::core::store::Store;

use super::context_store::insert_context_offer_in_tx;

/// Commit externally projected offers and clear the completed pending facts.
///
/// This is used by bounded sync commands that materialize context offers
/// directly from already-verified rows. It keeps the same transaction rule as
/// fact projection: newly visible context and completed pending work commit
/// together.
pub(crate) fn commit_projected_context_offers(
    store: &Store,
    offers: &[ContextOffer],
    completed_fact_ids: &[FactId],
) -> Result<(), String> {
    store
        .write_transaction(|tx| {
            for offer in offers {
                insert_context_offer_in_tx(tx, offer)?;
            }
            tx.delete_table_rows_in_tx(
                PENDING_PROJECTION,
                completed_fact_ids.iter().map(|id| id.to_vec()).collect(),
            )?;
            Ok(())
        })
        .map_err(|err| format!("commit projected context offers: {err}"))
}

// === Fact submission, purge, and time triggers ===

/// Insert a fact and mark it pending in the same transaction.
pub(crate) fn submit_fact_to_store(store: &Store, fact: Fact) -> Result<bool, String> {
    let inserted = store
        .write_transaction(|tx| insert_fact_and_pending_in_tx(tx, &fact))
        .map_err(|err| format!("submit fact: {err}"))?;
    Ok(inserted)
}

/// Bulk insert facts with one transaction and one pending row per insert.
pub(crate) fn submit_facts_to_store(
    store: &Store,
    facts: impl IntoIterator<Item = Fact>,
) -> Result<usize, String> {
    let facts = facts.into_iter().collect::<Vec<_>>();
    let inserted = store
        .write_transaction(|tx| {
            let mut inserted = Vec::new();
            for fact in &facts {
                if insert_fact_and_pending_in_tx(tx, fact)? {
                    inserted.push(fact.id);
                }
            }
            Ok(inserted)
        })
        .map_err(|err| format!("submit facts: {err}"))?;
    Ok(inserted.len())
}

/// Remove a fact and all durable runtime state derived from it.
pub(crate) fn purge_fact_from_store(store: &Store, owner: FactId) -> Result<bool, String> {
    let changed = store
        .write_transaction(|tx| purge_fact_in_tx(tx, owner))
        .map_err(|err| format!("purge fact: {err}"))?;
    Ok(changed)
}
