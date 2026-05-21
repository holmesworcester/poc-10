use crate::core::context::{ContextOffer, ContextSetDelta};
use crate::core::fact_store::{insert_fact_and_pending_in_tx, purge_fact_in_tx};
use crate::core::facts::{Fact, FactId};
use crate::core::matchers::ContextMatchers;
use crate::core::store::Store;
use rusqlite::params;

use super::context::{insert_context_offer_in_tx, wake_context_matches_in_tx};
use super::effects::sqlite_string_error;

/// Commit externally projected offers and clear the completed pending facts.
///
/// This is used by bounded sync commands that materialize context offers
/// directly from already-verified rows. It keeps the same transaction rule as
/// fact projection: newly visible context and completed pending work commit
/// together.
pub(crate) fn commit_projected_context_offers(
    store: &Store,
    matchers: &ContextMatchers,
    offers: &[ContextOffer],
    completed_fact_ids: &[FactId],
) -> Result<usize, String> {
    store
        .write_transaction(|tx| {
            let mut added_offers = Vec::new();
            for offer in offers {
                if insert_context_offer_in_tx(tx, offer)? {
                    added_offers.push(offer.clone());
                }
            }
            let woken_facts = wake_context_matches_in_tx(
                tx,
                &ContextSetDelta {
                    added_offers,
                    ..ContextSetDelta::default()
                },
                matchers,
            )
            .map_err(sqlite_string_error)?;
            for id in completed_fact_ids {
                tx.conn().execute(
                    "DELETE FROM pending_projection WHERE owner = ?1",
                    params![id.as_slice()],
                )?;
            }
            Ok(woken_facts)
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
