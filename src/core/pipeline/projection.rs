use crate::core::context::{diff_context_sets, ContextSet, ContextSetDelta};
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, RowMutation};
use crate::core::matchers::ContextMatcher;
use crate::core::pipeline::queues::validate_intents;
use crate::core::pipeline::report::PipelineReport;
use crate::core::pipeline::{
    persisted_fact, CONTEXT_NEEDS, CONTEXT_OFFERS, LOCAL_INTENTS, PENDING_PROJECTION, TIME_WAKES,
};
use crate::core::pipeline_storage::{
    context_need_row, context_offer_row, decode_fact_id,
    delete_pending_time_ranges_for_owner_in_tx, pending_context_change_rows, purge_fact_in_tx,
    record_intent_in_table_in_tx, record_intent_in_tx, row_mutation_rows, sqlite_string_error,
    stored_context_for_owner, stored_matching_context, stored_pending_time_ranges_for_owner,
    time_wake_row, validate_row_mutations,
};
use crate::core::projectors::{ProjectionContext, ProjectionOutput, Projector, TimeWake};
use crate::core::store::{Store, TableName};

// === Pending-fact projection ===

/// Process pending facts from SQLite one at a time until there is no work or
/// `limit` facts have completed projection.
///
/// This is the readable entry point for the SQL-backed projection path:
///
/// 1. `pending_owner_batch` chooses pending fact ids from SQLite.
/// 2. `load_pending_fact` loads each fact's projection inputs.
/// 3. `process_pending_fact` completes all processing for that one fact.
/// 4. `prepare_projection_effects` runs protocol projection and groups the outputs.
/// 5. `commit_projection_effects` commits every durable and restart-local effect in one
///    SQLite transaction.
/// 6. `finish_pending_fact` refreshes compatibility memory and the report after
///    the transaction has succeeded.
pub(crate) fn process_pending_facts(
    projector: &(impl Projector + ?Sized),
    matchers: &[&dyn ContextMatcher],
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut report = PipelineReport::default();

    for fact_id in pending_owner_batch(store, limit)? {
        if report.projections >= limit {
            break;
        }
        let Some(pending_fact) = load_pending_fact(store, fact_id, matchers)? else {
            store
                .write_transaction(|tx| purge_fact_in_tx(tx, fact_id))
                .map_err(|err| format!("purge stale pending fact: {err}"))?;
            continue;
        };
        process_pending_fact(pending_fact, projector, store, allowed_tables, &mut report)?;
    }

    Ok(report)
}

/// Read the next pending fact ids without mutating the queue.
///
/// The commit step removes the row only after projection succeeds. Missing
/// facts are handled by the caller as stale pending rows and purged there.
fn pending_owner_batch(store: &Store, limit: usize) -> Result<Vec<FactId>, String> {
    let mut owners = Vec::<(u64, FactId)>::new();
    for (key, _) in store
        .table_rows(PENDING_PROJECTION)
        .map_err(|err| format!("load pending projection: {err}"))?
    {
        let owner = decode_fact_id(&key)?;
        let timestamp = persisted_fact(store, &owner)?
            .map(|fact| fact.timestamp)
            .unwrap_or(u64::MAX);
        owners.push((timestamp, owner));
    }
    owners.sort_unstable();
    owners.truncate(limit);
    Ok(owners.into_iter().map(|(_, owner)| owner).collect())
}

/// Load everything projection needs for one fact.
///
/// `previous_context` is the fact's standing context before this run.
/// `projection_context` is the matched input context exposed to the projector
/// for this run, including any due time ranges.
fn load_pending_fact(
    store: &Store,
    fact_id: FactId,
    matchers: &[&dyn ContextMatcher],
) -> Result<Option<PendingFact>, String> {
    let Some(fact) = persisted_fact(store, &fact_id)? else {
        return Ok(None);
    };
    let previous_context = stored_context_for_owner(store, &fact_id)?;
    let time_ranges = stored_pending_time_ranges_for_owner(store, &fact_id)?;
    let projection_context =
        stored_matching_context(store, &previous_context, matchers)?.with_time_ranges(time_ranges);
    Ok(Some(PendingFact {
        fact_id,
        fact,
        previous_context,
        projection_context,
    }))
}

/// Complete all projection work for one pending fact.
///
/// The middle call, `commit_projection_effects`, is the only SQLite
/// transaction in this per-fact pipeline. Everything before it is uncommitted
/// calculation. Everything after it refreshes compatibility memory and reporting.
fn process_pending_fact(
    pending_fact: PendingFact,
    projector: &(impl Projector + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    report: &mut PipelineReport,
) -> Result<(), String> {
    let effects = prepare_projection_effects(projector, pending_fact, allowed_tables)?;
    let commit = commit_projection_effects(store, &effects, allowed_tables)?;
    finish_pending_fact(commit, report)
}

/// Run the protocol projector for one fact and split its output.
///
/// No rows are written here. The result is an uncommitted `ProjectionEffects`
/// value that says what should happen if the projection commits.
fn prepare_projection_effects(
    projector: &(impl Projector + ?Sized),
    pending_fact: PendingFact,
    allowed_tables: &[TableName],
) -> Result<ProjectionEffects, String> {
    let PendingFact {
        fact_id,
        fact,
        previous_context,
        projection_context,
    } = pending_fact;
    let run = run_projection_with_context(projector, &fact, &previous_context, projection_context)?;
    validate_intents(&run.intents)?;
    validate_intents(&run.local_intents)?;
    validate_row_mutations(&run.row_mutations, allowed_tables)?;
    Ok(ProjectionEffects::from_run(fact_id, previous_context, run))
}

/// Update compatibility memory and the report after a projection commit.
///
/// This function runs after SQLite has accepted the durable work and any
/// restart-local temp rows.
fn finish_pending_fact(
    commit: ProjectionCommit,
    report: &mut PipelineReport,
) -> Result<(), String> {
    let intents = commit.persisted_intents + commit.local_intents;

    report.projections += 1;
    report.intents += intents;
    Ok(())
}

/// A fact that has been claimed from the pending queue and is ready to project.
struct PendingFact {
    fact_id: FactId,
    fact: Fact,
    previous_context: ContextSet,
    projection_context: ProjectionContext,
}

/// The uncommitted output of projecting one pending fact.
struct ProjectionEffects {
    fact_id: FactId,
    previous_context: ContextSet,
    next_context: ContextSet,
    next_time_wakes: Vec<TimeWake>,
    context_delta: ContextSetDelta,
    row_mutations: Vec<RowMutation>,
    durable_intents: Vec<Intent>,
    local_intents: Vec<Intent>,
}

impl ProjectionEffects {
    fn from_run(fact_id: FactId, previous_context: ContextSet, run: ProjectionRun) -> Self {
        Self {
            fact_id,
            previous_context,
            next_context: run.context,
            next_time_wakes: run.time_wakes,
            context_delta: run.context_delta,
            row_mutations: run.row_mutations,
            durable_intents: run.intents,
            local_intents: run.local_intents,
        }
    }
}

/// The pure result of running one projector before any SQL writes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionRun {
    context: ContextSet,
    context_delta: ContextSetDelta,
    time_wakes: Vec<TimeWake>,
    row_mutations: Vec<RowMutation>,
    intents: Vec<Intent>,
    local_intents: Vec<Intent>,
}

/// Call the protocol projector and normalize the output for the SQL pipeline.
///
/// Projection output is the complete replacement context for this fact. This
/// helper enforces that projectors only own their own context/time rows, then
/// computes the context delta that will wake dependent facts after commit.
fn run_projection_with_context(
    projector: &(impl Projector + ?Sized),
    fact: &Fact,
    previous_context: &ContextSet,
    context: ProjectionContext,
) -> Result<ProjectionRun, String> {
    let output = projector.project(fact, &context)?;
    enforce_owner_is_self(fact, &output)?;
    let context = output.context_set();
    let context_delta = diff_context_sets(previous_context, &context);
    Ok(ProjectionRun {
        context,
        context_delta,
        time_wakes: output.time_wakes,
        row_mutations: output.row_mutations,
        intents: output.intents,
        local_intents: output.local_intents,
    })
}

/// Reject any projected need, offer, or time wake whose `owner` is not the fact
/// being projected.
fn enforce_owner_is_self(fact: &Fact, output: &ProjectionOutput) -> Result<(), String> {
    for need in &output.needs {
        if need.owner != fact.id {
            return Err(format!(
                "projector emitted need with owner {:x?} that is not the projected fact {:x?}",
                need.owner, fact.id
            ));
        }
    }
    for offer in &output.offers {
        if offer.owner != fact.id {
            return Err(format!(
                "projector emitted offer with owner {:x?} that is not the projected fact {:x?}",
                offer.owner, fact.id
            ));
        }
    }
    for wake in &output.time_wakes {
        if wake.owner != fact.id {
            return Err(format!(
                "projector emitted time wake with owner {:x?} that is not the projected fact {:x?}",
                wake.owner, fact.id
            ));
        }
    }
    Ok(())
}

/// The committed SQL result needed to update memory and reporting.
struct ProjectionCommit {
    persisted_intents: usize,
    local_intents: usize,
}

/// Commit all durable projection effects in one SQLite transaction.
///
/// Transaction contents:
///
/// - Clear this fact's pending row.
/// - Replace this fact's standing context.
/// - Replace this fact's time wakes.
/// - Record the pending context change.
/// - Apply row mutations.
/// - Record durable intents.
/// - Record restart-local intents in the temp local queue.
fn commit_projection_effects(
    store: &Store,
    effects: &ProjectionEffects,
    allowed_tables: &[TableName],
) -> Result<ProjectionCommit, String> {
    store
        .write_transaction(|tx| {
            tx.delete_table_rows_in_tx(PENDING_PROJECTION, vec![effects.fact_id.to_vec()])?;
            delete_pending_time_ranges_for_owner_in_tx(tx, effects.fact_id)?;
            replace_stored_context_owner_rows_from_previous(
                tx,
                &effects.previous_context,
                &effects.next_context,
            )?;
            replace_stored_time_wake_owner_rows(tx, effects.fact_id, &effects.next_time_wakes)?;

            tx.insert_table_rows_in_tx(pending_context_change_rows(&effects.context_delta))?;

            let (rows, deletes) = row_mutation_rows(&effects.row_mutations, allowed_tables)
                .map_err(sqlite_string_error)?;
            tx.insert_table_rows_in_tx(rows)?;
            for delete in deletes {
                tx.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
            }

            let mut persisted_intents = 0usize;
            for intent in &effects.durable_intents {
                if record_intent_in_tx(tx, intent)? {
                    persisted_intents += 1;
                }
            }

            let mut local_intents = 0usize;
            for intent in &effects.local_intents {
                if record_intent_in_table_in_tx(tx, LOCAL_INTENTS, intent)? {
                    local_intents += 1;
                }
            }

            Ok(ProjectionCommit {
                persisted_intents,
                local_intents,
            })
        })
        .map_err(|err| format!("commit projection effects: {err}"))
}

/// Replace this fact's standing needs/offers using the previous key set.
///
/// Projection owns the complete context set for its fact. Deleting exactly the
/// previous rows avoids wiping rows emitted by other facts with the same role.
fn replace_stored_context_owner_rows_from_previous(
    store: &Store,
    previous: &ContextSet,
    context: &ContextSet,
) -> rusqlite::Result<()> {
    store.delete_table_rows_in_tx(
        CONTEXT_NEEDS,
        previous
            .needs
            .iter()
            .map(|need| context_need_row(need).key)
            .collect(),
    )?;
    store.delete_table_rows_in_tx(
        CONTEXT_OFFERS,
        previous
            .offers
            .iter()
            .map(|offer| context_offer_row(offer).key)
            .collect(),
    )?;
    store.insert_table_rows_in_tx(context.needs.iter().map(context_need_row).collect())?;
    store.insert_table_rows_in_tx(context.offers.iter().map(context_offer_row).collect())?;
    Ok(())
}

/// Replace all time wakes owned by this fact.
///
/// Time wakes are not appended: projection output is the complete current
/// schedule for the owner, so old rows must disappear when the projection no
/// longer emits them.
fn replace_stored_time_wake_owner_rows(
    store: &Store,
    owner: FactId,
    wakes: &[TimeWake],
) -> rusqlite::Result<()> {
    let delete_keys = store
        .table_rows_with_key_prefix(TIME_WAKES, &owner, usize::MAX)?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    store.delete_table_rows_in_tx(TIME_WAKES, delete_keys)?;
    store.insert_table_rows_in_tx(wakes.iter().map(time_wake_row).collect())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
    use crate::core::facts::FactScope;
    use crate::core::intents::IntentKind;
    use crate::core::projectors::Timeline;

    #[test]
    fn projection_run_rejects_offer_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = BadOfferOwnerProjector;

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign offer owner");

        assert!(err.contains("projector emitted offer with owner"));
    }

    #[test]
    fn projection_run_rejects_need_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = BadNeedOwnerProjector;

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign need owner");

        assert!(err.contains("projector emitted need with owner"));
    }

    #[test]
    fn projection_run_rejects_time_wake_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = BadTimeWakeOwnerProjector;

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign time-wake owner");

        assert!(err.contains("projector emitted time wake with owner"));
    }

    #[test]
    fn projection_run_diffs_standing_context_without_self_waking() {
        let fact = Fact::new(FactScope::Global, 1, b"stable".to_vec());
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([9; 32]);
        let projector = NeedUntilOffer {
            role,
            selector,
            intent_kind: IntentKind::new("followup").unwrap(),
        };

        let first =
            run_projection(&projector, &fact, &ContextSet::new(), Vec::new()).expect("first run");
        assert_eq!(first.context_delta.added_needs.len(), 1);
        assert_eq!(first.context_delta.removed_needs.len(), 0);

        let second =
            run_projection(&projector, &fact, &first.context, Vec::new()).expect("second run");
        assert!(second.context_delta.is_empty());
        assert_eq!(second.context, first.context);
        assert!(second.intents.is_empty());
    }

    #[test]
    fn projection_run_replaces_need_with_intent_when_context_appears() {
        let fact = Fact::new(FactScope::Global, 1, b"recoverable".to_vec());
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([9; 32]);
        let projector = NeedUntilOffer {
            role: role.clone(),
            selector: selector.clone(),
            intent_kind: IntentKind::new("followup").unwrap(),
        };
        let previous = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect("previous projection")
            .context;
        let offer = ContextOffer {
            owner: [2; 32],
            role,
            scope: FactScope::Global,
            selector,
        };

        let next = run_projection(&projector, &fact, &previous, vec![offer])
            .expect("projection with context");

        assert!(next.context.needs.is_empty());
        assert_eq!(next.context_delta.removed_needs, previous.needs);
        assert_eq!(next.context_delta.added_needs.len(), 0);
        assert_eq!(next.intents.len(), 1);
        assert_eq!(next.intents[0].kind.as_str(), "followup");
    }

    fn run_projection(
        projector: &impl Projector,
        fact: &Fact,
        previous_context: &ContextSet,
        offers: Vec<ContextOffer>,
    ) -> Result<ProjectionRun, String> {
        run_projection_with_context(
            projector,
            fact,
            previous_context,
            ProjectionContext::new(offers),
        )
    }

    struct NeedUntilOffer {
        role: Role,
        selector: Selector,
        intent_kind: IntentKind,
    }

    impl Projector for NeedUntilOffer {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if context.offers().is_empty() {
                Ok(ProjectionOutput::new().need(ContextNeed {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                }))
            } else {
                Ok(ProjectionOutput::new().intent(Intent::new(
                    self.intent_kind.clone(),
                    fact.id,
                    context.offer_owners().next().unwrap_or(fact.id),
                )))
            }
        }
    }

    struct BadOfferOwnerProjector;

    impl Projector for BadOfferOwnerProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().offer(ContextOffer {
                owner: [9; 32],
                role: Role::new("exact").unwrap(),
                scope: fact.scope.clone(),
                selector: Selector::from_bytes(fact.id),
            }))
        }
    }

    struct BadNeedOwnerProjector;

    impl Projector for BadNeedOwnerProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().need(ContextNeed {
                owner: [9; 32],
                role: Role::new("exact").unwrap(),
                scope: fact.scope.clone(),
                selector: Selector::from_bytes(fact.id),
            }))
        }
    }

    struct BadTimeWakeOwnerProjector;

    impl Projector for BadTimeWakeOwnerProjector {
        fn project(
            &self,
            _fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().time_wake(TimeWake {
                owner: [9; 32],
                timeline: Timeline::new("test").unwrap(),
                at: 1,
            }))
        }
    }
}
