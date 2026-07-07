//! Protocol-neutral projection wake loop.
//!
//! This module owns the small cycle that every fact follows:
//!
//! ```text
//! submit fact -> pending projection -> projector output
//!             -> replace standing context
//!             -> context delta matching for new needs/offers
//!             -> wake matched owners
//!             -> collect intent output
//! ```
//!
//! The wake loop is deliberately below storage in this slice. The row schemas
//! already name durable tables for facts, context, pending projection, and
//! intents. Ephemeral intents share the same in-process scheduling machinery
//! but are deliberately skipped by persistence; this module first makes the
//! semantics crisp enough to persist without carrying forward the old lifecycle
//! vocabulary.

use crate::core::context::{
    ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role, Selector,
};
use crate::core::facts::{fact_id, Fact, FactId, FactScope, ScopeKind};
use crate::core::handler_dispatch::{retry_intent_reason, HandlerContext, IntentHandler};
use crate::core::intents::{AtomicIntent, Intent, IntentExecution, IntentKind, TableDelete};
use crate::core::matchers::{match_context_delta, ContextMatch, ContextMatcher};
use crate::core::projection::{
    run_projection_with_context, MatchedContext, ProjectionContext, Projector, TimeRange, TimeWake,
    Timeline,
};
use crate::core::store::{Store, TableName, TableRow};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const FACTS: TableName = TableName::new("facts");
pub const NEEDS: TableName = TableName::new("needs");
pub const OFFERS: TableName = TableName::new("offers");
pub const TIME_WAKES: TableName = TableName::new("time_wakes");
pub const PENDING_PROJECTION: TableName = TableName::new("pending_projection");
pub const INTENTS: TableName = TableName::new("intents");

type ExactContextKey = (Role, FactScope, Selector);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    pub projections: usize,
    pub context_matches: usize,
    pub wakes: usize,
    pub intents: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispatchReport {
    pub handled: usize,
    pub facts: usize,
    pub intents: usize,
    pub retries: usize,
}

#[derive(Debug, Default)]
pub struct WakeLoop {
    facts: BTreeMap<FactId, Fact>,
    context_by_owner: BTreeMap<FactId, ContextSet>,
    needs_by_exact_key: BTreeMap<ExactContextKey, BTreeSet<ContextNeed>>,
    offers_by_exact_key: BTreeMap<ExactContextKey, BTreeSet<ContextOffer>>,
    time_wakes_by_owner: BTreeMap<FactId, Vec<TimeWake>>,
    pending_time_ranges: BTreeMap<FactId, Vec<TimeRange>>,
    pending_projection: VecDeque<FactId>,
    pending_owners: BTreeSet<FactId>,
    intents: Vec<Intent>,
    intent_keys: BTreeMap<Vec<u8>, usize>,
    pending_atomic_row_intents: Vec<Intent>,
    dirty_facts: BTreeSet<FactId>,
    deleted_facts: BTreeSet<FactId>,
    dirty_context_owners: BTreeSet<FactId>,
    dirty_time_wake_owners: BTreeSet<FactId>,
    dirty_pending_owners: BTreeSet<FactId>,
    dirty_intent_keys: BTreeSet<Vec<u8>>,
    deleted_intent_keys: BTreeSet<Vec<u8>>,
}

impl WakeLoop {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(store: &Store) -> Result<Self, String> {
        let mut bus = Self::new();
        for (key, value) in store
            .table_rows(FACTS)
            .map_err(|err| format!("load facts: {err}"))?
        {
            let fact = decode_fact_row(&key, &value)?;
            bus.facts.insert(fact.id, fact);
        }
        for (_, value) in store
            .table_rows(NEEDS)
            .map_err(|err| format!("load needs: {err}"))?
        {
            let need = decode_need(&value)?;
            bus.context_by_owner
                .entry(need.owner)
                .or_default()
                .needs
                .push(need);
        }
        for (_, value) in store
            .table_rows(OFFERS)
            .map_err(|err| format!("load offers: {err}"))?
        {
            let offer = decode_offer(&value)?;
            bus.context_by_owner
                .entry(offer.owner)
                .or_default()
                .offers
                .push(offer);
        }
        for context in bus.context_by_owner.values_mut() {
            *context = std::mem::take(context).normalized();
        }
        bus.rebuild_context_indexes();
        for (_, value) in store
            .table_rows(TIME_WAKES)
            .map_err(|err| format!("load time wakes: {err}"))?
        {
            let wake = decode_time_wake(&value)?;
            bus.time_wakes_by_owner
                .entry(wake.owner)
                .or_default()
                .push(wake);
        }
        for wakes in bus.time_wakes_by_owner.values_mut() {
            wakes.sort();
            wakes.dedup();
        }
        for (key, _) in store
            .table_rows(PENDING_PROJECTION)
            .map_err(|err| format!("load pending projection: {err}"))?
        {
            let owner = decode_fact_id(&key)?;
            if !bus.facts.contains_key(&owner) {
                return Err(format!(
                    "pending projection references unknown fact {owner:?}"
                ));
            }
            if bus.pending_owners.insert(owner) {
                bus.pending_projection.push_back(owner);
            }
        }
        for (_, value) in store
            .table_rows(INTENTS)
            .map_err(|err| format!("load intents: {err}"))?
        {
            let intent = decode_intent(&value)?;
            if intent.execution == IntentExecution::Ephemeral {
                return Err("stored wake loop intent cannot be ephemeral".to_string());
            }
            bus.submit_intent(intent)?;
        }
        bus.clear_dirty();
        Ok(bus)
    }

    pub fn save(&mut self, store: &Store) -> Result<(), String> {
        if !self.pending_atomic_row_intents.is_empty() {
            return Err(
                "wake loop has unapplied atomic row intents; call save_applying_atomic_rows"
                    .to_string(),
            );
        }
        self.save_inner(store, &[])
    }

    pub fn save_applying_atomic_rows(
        &mut self,
        store: &Store,
        allowed_tables: &[TableName],
    ) -> Result<(), String> {
        self.save_inner(store, allowed_tables)
    }

    pub fn rebase_dirty_onto(&self, mut base: WakeLoop) -> Result<WakeLoop, String> {
        for id in &self.deleted_facts {
            base.purge_fact(*id);
        }
        for id in &self.dirty_facts {
            if let Some(fact) = self.facts.get(id).cloned() {
                base.submit_fact(fact);
            }
        }
        for owner in &self.dirty_context_owners {
            base.replace_context(
                *owner,
                self.context_by_owner
                    .get(owner)
                    .cloned()
                    .unwrap_or_default(),
            );
            if base.facts.contains_key(owner) {
                base.wake(*owner);
            }
        }
        for owner in &self.dirty_time_wake_owners {
            if let Some(wakes) = self.time_wakes_by_owner.get(owner).cloned() {
                base.replace_time_wakes(*owner, wakes);
            } else {
                base.replace_time_wakes(*owner, Vec::new());
            }
        }
        for owner in &self.dirty_pending_owners {
            if self.pending_owners.contains(owner) {
                base.wake(*owner);
            } else {
                base.remove_pending(owner);
            }
        }
        for key in &self.deleted_intent_keys {
            base.remove_intent_key(key)?;
        }
        for intent in self
            .intents
            .iter()
            .filter(|intent| self.dirty_intent_keys.contains(&intent_row_key(intent)))
            .cloned()
        {
            base.record_intent(intent)?;
        }
        for intent in self
            .intents
            .iter()
            .filter(|intent| intent.execution == IntentExecution::Ephemeral)
            .cloned()
        {
            base.record_intent(intent)?;
        }
        base.pending_atomic_row_intents
            .extend(self.pending_atomic_row_intents.iter().cloned());
        Ok(base)
    }

    fn save_inner(&mut self, store: &Store, allowed_tables: &[TableName]) -> Result<(), String> {
        let fact_rows = self.dirty_fact_rows();
        let deleted_fact_keys = self
            .deleted_facts
            .iter()
            .map(|id| id.to_vec())
            .collect::<Vec<_>>();
        let dirty_context_owners = self
            .dirty_context_owners
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let dirty_time_wake_owners = self
            .dirty_time_wake_owners
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let pending_rows = self.dirty_pending_rows();
        let deleted_pending_keys = self
            .dirty_pending_owners
            .iter()
            .filter(|owner| !self.pending_owners.contains(*owner))
            .map(|owner| owner.to_vec())
            .collect::<Vec<_>>();
        let intent_rows = self.dirty_intent_rows();
        let deleted_intent_keys = self.deleted_intent_keys.iter().cloned().collect::<Vec<_>>();
        let (atomic_rows, atomic_deletes) =
            atomic_row_mutations(&self.pending_atomic_row_intents, allowed_tables)?;

        store
            .write_transaction(|tx| {
                tx.delete_table_rows_in_tx(FACTS, deleted_fact_keys)?;
                tx.insert_table_rows_in_tx(fact_rows)?;
                replace_context_owner_rows(tx, &dirty_context_owners, self)?;
                replace_time_wake_owner_rows(tx, &dirty_time_wake_owners, self)?;
                tx.delete_table_rows_in_tx(PENDING_PROJECTION, deleted_pending_keys)?;
                tx.insert_table_rows_in_tx(pending_rows)?;
                tx.delete_table_rows_in_tx(INTENTS, deleted_intent_keys)?;
                tx.insert_table_rows_in_tx(intent_rows)?;
                tx.insert_table_rows_in_tx(atomic_rows)?;
                for delete in atomic_deletes {
                    tx.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
                }
                Ok(())
            })
            .map_err(|err| format!("save wake loop: {err}"))?;
        self.clear_dirty();
        self.pending_atomic_row_intents.clear();
        Ok(())
    }

    pub fn submit_fact(&mut self, fact: Fact) -> bool {
        let id = fact.id;
        if self.facts.insert(id, fact).is_some() {
            return false;
        }
        self.deleted_facts.remove(&id);
        self.dirty_facts.insert(id);
        self.wake(id)
    }

    pub fn has_fact(&self, id: &FactId) -> bool {
        self.facts.contains_key(id)
    }

    pub fn facts(&self) -> impl Iterator<Item = &Fact> {
        self.facts.values()
    }

    pub fn context(&self, owner: &FactId) -> Option<&ContextSet> {
        self.context_by_owner.get(owner)
    }

    pub fn pending_len(&self) -> usize {
        self.pending_projection.len()
    }

    pub fn intents(&self) -> &[Intent] {
        &self.intents
    }

    pub fn take_intents(&mut self) -> Vec<Intent> {
        for intent in &self.intents {
            self.deleted_intent_keys.insert(intent_row_key(intent));
        }
        self.intent_keys.clear();
        std::mem::take(&mut self.intents)
    }

    pub fn submit_intent(&mut self, intent: Intent) -> Result<bool, String> {
        self.record_intent(intent)
    }

    pub fn wake_time_range(
        &mut self,
        timeline: Timeline,
        start_exclusive: Option<u64>,
        end_inclusive: u64,
        limit: usize,
    ) -> usize {
        if limit == 0 {
            return 0;
        }
        let range = TimeRange {
            timeline,
            start_exclusive,
            end_inclusive,
        };
        let mut due = self
            .time_wakes_by_owner
            .values()
            .flat_map(|wakes| wakes.iter())
            .filter(|wake| wake.timeline == range.timeline && range.contains(wake.at))
            .cloned()
            .collect::<Vec<_>>();
        due.sort_by(|left, right| {
            left.at
                .cmp(&right.at)
                .then_with(|| left.owner.cmp(&right.owner))
                .then_with(|| left.timeline.cmp(&right.timeline))
        });
        due.dedup();

        let mut matched = 0usize;
        for wake in due.into_iter().take(limit) {
            self.pending_time_ranges
                .entry(wake.owner)
                .or_default()
                .push(range.clone());
            self.wake(wake.owner);
            matched += 1;
        }
        matched
    }

    pub fn dispatch_intents(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        context: &HandlerContext,
        limit: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_intents_matching(handler, context, limit, |_| true)
    }

    pub fn dispatch_atomic_intents(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        context: &HandlerContext,
        limit: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_intents_matching(handler, context, limit, |intent| {
            intent.execution == IntentExecution::Atomic
        })
    }

    pub fn dispatch_deferred_intents(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        context: &HandlerContext,
        limit: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_intents_matching(handler, context, limit, |intent| {
            intent.execution == IntentExecution::Deferred
        })
    }

    pub fn dispatch_ephemeral_intents(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        context: &HandlerContext,
        limit: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_intents_matching(handler, context, limit, |intent| {
            intent.execution == IntentExecution::Ephemeral
        })
    }

    pub fn dispatch_deferred_intents_with_fact_context(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        limit: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_deferred_intents_with_optional_store(handler, None, limit)
    }

    pub fn dispatch_deferred_intents_with_fact_context_and_store(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        store: &Store,
        limit: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_deferred_intents_with_optional_store(handler, Some(store), limit)
    }

    pub fn dispatch_ephemeral_intents_with_fact_context(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        limit: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_intents_with_fact_context_for_execution(
            handler,
            IntentExecution::Ephemeral,
            None,
            limit,
        )
    }

    pub fn dispatch_ephemeral_intents_with_fact_context_and_store(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        store: &Store,
        limit: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_intents_with_fact_context_for_execution(
            handler,
            IntentExecution::Ephemeral,
            Some(store),
            limit,
        )
    }

    fn dispatch_deferred_intents_with_optional_store(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        store: Option<&Store>,
        limit: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_intents_with_fact_context_for_execution(
            handler,
            IntentExecution::Deferred,
            store,
            limit,
        )
    }

    fn dispatch_intents_with_fact_context_for_execution(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        execution: IntentExecution,
        store: Option<&Store>,
        limit: usize,
    ) -> Result<DispatchReport, String> {
        let mut report = DispatchReport::default();
        while report.handled < limit {
            let Some((intent_index, intent)) =
                self.pop_next_intent_matching(handler, |intent| intent.execution == execution)?
            else {
                break;
            };
            let input_ids = match handler.input_fact_ids(&intent) {
                Ok(input_ids) => input_ids,
                Err(err) => {
                    self.restore_intent(intent_index, intent)?;
                    return Err(err);
                }
            };
            let mut context_facts = BTreeMap::new();
            for fact_id in input_ids {
                if let Some(fact) = self.facts.get(&fact_id).cloned() {
                    context_facts.insert(fact_id, fact);
                }
            }
            let mut context = HandlerContext::with_facts(context_facts.into_values());
            if let Some(store) = store {
                context = context.with_store(store);
            }
            let output = match handler.handle(&intent, &context) {
                Ok(output) => output,
                Err(err) => {
                    self.restore_intent(intent_index, intent)?;
                    if retry_intent_reason(&err).is_some() {
                        report.retries += 1;
                        break;
                    }
                    if err.starts_with("handler context missing fact ") {
                        report.retries += 1;
                        break;
                    }
                    return Err(err);
                }
            };
            if let Err(err) = self.validate_intents(&output.intents) {
                self.restore_intent(intent_index, intent)?;
                return Err(err);
            }
            for purged in output.purged_facts {
                self.purge_fact(purged);
            }
            for fact in output.facts {
                if self.submit_fact(fact) {
                    report.facts += 1;
                }
            }
            for intent in output.intents {
                if self.record_intent(intent)? {
                    report.intents += 1;
                }
            }
            report.handled += 1;
        }
        Ok(report)
    }

    fn dispatch_intents_matching(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        context: &HandlerContext,
        limit: usize,
        accepts_execution: impl Fn(&Intent) -> bool,
    ) -> Result<DispatchReport, String> {
        let mut report = DispatchReport::default();
        while report.handled < limit {
            let Some((intent_index, intent)) =
                self.pop_next_intent_matching(handler, &accepts_execution)?
            else {
                break;
            };
            let output = match handler.handle(&intent, context) {
                Ok(output) => output,
                Err(err) => {
                    self.restore_intent(intent_index, intent)?;
                    if retry_intent_reason(&err).is_some() {
                        report.retries += 1;
                        break;
                    }
                    return Err(err);
                }
            };
            if let Err(err) = self.validate_intents(&output.intents) {
                self.restore_intent(intent_index, intent)?;
                return Err(err);
            }
            for purged in output.purged_facts {
                self.purge_fact(purged);
            }
            for fact in output.facts {
                if self.submit_fact(fact) {
                    report.facts += 1;
                }
            }
            for intent in output.intents {
                if self.record_intent(intent)? {
                    report.intents += 1;
                }
            }
            report.handled += 1;
        }
        Ok(report)
    }

    pub fn drain(
        &mut self,
        projector: &impl Projector,
        matchers: &[&dyn ContextMatcher],
        limit: usize,
    ) -> Result<DrainReport, String> {
        self.drain_inner(projector, matchers, limit, None)
    }

    pub fn drain_applying_atomic_rows(
        &mut self,
        projector: &impl Projector,
        matchers: &[&dyn ContextMatcher],
        store: &Store,
        allowed_tables: &[TableName],
        limit: usize,
    ) -> Result<DrainReport, String> {
        let report = self.drain_inner(projector, matchers, limit, Some(allowed_tables))?;
        self.save_applying_atomic_rows(store, allowed_tables)?;
        Ok(report)
    }

    fn drain_inner(
        &mut self,
        projector: &impl Projector,
        matchers: &[&dyn ContextMatcher],
        limit: usize,
        atomic_rows: Option<&[TableName]>,
    ) -> Result<DrainReport, String> {
        let mut report = DrainReport::default();
        while report.projections < limit {
            let Some(owner) = self.pop_pending() else {
                break;
            };
            let Some(fact) = self.facts.get(&owner).cloned() else {
                continue;
            };
            let previous = self
                .context_by_owner
                .get(&owner)
                .cloned()
                .unwrap_or_default();
            let context = self
                .matching_context_for_owner(&owner, matchers)?
                .with_time_ranges(self.pending_time_ranges.remove(&owner).unwrap_or_default());
            let run = match run_projection_with_context(projector, &fact, &previous, context) {
                Ok(run) => run,
                Err(err) => {
                    self.restore_pending(owner);
                    return Err(err);
                }
            };
            if let Err(err) = self.validate_intents(&run.intents) {
                self.restore_pending(owner);
                return Err(err);
            }
            if let Some(allowed_tables) = atomic_rows {
                if let Err(err) = validate_atomic_row_intents(&run.intents, allowed_tables) {
                    self.restore_pending(owner);
                    return Err(err);
                }
            }
            self.replace_context(owner, run.context);
            self.replace_time_wakes(owner, run.time_wakes);
            report.projections += 1;
            report.context_matches +=
                self.wake_context_matches(&run.context_delta, matchers, &mut report);
            for intent in run.intents {
                if atomic_rows.is_some() && intent.execution == IntentExecution::Atomic {
                    self.pending_atomic_row_intents.push(intent);
                    report.intents += 1;
                    continue;
                }
                if self.record_intent(intent)? {
                    report.intents += 1;
                }
            }
        }
        Ok(report)
    }

    fn wake(&mut self, owner: FactId) -> bool {
        if !self.pending_owners.insert(owner) {
            return false;
        }
        self.pending_projection.push_back(owner);
        self.dirty_pending_owners.insert(owner);
        true
    }

    fn pop_pending(&mut self) -> Option<FactId> {
        let owner = self.pending_projection.pop_front()?;
        self.pending_owners.remove(&owner);
        self.dirty_pending_owners.insert(owner);
        Some(owner)
    }

    fn restore_pending(&mut self, owner: FactId) {
        if self.pending_owners.insert(owner) {
            self.pending_projection.push_front(owner);
            self.dirty_pending_owners.insert(owner);
        }
    }

    fn remove_pending(&mut self, owner: &FactId) {
        self.pending_owners.remove(owner);
        self.pending_projection.retain(|pending| pending != owner);
        self.dirty_pending_owners.insert(*owner);
    }

    fn replace_context(&mut self, owner: FactId, context: ContextSet) {
        if let Some(previous) = self.context_by_owner.get(&owner).cloned() {
            self.remove_context_from_indexes(&previous);
        }
        if context.needs.is_empty() && context.offers.is_empty() {
            self.context_by_owner.remove(&owner);
        } else {
            self.insert_context_into_indexes(&context);
            self.context_by_owner.insert(owner, context);
        }
        self.dirty_context_owners.insert(owner);
    }

    fn replace_time_wakes(&mut self, owner: FactId, mut wakes: Vec<TimeWake>) {
        wakes.sort();
        wakes.dedup();
        if wakes.is_empty() {
            self.time_wakes_by_owner.remove(&owner);
        } else {
            self.time_wakes_by_owner.insert(owner, wakes);
        }
        self.dirty_time_wake_owners.insert(owner);
    }

    pub fn purge_fact(&mut self, owner: FactId) -> bool {
        let mut changed = self.facts.remove(&owner).is_some();
        if changed {
            self.dirty_facts.remove(&owner);
            self.deleted_facts.insert(owner);
        }
        if let Some(context) = self.context_by_owner.remove(&owner) {
            self.remove_context_from_indexes(&context);
            self.dirty_context_owners.insert(owner);
            changed = true;
        }
        if self.time_wakes_by_owner.remove(&owner).is_some() {
            self.dirty_time_wake_owners.insert(owner);
            changed = true;
        }
        if self.pending_time_ranges.remove(&owner).is_some() {
            changed = true;
        }
        if self.pending_owners.remove(&owner) {
            self.dirty_pending_owners.insert(owner);
            changed = true;
        }
        let before = self.pending_projection.len();
        self.pending_projection.retain(|pending| pending != &owner);
        if self.pending_projection.len() != before {
            self.dirty_pending_owners.insert(owner);
            changed = true;
        }

        let mut dirty_context_owners = Vec::new();
        self.context_by_owner.retain(|context_owner, context| {
            let before = context.offers.len();
            context.offers.retain(|offer| offer.payload_ref != owner);
            if context.offers.len() != before {
                dirty_context_owners.push(*context_owner);
            }
            !(context.needs.is_empty() && context.offers.is_empty())
        });
        for context_owner in dirty_context_owners {
            self.dirty_context_owners.insert(context_owner);
        }
        if changed {
            self.rebuild_context_indexes();
        }
        changed
    }

    fn validate_intents(&self, intents: &[Intent]) -> Result<(), String> {
        let mut proposed = BTreeMap::<Vec<u8>, &Intent>::new();
        for intent in intents {
            let key = intent_row_key(intent);
            if let Some(existing_index) = self.intent_keys.get(&key) {
                if self.intents[*existing_index] != *intent {
                    return Err(format!(
                        "intent idempotence key conflict for {}",
                        intent.kind.as_str()
                    ));
                }
            }
            if let Some(existing) = proposed.insert(key, intent) {
                if existing != intent {
                    return Err(format!(
                        "projection emitted conflicting intents for {}",
                        intent.kind.as_str()
                    ));
                }
            }
        }
        Ok(())
    }

    fn record_intent(&mut self, intent: Intent) -> Result<bool, String> {
        let key = intent_row_key(&intent);
        if let Some(existing_index) = self.intent_keys.get(&key) {
            if self.intents[*existing_index] == intent {
                return Ok(false);
            }
            return Err(format!(
                "intent idempotence key conflict for {}",
                intent.kind.as_str()
            ));
        }
        self.deleted_intent_keys.remove(&key);
        self.dirty_intent_keys.insert(key.clone());
        self.intent_keys.insert(key, self.intents.len());
        self.intents.push(intent);
        Ok(true)
    }

    fn pop_next_intent_matching(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        accepts_execution: impl Fn(&Intent) -> bool,
    ) -> Result<Option<(usize, Intent)>, String> {
        let Some(index) = self
            .intents
            .iter()
            .position(|intent| accepts_execution(intent) && handler.accepts(intent))
        else {
            return Ok(None);
        };
        let intent = self.intents.remove(index);
        self.deleted_intent_keys.insert(intent_row_key(&intent));
        self.rebuild_intent_keys()?;
        Ok(Some((index, intent)))
    }

    fn restore_intent(&mut self, index: usize, intent: Intent) -> Result<(), String> {
        self.deleted_intent_keys.remove(&intent_row_key(&intent));
        let index = index.min(self.intents.len());
        self.intents.insert(index, intent);
        self.rebuild_intent_keys()
    }

    fn rebuild_intent_keys(&mut self) -> Result<(), String> {
        self.intent_keys.clear();
        for (index, intent) in self.intents.iter().enumerate() {
            let key = intent_row_key(intent);
            if self.intent_keys.insert(key, index).is_some() {
                return Err(format!(
                    "duplicate intent idempotence key for {}",
                    intent.kind.as_str()
                ));
            }
        }
        Ok(())
    }

    fn remove_intent_key(&mut self, key: &[u8]) -> Result<(), String> {
        let Some(index) = self.intent_keys.get(key).copied() else {
            return Ok(());
        };
        let intent = self.intents.remove(index);
        self.deleted_intent_keys.insert(intent_row_key(&intent));
        self.rebuild_intent_keys()
    }

    fn wake_context_matches(
        &mut self,
        delta: &ContextSetDelta,
        matchers: &[&dyn ContextMatcher],
        report: &mut DrainReport,
    ) -> usize {
        let mut matches = BTreeSet::new();
        let exact_roles = exact_matcher_roles(matchers);
        for need in delta
            .added_needs
            .iter()
            .filter(|need| exact_roles.contains(&need.role))
        {
            let key = exact_context_key(&need.role, &need.scope, &need.selector);
            if let Some(offers) = self.offers_by_exact_key.get(&key) {
                for offer in offers {
                    matches.insert(ContextMatch {
                        need_owner: need.owner,
                        offer_owner: offer.owner,
                        payload_ref: offer.payload_ref,
                    });
                }
            }
        }
        for offer in delta
            .added_offers
            .iter()
            .filter(|offer| exact_roles.contains(&offer.role))
        {
            let key = exact_context_key(&offer.role, &offer.scope, &offer.selector);
            if let Some(needs) = self.needs_by_exact_key.get(&key) {
                for need in needs {
                    matches.insert(ContextMatch {
                        need_owner: need.owner,
                        offer_owner: offer.owner,
                        payload_ref: offer.payload_ref,
                    });
                }
            }
        }

        let custom_matchers = relevant_custom_matchers_for_delta(matchers, delta);
        if !custom_matchers.is_empty() {
            let custom_roles = matcher_roles(&custom_matchers);
            let needs = self.all_needs_for_roles(&custom_roles);
            let offers = self.all_offers_for_roles(&custom_roles);
            matches.extend(match_context_delta(
                delta,
                &needs,
                &offers,
                &custom_matchers,
            ));
        }
        let mut matches = matches.into_iter().collect::<Vec<_>>();
        matches.sort_by_key(|matched| {
            (
                self.facts
                    .get(&matched.need_owner)
                    .map(|fact| fact.timestamp)
                    .unwrap_or(u64::MAX),
                matched.need_owner,
            )
        });
        for matched in &matches {
            if self.wake(matched.need_owner) {
                report.wakes += 1;
            }
        }
        matches.len()
    }

    fn matching_context_for_owner(
        &self,
        owner: &FactId,
        matchers: &[&dyn ContextMatcher],
    ) -> Result<ProjectionContext, String> {
        let Some(context) = self.context_by_owner.get(owner) else {
            return Ok(ProjectionContext::new(Vec::new()));
        };
        let exact_roles = exact_matcher_roles(matchers);
        let custom_matchers = matchers
            .iter()
            .copied()
            .filter(|matcher| {
                matcher.exact_selector_role().is_none()
                    && context
                        .needs
                        .iter()
                        .any(|need| &need.role == matcher.role())
            })
            .collect::<Vec<_>>();
        let custom_offers = (!custom_matchers.is_empty()).then(|| {
            let custom_roles = matcher_roles(&custom_matchers);
            self.all_offers_for_roles(&custom_roles)
        });
        let mut matched = Vec::new();
        let mut seen = BTreeSet::new();
        for need in &context.needs {
            if exact_roles.contains(&need.role) {
                let key = exact_context_key(&need.role, &need.scope, &need.selector);
                if let Some(offers) = self.offers_by_exact_key.get(&key) {
                    for offer in offers {
                        if !seen.insert((need.clone(), offer.clone())) {
                            continue;
                        }
                        let payload = self
                            .facts
                            .get(&offer.payload_ref)
                            .ok_or_else(|| {
                                "context offer payload references unknown fact".to_string()
                            })?
                            .clone();
                        matched.push(MatchedContext {
                            need: need.clone(),
                            offer: offer.clone(),
                            payload,
                        });
                    }
                }
            }

            for matcher in custom_matchers
                .iter()
                .copied()
                .filter(|matcher| matcher.role() == &need.role)
            {
                for offer in custom_offers
                    .as_ref()
                    .into_iter()
                    .flat_map(|offers| offers.iter())
                    .filter(|offer| offer.role == need.role)
                {
                    let offer_matches = matcher
                        .match_new_need(need, std::slice::from_ref(offer))
                        .into_iter()
                        .any(|context_match| {
                            context_match.need_owner == need.owner
                                && context_match.offer_owner == offer.owner
                                && context_match.payload_ref == offer.payload_ref
                        });
                    if !offer_matches || !seen.insert((need.clone(), offer.clone())) {
                        continue;
                    }
                    let payload = self
                        .facts
                        .get(&offer.payload_ref)
                        .ok_or_else(|| "context offer payload references unknown fact".to_string())?
                        .clone();
                    matched.push(MatchedContext {
                        need: need.clone(),
                        offer: offer.clone(),
                        payload,
                    });
                }
            }
        }
        Ok(ProjectionContext::from_matches(matched))
    }

    fn rebuild_context_indexes(&mut self) {
        self.needs_by_exact_key.clear();
        self.offers_by_exact_key.clear();
        let contexts = self.context_by_owner.values().cloned().collect::<Vec<_>>();
        for context in &contexts {
            self.insert_context_into_indexes(context);
        }
    }

    fn insert_context_into_indexes(&mut self, context: &ContextSet) {
        for need in &context.needs {
            self.needs_by_exact_key
                .entry(exact_context_key(&need.role, &need.scope, &need.selector))
                .or_default()
                .insert(need.clone());
        }
        for offer in &context.offers {
            self.offers_by_exact_key
                .entry(exact_context_key(
                    &offer.role,
                    &offer.scope,
                    &offer.selector,
                ))
                .or_default()
                .insert(offer.clone());
        }
    }

    fn remove_context_from_indexes(&mut self, context: &ContextSet) {
        for need in &context.needs {
            let key = exact_context_key(&need.role, &need.scope, &need.selector);
            let should_remove = if let Some(needs) = self.needs_by_exact_key.get_mut(&key) {
                needs.remove(need);
                needs.is_empty()
            } else {
                false
            };
            if should_remove {
                self.needs_by_exact_key.remove(&key);
            }
        }
        for offer in &context.offers {
            let key = exact_context_key(&offer.role, &offer.scope, &offer.selector);
            let should_remove = if let Some(offers) = self.offers_by_exact_key.get_mut(&key) {
                offers.remove(offer);
                offers.is_empty()
            } else {
                false
            };
            if should_remove {
                self.offers_by_exact_key.remove(&key);
            }
        }
    }

    fn all_needs_for_roles(&self, roles: &BTreeSet<Role>) -> Vec<ContextNeed> {
        self.context_by_owner
            .values()
            .flat_map(|context| {
                context
                    .needs
                    .iter()
                    .filter(|need| roles.contains(&need.role))
                    .cloned()
            })
            .collect()
    }

    fn all_offers_for_roles(&self, roles: &BTreeSet<Role>) -> Vec<ContextOffer> {
        self.context_by_owner
            .values()
            .flat_map(|context| {
                context
                    .offers
                    .iter()
                    .filter(|offer| roles.contains(&offer.role))
                    .cloned()
            })
            .collect()
    }

    fn dirty_fact_rows(&self) -> Vec<TableRow> {
        self.dirty_facts
            .iter()
            .filter_map(|id| self.facts.get(id))
            .map(fact_row)
            .collect()
    }

    fn dirty_pending_rows(&self) -> Vec<TableRow> {
        self.dirty_pending_owners
            .iter()
            .filter(|owner| self.pending_owners.contains(*owner))
            .map(|owner| TableRow {
                table: PENDING_PROJECTION,
                key: owner.to_vec(),
                value: Vec::new(),
            })
            .collect()
    }

    fn dirty_intent_rows(&self) -> Vec<TableRow> {
        self.intents
            .iter()
            .filter(|intent| intent.execution != IntentExecution::Ephemeral)
            .filter(|intent| self.dirty_intent_keys.contains(&intent_row_key(intent)))
            .map(intent_row)
            .collect()
    }

    fn clear_dirty(&mut self) {
        self.dirty_facts.clear();
        self.deleted_facts.clear();
        self.dirty_context_owners.clear();
        self.dirty_time_wake_owners.clear();
        self.dirty_pending_owners.clear();
        self.dirty_intent_keys.clear();
        self.deleted_intent_keys.clear();
    }
}

fn exact_context_key(role: &Role, scope: &FactScope, selector: &Selector) -> ExactContextKey {
    (role.clone(), scope.clone(), selector.clone())
}

fn exact_matcher_roles(matchers: &[&dyn ContextMatcher]) -> BTreeSet<Role> {
    matchers
        .iter()
        .filter_map(|matcher| matcher.exact_selector_role().cloned())
        .collect()
}

fn relevant_custom_matchers_for_delta<'a>(
    matchers: &[&'a dyn ContextMatcher],
    delta: &ContextSetDelta,
) -> Vec<&'a dyn ContextMatcher> {
    matchers
        .iter()
        .copied()
        .filter(|matcher| {
            matcher.exact_selector_role().is_none()
                && (delta
                    .added_needs
                    .iter()
                    .any(|need| &need.role == matcher.role())
                    || delta
                        .added_offers
                        .iter()
                        .any(|offer| &offer.role == matcher.role()))
        })
        .collect()
}

fn matcher_roles(matchers: &[&dyn ContextMatcher]) -> BTreeSet<Role> {
    matchers
        .iter()
        .map(|matcher| matcher.role().clone())
        .collect()
}

fn replace_context_owner_rows(
    store: &Store,
    owners: &[FactId],
    wake_loop: &WakeLoop,
) -> rusqlite::Result<()> {
    let mut need_delete_keys = Vec::new();
    let mut offer_delete_keys = Vec::new();
    let mut need_rows = Vec::new();
    let mut offer_rows = Vec::new();

    for owner in owners {
        need_delete_keys.extend(
            store
                .table_rows_with_key_prefix(NEEDS, owner, usize::MAX)?
                .into_iter()
                .map(|(key, _)| key),
        );
        offer_delete_keys.extend(
            store
                .table_rows_with_key_prefix(OFFERS, owner, usize::MAX)?
                .into_iter()
                .map(|(key, _)| key),
        );
        if let Some(context) = wake_loop.context_by_owner.get(owner) {
            need_rows.extend(context.needs.iter().map(need_row));
            offer_rows.extend(context.offers.iter().map(offer_row));
        }
    }

    store.delete_table_rows_in_tx(NEEDS, need_delete_keys)?;
    store.delete_table_rows_in_tx(OFFERS, offer_delete_keys)?;
    store.insert_table_rows_in_tx(need_rows)?;
    store.insert_table_rows_in_tx(offer_rows)?;
    Ok(())
}

fn replace_time_wake_owner_rows(
    store: &Store,
    owners: &[FactId],
    wake_loop: &WakeLoop,
) -> rusqlite::Result<()> {
    let mut delete_keys = Vec::new();
    let mut rows = Vec::new();

    for owner in owners {
        delete_keys.extend(
            store
                .table_rows_with_key_prefix(TIME_WAKES, owner, usize::MAX)?
                .into_iter()
                .map(|(key, _)| key),
        );
        if let Some(wakes) = wake_loop.time_wakes_by_owner.get(owner) {
            rows.extend(wakes.iter().map(time_wake_row));
        }
    }

    store.delete_table_rows_in_tx(TIME_WAKES, delete_keys)?;
    store.insert_table_rows_in_tx(rows)?;
    Ok(())
}

fn fact_row(fact: &Fact) -> TableRow {
    TableRow {
        table: FACTS,
        key: fact.id.to_vec(),
        value: encode_fact(fact),
    }
}

fn need_row(need: &ContextNeed) -> TableRow {
    let value = encode_need(need);
    TableRow {
        table: NEEDS,
        key: context_row_key(need.owner, &value),
        value,
    }
}

fn offer_row(offer: &ContextOffer) -> TableRow {
    let value = encode_offer(offer);
    TableRow {
        table: OFFERS,
        key: context_row_key(offer.owner, &value),
        value,
    }
}

fn time_wake_row(wake: &TimeWake) -> TableRow {
    let value = encode_time_wake(wake);
    TableRow {
        table: TIME_WAKES,
        key: context_row_key(wake.owner, &value),
        value,
    }
}

fn intent_row(intent: &Intent) -> TableRow {
    let value = encode_intent(intent);
    TableRow {
        table: INTENTS,
        key: intent_row_key(intent),
        value,
    }
}

fn validate_atomic_row_intents(
    intents: &[Intent],
    allowed_tables: &[TableName],
) -> Result<(), String> {
    for intent in intents {
        if intent.execution == IntentExecution::Atomic {
            AtomicIntent::from_intent(intent, allowed_tables)?;
        }
    }
    Ok(())
}

fn atomic_row_mutations(
    intents: &[Intent],
    allowed_tables: &[TableName],
) -> Result<(Vec<TableRow>, Vec<TableDelete>), String> {
    let mut rows = Vec::new();
    let mut deletes = Vec::<TableDelete>::new();
    for intent in intents {
        if intent.execution != IntentExecution::Atomic {
            continue;
        }
        match AtomicIntent::from_intent(intent, allowed_tables)? {
            AtomicIntent::PutRow(row) => rows.push(row),
            AtomicIntent::DeleteRow(delete) => deletes.push(delete),
        }
    }
    Ok((rows, deletes))
}

fn context_row_key(owner: FactId, value: &[u8]) -> Vec<u8> {
    let mut key = owner.to_vec();
    key.extend_from_slice(blake3::hash(value).as_bytes());
    key
}

fn intent_row_key(intent: &Intent) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(intent.kind.as_str().as_bytes());
    hash.update(&[0]);
    hash.update(&intent.key);
    hash.finalize().as_bytes().to_vec()
}

fn encode_fact(fact: &Fact) -> Vec<u8> {
    let mut out = Vec::new();
    put_u8(&mut out, 1);
    put_u64(&mut out, fact.timestamp);
    encode_scope(&mut out, &fact.scope);
    put_bytes_u32(&mut out, &fact.bytes);
    out
}

pub fn persisted_fact(store: &Store, id: &FactId) -> Result<Option<Fact>, String> {
    store
        .table_row(FACTS, id)
        .map_err(|err| format!("load fact row: {err}"))?
        .map(|value| decode_fact_row(id, &value))
        .transpose()
}

pub fn persisted_facts(store: &Store) -> Result<Vec<Fact>, String> {
    store
        .table_rows(FACTS)
        .map_err(|err| format!("load fact rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_fact_row(&key, &value))
        .collect()
}

fn decode_fact_row(key: &[u8], value: &[u8]) -> Result<Fact, String> {
    let id = decode_fact_id(key)?;
    let mut reader = Reader::new(value);
    reader.expect_u8(1)?;
    let timestamp = reader.take_u64()?;
    let scope = decode_scope(&mut reader)?;
    let bytes = reader.take_bytes_u32()?.to_vec();
    reader.finish()?;
    if fact_id(&bytes) != id {
        return Err("fact row key does not match fact bytes".to_string());
    }
    Ok(Fact {
        id,
        scope,
        timestamp,
        bytes,
    })
}

fn encode_need(need: &ContextNeed) -> Vec<u8> {
    let mut out = Vec::new();
    put_u8(&mut out, 1);
    put_id(&mut out, &need.owner);
    put_string_u16(&mut out, need.role.as_str());
    encode_scope(&mut out, &need.scope);
    put_bytes_u32(&mut out, need.selector.as_bytes());
    out
}

fn decode_need(value: &[u8]) -> Result<ContextNeed, String> {
    let mut reader = Reader::new(value);
    reader.expect_u8(1)?;
    let owner = reader.take_id()?;
    let role = Role::new(reader.take_string_u16()?)?;
    let scope = decode_scope(&mut reader)?;
    let selector = Selector::from_bytes(reader.take_bytes_u32()?.to_vec());
    reader.finish()?;
    Ok(ContextNeed {
        owner,
        role,
        scope,
        selector,
    })
}

fn encode_offer(offer: &ContextOffer) -> Vec<u8> {
    let mut out = Vec::new();
    put_u8(&mut out, 1);
    put_id(&mut out, &offer.owner);
    put_string_u16(&mut out, offer.role.as_str());
    encode_scope(&mut out, &offer.scope);
    put_bytes_u32(&mut out, offer.selector.as_bytes());
    put_id(&mut out, &offer.payload_ref);
    out
}

fn decode_offer(value: &[u8]) -> Result<ContextOffer, String> {
    let mut reader = Reader::new(value);
    reader.expect_u8(1)?;
    let owner = reader.take_id()?;
    let role = Role::new(reader.take_string_u16()?)?;
    let scope = decode_scope(&mut reader)?;
    let selector = Selector::from_bytes(reader.take_bytes_u32()?.to_vec());
    let payload_ref = reader.take_id()?;
    reader.finish()?;
    Ok(ContextOffer {
        owner,
        role,
        scope,
        selector,
        payload_ref,
    })
}

fn encode_time_wake(wake: &TimeWake) -> Vec<u8> {
    let mut out = Vec::new();
    put_u8(&mut out, 1);
    put_id(&mut out, &wake.owner);
    put_string_u16(&mut out, wake.timeline.as_str());
    put_u64(&mut out, wake.at);
    out
}

fn decode_time_wake(value: &[u8]) -> Result<TimeWake, String> {
    let mut reader = Reader::new(value);
    reader.expect_u8(1)?;
    let owner = reader.take_id()?;
    let timeline = Timeline::new(reader.take_string_u16()?)?;
    let at = reader.take_u64()?;
    reader.finish()?;
    Ok(TimeWake {
        owner,
        timeline,
        at,
    })
}

fn encode_intent(intent: &Intent) -> Vec<u8> {
    let mut out = Vec::new();
    put_u8(&mut out, 1);
    put_string_u16(&mut out, intent.kind.as_str());
    put_u8(
        &mut out,
        match intent.execution {
            IntentExecution::Atomic => 0,
            IntentExecution::Deferred => 1,
            IntentExecution::Ephemeral => 2,
        },
    );
    put_bytes_u32(&mut out, &intent.key);
    put_bytes_u32(&mut out, &intent.payload);
    out
}

fn decode_intent(value: &[u8]) -> Result<Intent, String> {
    let mut reader = Reader::new(value);
    reader.expect_u8(1)?;
    let kind = IntentKind::new(reader.take_string_u16()?)?;
    let execution = match reader.take_u8()? {
        0 => IntentExecution::Atomic,
        1 => IntentExecution::Deferred,
        2 => IntentExecution::Ephemeral,
        other => return Err(format!("invalid intent execution tag {other}")),
    };
    let key = reader.take_bytes_u32()?.to_vec();
    let payload = reader.take_bytes_u32()?.to_vec();
    reader.finish()?;
    Ok(Intent::new(kind, execution, key, payload))
}

fn encode_scope(out: &mut Vec<u8>, scope: &FactScope) {
    match scope {
        FactScope::Global => put_u8(out, 0),
        FactScope::Local => put_u8(out, 1),
        FactScope::Scoped { kind, id } => {
            put_u8(out, 2);
            put_string_u16(out, kind.as_str());
            put_id(out, id);
        }
    }
}

fn decode_scope(reader: &mut Reader<'_>) -> Result<FactScope, String> {
    match reader.take_u8()? {
        0 => Ok(FactScope::Global),
        1 => Ok(FactScope::Local),
        2 => {
            let kind = ScopeKind::new(reader.take_string_u16()?)?;
            let id = reader.take_id()?;
            Ok(FactScope::Scoped { kind, id })
        }
        other => Err(format!("invalid fact scope tag {other}")),
    }
}

fn decode_fact_id(bytes: &[u8]) -> Result<FactId, String> {
    bytes
        .try_into()
        .map_err(|_| format!("expected 32-byte fact id, got {}", bytes.len()))
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_id(out: &mut Vec<u8>, id: &FactId) {
    out.extend_from_slice(id);
}

fn put_string_u16(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len()).expect("core vocabulary string length fits u16");
    put_u16(out, len);
    out.extend_from_slice(bytes);
}

fn put_bytes_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("core wake loop bytes length fits u32");
    put_u32(out, len);
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_u8(&mut self, expected: u8) -> Result<(), String> {
        let actual = self.take_u8()?;
        if actual == expected {
            Ok(())
        } else {
            Err(format!("expected byte {expected}, got {actual}"))
        }
    }

    fn take_u8(&mut self) -> Result<u8, String> {
        let bytes = self.take_exact(1)?;
        Ok(bytes[0])
    }

    fn take_u16(&mut self) -> Result<u16, String> {
        let bytes = self.take_exact(2)?;
        Ok(u16::from_be_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn take_u32(&mut self) -> Result<u32, String> {
        let bytes = self.take_exact(4)?;
        Ok(u32::from_be_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn take_u64(&mut self) -> Result<u64, String> {
        let bytes = self.take_exact(8)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn take_id(&mut self) -> Result<FactId, String> {
        let bytes = self.take_exact(32)?;
        Ok(bytes.try_into().expect("length checked"))
    }

    fn take_string_u16(&mut self) -> Result<String, String> {
        let len = self.take_u16()? as usize;
        let bytes = self.take_exact(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|err| format!("invalid utf-8 string: {err}"))
    }

    fn take_bytes_u32(&mut self) -> Result<&'a [u8], String> {
        let len = self.take_u32()? as usize;
        self.take_exact(len)
    }

    fn take_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "wake loop row length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err(format!(
                "wake loop row ended early at {}, needed {} bytes",
                self.offset, len
            ));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(format!(
                "wake loop row has {} trailing bytes",
                self.bytes.len() - self.offset
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{Role, Selector};
    use crate::core::facts::FactScope;
    use crate::core::handler_dispatch::HandlerOutput;
    use crate::core::intents::{IntentExecution, IntentKind};
    use crate::core::matchers::ExactSelectorMatcher;
    use crate::core::projection::{ProjectionContext, ProjectionOutput};
    use crate::core::schema_dsl::CORE_SCHEMA_SOURCE;
    use std::cell::Cell;

    #[test]
    fn standing_need_does_not_create_a_reproject_loop() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let fact = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let report = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("drain");

        assert_eq!(report.projections, 1);
        assert_eq!(report.wakes, 0);
        assert_eq!(bus.pending_len(), 0);
        assert_eq!(projector.need_projections.get(), 1);
        assert_eq!(bus.context(&fact.id).unwrap().needs.len(), 1);
        assert!(bus.intents().is_empty());
    }

    #[test]
    fn new_offer_wakes_existing_need_owner_once() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let need = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let offer = Fact::new(FactScope::Global, 2, b"offer".to_vec());
        let mut bus = WakeLoop::new();

        bus.submit_fact(need.clone());
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("need drain");
        bus.submit_fact(offer.clone());
        let report = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("offer drain");

        assert_eq!(report.projections, 2);
        assert_eq!(report.context_matches, 1);
        assert_eq!(report.wakes, 1);
        assert_eq!(projector.need_projections.get(), 2);
        assert_eq!(projector.offer_projections.get(), 1);
        assert!(bus.context(&need.id).is_none());
        assert_eq!(bus.intents().len(), 1);
        assert!(!bus.submit_fact(offer));
        let duplicate = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("duplicate drain");
        assert_eq!(duplicate.projections, 0);
        assert_eq!(bus.intents().len(), 1);
    }

    #[test]
    fn many_new_offers_do_not_amplify_one_owner_wake() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let need = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let offer_a = Fact::new(FactScope::Global, 2, b"offer-a".to_vec());
        let offer_b = Fact::new(FactScope::Global, 3, b"offer-b".to_vec());
        let mut bus = WakeLoop::new();

        bus.submit_fact(need);
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("need drain");
        bus.submit_fact(offer_a);
        bus.submit_fact(offer_b);
        let report = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("offer drain");

        assert_eq!(report.projections, 3);
        assert_eq!(report.context_matches, 2);
        assert_eq!(report.wakes, 1);
        assert_eq!(bus.pending_len(), 0);
        assert_eq!(bus.intents().len(), 1);
    }

    #[test]
    fn unrelated_custom_matcher_is_not_scanned_for_exact_only_delta() {
        let exact_role = Role::new("exact").unwrap();
        let custom_role = Role::new("custom").unwrap();
        let exact_matcher = ExactSelectorMatcher::new(exact_role.clone());
        let custom_matcher = CountingMatcher::new(custom_role);
        let projector = NeedOfferProjector::new(exact_role, Selector::from_bytes([8; 32]));
        let need = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let offer = Fact::new(FactScope::Global, 2, b"offer".to_vec());
        let mut bus = WakeLoop::new();

        bus.submit_fact(need);
        bus.drain(
            &projector,
            &[
                &exact_matcher as &dyn ContextMatcher,
                &custom_matcher as &dyn ContextMatcher,
            ],
            10,
        )
        .expect("need drain");
        bus.submit_fact(offer);
        let report = bus
            .drain(
                &projector,
                &[
                    &exact_matcher as &dyn ContextMatcher,
                    &custom_matcher as &dyn ContextMatcher,
                ],
                10,
            )
            .expect("offer drain");

        assert_eq!(report.context_matches, 1);
        assert_eq!(custom_matcher.need_calls.get(), 0);
        assert_eq!(custom_matcher.offer_calls.get(), 0);
    }

    #[test]
    fn deterministic_intents_are_idempotent_across_repeated_wakes() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = StandingNeedIntentProjector::new(role, Selector::from_bytes([8; 32]));
        let owner = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let offer_a = Fact::new(FactScope::Global, 2, b"offer-a".to_vec());
        let offer_b = Fact::new(FactScope::Global, 3, b"offer-b".to_vec());
        let mut bus = WakeLoop::new();

        bus.submit_fact(owner);
        let first = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("first drain");
        assert_eq!(first.intents, 1);
        assert_eq!(bus.intents().len(), 1);

        bus.submit_fact(offer_a);
        bus.submit_fact(offer_b);
        let rewake = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("rewake drain");

        assert_eq!(rewake.wakes, 1);
        assert_eq!(rewake.intents, 0);
        assert_eq!(bus.intents().len(), 1);
        assert_eq!(bus.take_intents().len(), 1);
        assert!(bus.intents().is_empty());
    }

    #[test]
    fn conflicting_intent_key_restores_pending_without_replacing_context() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = StandingNeedIntentProjector::new(role, Selector::from_bytes([8; 32]));
        let owner = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let offer = Fact::new(FactScope::Global, 2, b"offer".to_vec());
        let mut bus = WakeLoop::new();

        bus.submit_fact(owner.clone());
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("first drain");
        assert_eq!(bus.context(&owner.id).unwrap().needs.len(), 1);

        projector.payload_byte.set(2);
        bus.submit_fact(offer);
        let err = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect_err("conflicting deterministic intent");

        assert!(err.contains("intent idempotence key conflict"), "{err}");
        assert_eq!(bus.pending_len(), 1);
        assert_eq!(bus.context(&owner.id).unwrap().needs.len(), 1);

        projector.payload_byte.set(1);
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("retry with original deterministic intent");
        assert_eq!(bus.pending_len(), 0);
        assert!(bus.context(&owner.id).is_none());
        assert_eq!(bus.intents().len(), 1);
    }

    #[test]
    fn dispatch_handler_output_feeds_back_into_projection_cycle() {
        let mut bus = WakeLoop::new();
        bus.submit_intent(Intent::new(
            IntentKind::new("trigger_handler").unwrap(),
            IntentExecution::Deferred,
            b"trigger",
            b"payload",
        ))
        .expect("submit trigger intent");

        let report = bus
            .dispatch_intents(&FactAndIntentHandler, &HandlerContext::new(), 1)
            .expect("dispatch handler");

        assert_eq!(report.handled, 1);
        assert_eq!(report.facts, 1);
        assert_eq!(report.intents, 1);
        assert_eq!(bus.pending_len(), 1);
        assert_eq!(bus.intents().len(), 1);

        let drain = bus
            .drain(&HandlerFactProjector, &[], 10)
            .expect("project handler fact");
        assert_eq!(drain.projections, 1);
        assert_eq!(drain.intents, 1);
        assert_eq!(bus.pending_len(), 0);
        assert_eq!(bus.intents().len(), 2);
    }

    #[test]
    fn dispatch_handler_skips_unaccepted_intents() {
        let mut bus = WakeLoop::new();
        bus.submit_intent(Intent::new(
            IntentKind::new("other_handler").unwrap(),
            IntentExecution::Deferred,
            b"other",
            b"payload",
        ))
        .expect("submit other");
        bus.submit_intent(Intent::new(
            IntentKind::new("selected_handler").unwrap(),
            IntentExecution::Deferred,
            b"selected",
            b"payload",
        ))
        .expect("submit selected");

        let report = bus
            .dispatch_intents(&SelectedHandler, &HandlerContext::new(), 10)
            .expect("dispatch selected");

        assert_eq!(report.handled, 1);
        assert_eq!(bus.intents().len(), 1);
        assert_eq!(bus.intents()[0].kind.as_str(), "other_handler");
    }

    #[test]
    fn dispatch_can_filter_atomic_deferred_and_ephemeral_intents() {
        let mut bus = WakeLoop::new();
        bus.submit_intent(Intent::new(
            IntentKind::new("work").unwrap(),
            IntentExecution::Atomic,
            b"atomic",
            b"payload",
        ))
        .expect("submit atomic");
        bus.submit_intent(Intent::new(
            IntentKind::new("work").unwrap(),
            IntentExecution::Deferred,
            b"deferred",
            b"payload",
        ))
        .expect("submit deferred");
        bus.submit_intent(Intent::new(
            IntentKind::new("work").unwrap(),
            IntentExecution::Ephemeral,
            b"ephemeral",
            b"payload",
        ))
        .expect("submit ephemeral");

        let atomic = bus
            .dispatch_atomic_intents(&AcceptAllHandler, &HandlerContext::new(), 10)
            .expect("dispatch atomic");
        assert_eq!(atomic.handled, 1);
        assert_eq!(bus.intents().len(), 2);
        assert!(bus
            .intents()
            .iter()
            .all(|intent| intent.execution != IntentExecution::Atomic));

        let deferred = bus
            .dispatch_deferred_intents(&AcceptAllHandler, &HandlerContext::new(), 10)
            .expect("dispatch deferred");
        assert_eq!(deferred.handled, 1);
        assert_eq!(bus.intents().len(), 1);
        assert_eq!(bus.intents()[0].execution, IntentExecution::Ephemeral);

        let ephemeral = bus
            .dispatch_ephemeral_intents(&AcceptAllHandler, &HandlerContext::new(), 10)
            .expect("dispatch ephemeral");
        assert_eq!(ephemeral.handled, 1);
        assert!(bus.intents().is_empty());
    }

    #[test]
    fn ephemeral_intents_are_restart_local() {
        let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE])
            .expect("open core schema store");
        let mut bus = WakeLoop::new();
        bus.submit_intent(Intent::new(
            IntentKind::new("durable_work").unwrap(),
            IntentExecution::Deferred,
            b"durable",
            b"payload",
        ))
        .expect("submit durable");
        bus.submit_intent(Intent::new(
            IntentKind::new("socket_write").unwrap(),
            IntentExecution::Ephemeral,
            b"ephemeral",
            b"payload",
        ))
        .expect("submit ephemeral");

        bus.save(&store).expect("save bus");

        assert_eq!(bus.intents().len(), 2);
        let loaded = WakeLoop::load(&store).expect("reload bus");
        assert_eq!(loaded.intents().len(), 1);
        assert_eq!(loaded.intents()[0].kind.as_str(), "durable_work");
        assert_eq!(loaded.intents()[0].execution, IntentExecution::Deferred);
    }

    #[test]
    fn failed_handler_keeps_intent_available_for_retry() {
        let mut bus = WakeLoop::new();
        let handler = FailOnceHandler {
            fail: Cell::new(true),
        };
        bus.submit_intent(Intent::new(
            IntentKind::new("retryable_handler").unwrap(),
            IntentExecution::Deferred,
            b"retry",
            b"payload",
        ))
        .expect("submit retry intent");

        let err = bus
            .dispatch_intents(&handler, &HandlerContext::new(), 10)
            .expect_err("handler fails once");
        assert!(err.contains("handler unavailable"), "{err}");
        assert_eq!(bus.intents().len(), 1);

        let report = bus
            .dispatch_intents(&handler, &HandlerContext::new(), 10)
            .expect("handler retry succeeds");
        assert_eq!(report.handled, 1);
        assert!(bus.intents().is_empty());
    }

    #[test]
    fn retrying_handler_keeps_intent_without_failing_dispatch() {
        let mut bus = WakeLoop::new();
        bus.submit_intent(Intent::new(
            IntentKind::new("retry_later").unwrap(),
            IntentExecution::Deferred,
            b"retry",
            b"payload",
        ))
        .expect("submit retry intent");

        let report = bus
            .dispatch_intents(&RetryLaterHandler, &HandlerContext::new(), 10)
            .expect("transient retry is not a dispatch failure");

        assert_eq!(report.handled, 0);
        assert_eq!(report.retries, 1);
        assert_eq!(bus.intents().len(), 1);
    }

    #[test]
    fn deferred_dispatch_helper_exposes_exact_fact_payloads_to_handler() {
        let fact = Fact::new(FactScope::Global, 7, b"effect-input".to_vec());
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact.clone());
        bus.drain(&NoopProjector, &[], 10).expect("clear pending");
        bus.submit_intent(Intent::new(
            IntentKind::new("read_named_fact").unwrap(),
            IntentExecution::Deferred,
            fact.id,
            Vec::new(),
        ))
        .expect("submit fact-reading intent");

        let report = bus
            .dispatch_deferred_intents_with_fact_context(&ReadNamedFactHandler, 10)
            .expect("dispatch with fact context");

        assert_eq!(report.handled, 1);
        assert_eq!(report.intents, 1);
        assert_eq!(bus.intents().len(), 1);
        assert_eq!(bus.intents()[0].payload, b"effect-input");
    }

    #[test]
    fn ordinary_dispatch_does_not_expose_wake_loop_facts_to_handler_context() {
        let fact = Fact::new(FactScope::Global, 7, b"effect-input".to_vec());
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact.clone());
        bus.submit_intent(Intent::new(
            IntentKind::new("read_named_fact").unwrap(),
            IntentExecution::Deferred,
            fact.id,
            Vec::new(),
        ))
        .expect("submit fact-reading intent");

        let err = bus
            .dispatch_deferred_intents(&ReadNamedFactHandler, &HandlerContext::new(), 10)
            .expect_err("plain context has no facts");

        assert!(err.contains("handler context missing fact"), "{err}");
        assert_eq!(bus.intents().len(), 1);
    }

    #[test]
    fn conflicting_handler_intent_does_not_submit_facts() {
        let mut bus = WakeLoop::new();
        let fact = Fact::new(FactScope::Global, 9, b"conflict-fact".to_vec());
        bus.submit_intent(Intent::new(
            IntentKind::new("trigger_conflict").unwrap(),
            IntentExecution::Deferred,
            b"trigger",
            b"payload",
        ))
        .expect("submit trigger");
        bus.submit_intent(Intent::new(
            IntentKind::new("followup_conflict").unwrap(),
            IntentExecution::Deferred,
            b"same",
            b"old",
        ))
        .expect("submit existing followup");

        let err = bus
            .dispatch_intents(
                &ConflictingIntentHandler { fact: fact.clone() },
                &HandlerContext::new(),
                10,
            )
            .expect_err("handler output conflicts");

        assert!(err.contains("intent idempotence key conflict"), "{err}");
        assert_eq!(bus.intents().len(), 2);
        assert_eq!(bus.intents()[0].kind.as_str(), "trigger_conflict");
        assert!(!bus.has_fact(&fact.id));
        assert_eq!(bus.pending_len(), 0);
    }

    #[test]
    fn new_need_finds_existing_offer_and_wakes_itself() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let offer = Fact::new(FactScope::Global, 1, b"offer".to_vec());
        let need = Fact::new(FactScope::Global, 2, b"need".to_vec());
        let mut bus = WakeLoop::new();

        bus.submit_fact(offer);
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("offer drain");
        bus.submit_fact(need);
        let report = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("need drain");

        assert_eq!(report.projections, 2);
        assert_eq!(report.context_matches, 1);
        assert_eq!(report.wakes, 1);
        assert_eq!(bus.intents().len(), 1);
    }

    #[test]
    fn durable_wake_loop_preserves_pending_projection_across_restart() {
        let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE])
            .expect("open core schema store");
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let need = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let offer = Fact::new(FactScope::Global, 2, b"offer".to_vec());
        let mut bus = WakeLoop::new();

        bus.submit_fact(need.clone());
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("initial need drain");
        bus.submit_fact(offer);
        bus.save(&store).expect("save before offer drain");

        let mut restarted = WakeLoop::load(&store).expect("load bus");
        assert_eq!(restarted.pending_len(), 1);
        let report = restarted
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("restart drain");
        restarted.save(&store).expect("save drained bus");

        assert_eq!(report.projections, 2);
        assert_eq!(report.wakes, 1);
        assert!(restarted.context(&need.id).is_none());
        assert_eq!(restarted.intents().len(), 1);
        let loaded = WakeLoop::load(&store).expect("reload drained bus");
        assert_eq!(loaded.pending_len(), 0);
        assert_eq!(loaded.intents().len(), 1);
    }

    #[test]
    fn durable_wake_loop_round_trips_context_without_standing_need_amplification() {
        let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE])
            .expect("open core schema store");
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let need = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let mut bus = WakeLoop::new();

        bus.submit_fact(need.clone());
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("need drain");
        bus.save(&store).expect("save bus");

        let mut loaded = WakeLoop::load(&store).expect("load bus");
        assert_eq!(loaded.context(&need.id).unwrap().needs.len(), 1);
        let report = loaded
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("loaded drain");

        assert_eq!(report.projections, 0);
        assert_eq!(report.wakes, 0);
        assert!(loaded.intents().is_empty());
    }

    #[test]
    fn dependency_offer_is_context_only_after_successful_projection() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let child = Fact::new(FactScope::Global, 1, b"child".to_vec());
        let dep = Fact::new(FactScope::Global, 2, b"dep".to_vec());
        let projector = DependencyGateProjector::new(role, Selector::from_bytes(dep.id), dep.id);
        let mut bus = WakeLoop::new();

        bus.submit_fact(child.clone());
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("child waits");
        bus.submit_fact(dep.clone());
        let err = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect_err("dependency projection fails once");
        assert!(err.contains("dependency rejected by projector"), "{err}");
        assert_eq!(bus.pending_len(), 1);
        assert_eq!(projector.child_applied.get(), 0);

        projector.allow_dep.set(true);
        let report = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("dependency retry succeeds");

        assert_eq!(report.projections, 2);
        assert_eq!(projector.child_applied.get(), 1);
        assert_eq!(bus.pending_len(), 0);
    }

    #[test]
    fn update_offer_reprojects_already_applied_dependent() {
        let base_role = Role::new("base").unwrap();
        let update_role = Role::new("update").unwrap();
        let base_matcher = ExactSelectorMatcher::new(base_role.clone());
        let update_matcher = ExactSelectorMatcher::new(update_role.clone());
        let dep = Fact::new(FactScope::Global, 1, b"dep".to_vec());
        let child = Fact::new(FactScope::Global, 2, b"child".to_vec());
        let updater = Fact::new(FactScope::Global, 3, b"updater".to_vec());
        let projector = UpdateWakeProjector::new(
            base_role,
            update_role,
            Selector::from_bytes(dep.id),
            Selector::from_bytes(child.id),
        );
        let mut bus = WakeLoop::new();

        bus.submit_fact(dep);
        bus.submit_fact(child.clone());
        bus.drain(
            &projector,
            &[
                &base_matcher as &dyn ContextMatcher,
                &update_matcher as &dyn ContextMatcher,
            ],
            10,
        )
        .expect("base drain");
        assert_eq!(projector.child_projections.get(), 1);
        assert!(!projector.child_saw_update.get());

        bus.submit_fact(updater);
        let report = bus
            .drain(
                &projector,
                &[
                    &base_matcher as &dyn ContextMatcher,
                    &update_matcher as &dyn ContextMatcher,
                ],
                10,
            )
            .expect("update drain");

        assert_eq!(report.wakes, 1);
        assert_eq!(projector.child_projections.get(), 2);
        assert!(projector.child_saw_update.get());
        assert_eq!(bus.context(&child.id).unwrap().needs.len(), 1);
    }

    #[test]
    fn update_offer_can_retire_waiting_fact_without_primary_context() {
        let primary_role = Role::new("primary").unwrap();
        let update_role = Role::new("update").unwrap();
        let primary_matcher = ExactSelectorMatcher::new(primary_role.clone());
        let update_matcher = ExactSelectorMatcher::new(update_role.clone());
        let target = Fact::new(FactScope::Global, 1, b"target".to_vec());
        let updater = Fact::new(FactScope::Global, 2, b"updater".to_vec());
        let projector = RetireWaitingProjector::new(
            primary_role,
            update_role,
            Selector::from_bytes([99; 32]),
            Selector::from_bytes(target.id),
        );
        let mut bus = WakeLoop::new();

        bus.submit_fact(target.clone());
        bus.drain(
            &projector,
            &[
                &primary_matcher as &dyn ContextMatcher,
                &update_matcher as &dyn ContextMatcher,
            ],
            10,
        )
        .expect("target waits");
        assert_eq!(bus.context(&target.id).unwrap().needs.len(), 2);

        bus.submit_fact(updater);
        let report = bus
            .drain(
                &projector,
                &[
                    &primary_matcher as &dyn ContextMatcher,
                    &update_matcher as &dyn ContextMatcher,
                ],
                10,
            )
            .expect("update retires target");

        assert_eq!(report.wakes, 1);
        assert_eq!(projector.target_retired.get(), 1);
        assert!(bus.context(&target.id).is_none());
        assert_eq!(bus.intents().len(), 1);
    }

    #[test]
    fn projection_context_exposes_matched_need_offer_and_payload_fact() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let selector = Selector::from_bytes([8; 32]);
        let projector = MatchedPayloadProjector::new(role, selector);
        let need = Fact::new(FactScope::Global, 1, b"need-matched-payload".to_vec());
        let offer = Fact::new(FactScope::Global, 2, b"payload-fact".to_vec());
        let mut bus = WakeLoop::new();

        bus.submit_fact(need);
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("need waits");
        bus.submit_fact(offer);
        let report = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("offer wakes need");

        assert_eq!(report.wakes, 1);
        assert_eq!(projector.matched.get(), 1);
        assert_eq!(bus.intents().len(), 1);
        assert_eq!(bus.intents()[0].payload, b"payload-fact");
    }

    #[test]
    fn projection_context_keeps_only_the_exact_matched_offer() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let wanted = Selector::from_bytes([8; 32]);
        let sibling = Selector::from_bytes([9; 32]);
        let projector = SiblingOfferProjector::new(role, wanted, sibling);
        let need = Fact::new(FactScope::Global, 1, b"need-exact-offer".to_vec());
        let offer = Fact::new(FactScope::Global, 2, b"sibling-offers".to_vec());
        let mut bus = WakeLoop::new();

        bus.submit_fact(need);
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("need waits");
        bus.submit_fact(offer);
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("offer wakes need");

        assert_eq!(projector.matched.get(), 1);
        assert_eq!(bus.intents().len(), 1);
        assert_eq!(bus.intents()[0].payload, b"exact-offer-only");
    }

    struct NeedOfferProjector {
        role: Role,
        selector: Selector,
        need_projections: Cell<usize>,
        offer_projections: Cell<usize>,
    }

    impl NeedOfferProjector {
        fn new(role: Role, selector: Selector) -> Self {
            Self {
                role,
                selector,
                need_projections: Cell::new(0),
                offer_projections: Cell::new(0),
            }
        }
    }

    impl Projector for NeedOfferProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.bytes.starts_with(b"offer") {
                self.offer_projections.set(self.offer_projections.get() + 1);
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                    payload_ref: fact.id,
                }));
            }
            self.need_projections.set(self.need_projections.get() + 1);
            if context.offers().is_empty() {
                return Ok(ProjectionOutput::new().need(ContextNeed {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                }));
            }
            Ok(ProjectionOutput::new().intent(Intent::new(
                IntentKind::new("open_context").unwrap(),
                IntentExecution::Atomic,
                fact.id,
                context.payload_refs().next().unwrap_or(fact.id),
            )))
        }
    }

    struct CountingMatcher {
        role: Role,
        need_calls: Cell<usize>,
        offer_calls: Cell<usize>,
    }

    impl CountingMatcher {
        fn new(role: Role) -> Self {
            Self {
                role,
                need_calls: Cell::new(0),
                offer_calls: Cell::new(0),
            }
        }
    }

    impl ContextMatcher for CountingMatcher {
        fn role(&self) -> &Role {
            &self.role
        }

        fn match_new_need(
            &self,
            _need: &ContextNeed,
            _existing_offers: &[ContextOffer],
        ) -> Vec<ContextMatch> {
            self.need_calls.set(self.need_calls.get() + 1);
            Vec::new()
        }

        fn match_new_offer(
            &self,
            _offer: &ContextOffer,
            _existing_needs: &[ContextNeed],
        ) -> Vec<ContextMatch> {
            self.offer_calls.set(self.offer_calls.get() + 1);
            Vec::new()
        }
    }

    struct DependencyGateProjector {
        role: Role,
        selector: Selector,
        dep_id: FactId,
        allow_dep: Cell<bool>,
        child_applied: Cell<usize>,
    }

    impl DependencyGateProjector {
        fn new(role: Role, selector: Selector, dep_id: FactId) -> Self {
            Self {
                role,
                selector,
                dep_id,
                allow_dep: Cell::new(false),
                child_applied: Cell::new(0),
            }
        }
    }

    impl Projector for DependencyGateProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.id == self.dep_id {
                if !self.allow_dep.get() {
                    return Err("dependency rejected by projector".to_string());
                }
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                    payload_ref: fact.id,
                }));
            }
            if context.offers().is_empty() {
                return Ok(ProjectionOutput::new().need(ContextNeed {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                }));
            }
            self.child_applied.set(self.child_applied.get() + 1);
            Ok(ProjectionOutput::new())
        }
    }

    struct StandingNeedIntentProjector {
        role: Role,
        selector: Selector,
        payload_byte: Cell<u8>,
    }

    impl StandingNeedIntentProjector {
        fn new(role: Role, selector: Selector) -> Self {
            Self {
                role,
                selector,
                payload_byte: Cell::new(1),
            }
        }
    }

    impl Projector for StandingNeedIntentProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.bytes.starts_with(b"offer") {
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                    payload_ref: fact.id,
                }));
            }

            let intent = Intent::new(
                IntentKind::new("deterministic_work").unwrap(),
                IntentExecution::Deferred,
                fact.id,
                [self.payload_byte.get()],
            );
            let output = ProjectionOutput::new().intent(intent);
            if context.offers().is_empty() {
                Ok(output.need(ContextNeed {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                }))
            } else {
                Ok(output)
            }
        }
    }

    struct FactAndIntentHandler;

    impl IntentHandler for FactAndIntentHandler {
        fn handle(
            &self,
            intent: &Intent,
            _context: &HandlerContext,
        ) -> Result<HandlerOutput, String> {
            Ok(HandlerOutput::new()
                .fact(Fact::new(
                    FactScope::Global,
                    44,
                    b"handler-produced-fact".to_vec(),
                ))
                .intent(Intent::new(
                    IntentKind::new("handler_followup").unwrap(),
                    IntentExecution::Deferred,
                    intent.key.clone(),
                    b"followup",
                )))
        }
    }

    struct SelectedHandler;

    impl IntentHandler for SelectedHandler {
        fn accepts(&self, intent: &Intent) -> bool {
            intent.kind.as_str() == "selected_handler"
        }

        fn handle(
            &self,
            _intent: &Intent,
            _context: &HandlerContext,
        ) -> Result<HandlerOutput, String> {
            Ok(HandlerOutput::new())
        }
    }

    struct AcceptAllHandler;

    impl IntentHandler for AcceptAllHandler {
        fn handle(
            &self,
            _intent: &Intent,
            _context: &HandlerContext,
        ) -> Result<HandlerOutput, String> {
            Ok(HandlerOutput::new())
        }
    }

    struct HandlerFactProjector;

    impl Projector for HandlerFactProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.bytes == b"handler-produced-fact" {
                return Ok(ProjectionOutput::new().intent(Intent::new(
                    IntentKind::new("projected_handler_fact").unwrap(),
                    IntentExecution::Atomic,
                    fact.id,
                    b"materialized",
                )));
            }
            Ok(ProjectionOutput::new())
        }
    }

    struct FailOnceHandler {
        fail: Cell<bool>,
    }

    impl IntentHandler for FailOnceHandler {
        fn handle(
            &self,
            _intent: &Intent,
            _context: &HandlerContext,
        ) -> Result<HandlerOutput, String> {
            if self.fail.replace(false) {
                return Err("handler unavailable".to_string());
            }
            Ok(HandlerOutput::new())
        }
    }

    struct RetryLaterHandler;

    impl IntentHandler for RetryLaterHandler {
        fn handle(
            &self,
            _intent: &Intent,
            _context: &HandlerContext,
        ) -> Result<HandlerOutput, String> {
            Err(crate::core::handler_dispatch::retry_intent(
                "transient transport",
            ))
        }
    }

    struct ConflictingIntentHandler {
        fact: Fact,
    }

    impl IntentHandler for ConflictingIntentHandler {
        fn handle(
            &self,
            _intent: &Intent,
            _context: &HandlerContext,
        ) -> Result<HandlerOutput, String> {
            Ok(HandlerOutput::new()
                .fact(self.fact.clone())
                .intent(Intent::new(
                    IntentKind::new("followup_conflict").unwrap(),
                    IntentExecution::Deferred,
                    b"same",
                    b"new",
                )))
        }
    }

    struct ReadNamedFactHandler;

    impl IntentHandler for ReadNamedFactHandler {
        fn accepts(&self, intent: &Intent) -> bool {
            intent.kind.as_str() == "read_named_fact"
        }

        fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<FactId>, String> {
            let fact_id: FactId = intent
                .key
                .as_slice()
                .try_into()
                .map_err(|_| "read_named_fact intent key must be a fact id".to_string())?;
            Ok(vec![fact_id])
        }

        fn handle(
            &self,
            intent: &Intent,
            context: &HandlerContext,
        ) -> Result<HandlerOutput, String> {
            let fact_id: FactId = intent
                .key
                .as_slice()
                .try_into()
                .map_err(|_| "read_named_fact intent key must be a fact id".to_string())?;
            let fact = context.require_fact(&fact_id)?;
            Ok(HandlerOutput::new().intent(Intent::new(
                IntentKind::new("fact_effect_done").unwrap(),
                IntentExecution::Deferred,
                fact.id,
                fact.bytes.clone(),
            )))
        }
    }

    struct NoopProjector;

    impl Projector for NoopProjector {
        fn project(
            &self,
            _fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new())
        }
    }

    struct UpdateWakeProjector {
        base_role: Role,
        update_role: Role,
        base_selector: Selector,
        update_selector: Selector,
        child_projections: Cell<usize>,
        child_saw_update: Cell<bool>,
    }

    impl UpdateWakeProjector {
        fn new(
            base_role: Role,
            update_role: Role,
            base_selector: Selector,
            update_selector: Selector,
        ) -> Self {
            Self {
                base_role,
                update_role,
                base_selector,
                update_selector,
                child_projections: Cell::new(0),
                child_saw_update: Cell::new(false),
            }
        }
    }

    impl Projector for UpdateWakeProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.bytes == b"dep" {
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.base_role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.base_selector.clone(),
                    payload_ref: fact.id,
                }));
            }
            if fact.bytes == b"updater" {
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.update_role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.update_selector.clone(),
                    payload_ref: fact.id,
                }));
            }
            let saw_base = context
                .offers()
                .iter()
                .any(|offer| offer.role == self.base_role);
            let base_already_projected = self.child_projections.get() > 0;
            let saw_update = context
                .offers()
                .iter()
                .any(|offer| offer.role == self.update_role);
            if !saw_base && !base_already_projected {
                return Ok(ProjectionOutput::new().need(ContextNeed {
                    owner: fact.id,
                    role: self.base_role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.base_selector.clone(),
                }));
            }
            self.child_projections.set(self.child_projections.get() + 1);
            self.child_saw_update.set(saw_update);
            Ok(ProjectionOutput::new().need(ContextNeed {
                owner: fact.id,
                role: self.update_role.clone(),
                scope: fact.scope.clone(),
                selector: self.update_selector.clone(),
            }))
        }
    }

    struct RetireWaitingProjector {
        primary_role: Role,
        update_role: Role,
        primary_selector: Selector,
        update_selector: Selector,
        target_retired: Cell<usize>,
    }

    impl RetireWaitingProjector {
        fn new(
            primary_role: Role,
            update_role: Role,
            primary_selector: Selector,
            update_selector: Selector,
        ) -> Self {
            Self {
                primary_role,
                update_role,
                primary_selector,
                update_selector,
                target_retired: Cell::new(0),
            }
        }
    }

    impl Projector for RetireWaitingProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.bytes == b"updater" {
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.update_role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.update_selector.clone(),
                    payload_ref: fact.id,
                }));
            }
            let saw_update = context
                .offers()
                .iter()
                .any(|offer| offer.role == self.update_role);
            if saw_update {
                self.target_retired.set(self.target_retired.get() + 1);
                return Ok(ProjectionOutput::new().intent(Intent::new(
                    IntentKind::new("retire_fact").unwrap(),
                    IntentExecution::Atomic,
                    fact.id,
                    b"retired".to_vec(),
                )));
            }
            Ok(ProjectionOutput::new()
                .need(ContextNeed {
                    owner: fact.id,
                    role: self.primary_role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.primary_selector.clone(),
                })
                .need(ContextNeed {
                    owner: fact.id,
                    role: self.update_role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.update_selector.clone(),
                }))
        }
    }

    struct MatchedPayloadProjector {
        role: Role,
        selector: Selector,
        matched: Cell<usize>,
    }

    impl MatchedPayloadProjector {
        fn new(role: Role, selector: Selector) -> Self {
            Self {
                role,
                selector,
                matched: Cell::new(0),
            }
        }
    }

    impl Projector for MatchedPayloadProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.bytes == b"payload-fact" {
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                    payload_ref: fact.id,
                }));
            }
            if let Some(matched) = context.matched_context().first() {
                self.matched.set(self.matched.get() + 1);
                if matched.need.selector != self.selector
                    || matched.offer.selector != self.selector
                    || matched.payload.bytes != b"payload-fact"
                {
                    return Err("matched context did not preserve edge details".to_string());
                }
                return Ok(ProjectionOutput::new().intent(Intent::new(
                    IntentKind::new("matched_payload").unwrap(),
                    IntentExecution::Atomic,
                    fact.id,
                    matched.payload.bytes.clone(),
                )));
            }
            Ok(ProjectionOutput::new().need(ContextNeed {
                owner: fact.id,
                role: self.role.clone(),
                scope: fact.scope.clone(),
                selector: self.selector.clone(),
            }))
        }
    }

    struct SiblingOfferProjector {
        role: Role,
        wanted: Selector,
        sibling: Selector,
        matched: Cell<usize>,
    }

    impl SiblingOfferProjector {
        fn new(role: Role, wanted: Selector, sibling: Selector) -> Self {
            Self {
                role,
                wanted,
                sibling,
                matched: Cell::new(0),
            }
        }
    }

    impl Projector for SiblingOfferProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.bytes == b"sibling-offers" {
                return Ok(ProjectionOutput::new()
                    .offer(ContextOffer {
                        owner: fact.id,
                        role: self.role.clone(),
                        scope: fact.scope.clone(),
                        selector: self.wanted.clone(),
                        payload_ref: fact.id,
                    })
                    .offer(ContextOffer {
                        owner: fact.id,
                        role: self.role.clone(),
                        scope: fact.scope.clone(),
                        selector: self.sibling.clone(),
                        payload_ref: fact.id,
                    }));
            }
            if !context.offers().is_empty() {
                if context.offers().len() != 1 || context.offers()[0].selector != self.wanted {
                    return Err(
                        "projection context included an unmatched sibling offer".to_string()
                    );
                }
                self.matched.set(self.matched.get() + 1);
                return Ok(ProjectionOutput::new().intent(Intent::new(
                    IntentKind::new("exact_matched_offer").unwrap(),
                    IntentExecution::Atomic,
                    fact.id,
                    b"exact-offer-only".to_vec(),
                )));
            }
            Ok(ProjectionOutput::new().need(ContextNeed {
                owner: fact.id,
                role: self.role.clone(),
                scope: fact.scope.clone(),
                selector: self.wanted.clone(),
            }))
        }
    }
}
