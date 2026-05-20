//! SQL-backed intent dispatch pipeline.
//!
//! This module owns runtime handler dispatch for intents that have reached the
//! pipeline after fact projection. The top-level functions show the staged
//! shape:
//!
//! ```text
//! dispatch_deferred_intents_from_store_with_fact_context
//! dispatch_atomic_intents_from_store
//!   -> claim_stored_intent
//!   -> load_handler_context
//!   -> run_handler
//!   -> prepare_handler_output
//!   -> commit_handler_output
//!   -> finish_handler_output
//! ```
//!
//! Transaction rule: `commit_handler_output` is the durable boundary for one
//! stored intent. It deletes the handled intent, applies purges, admits emitted
//! facts as pending facts, applies atomic row intents, and records deferred
//! intents together.

use crate::core::context_change_helpers::{
    atomic_row_mutations, decode_intent_row, insert_fact_and_pending_in_tx, intent_row_key,
    persisted_fact, purge_fact_in_tx, record_intent_in_tx, sqlite_string_error,
    validate_atomic_row_intents,
};
use crate::core::context_change_pipeline::INTENTS;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::{Intent, IntentExecution};
use crate::core::store::{Store, TableName};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispatchReport {
    pub handled: usize,
    pub facts: usize,
    pub intents: usize,
    pub retries: usize,
}

/// Fact ids requested by a handler before it runs.
pub type HandlerFactId = FactId;

const RETRY_INTENT_PREFIX: &str = "retry intent: ";

/// Mark a handler failure as transient so dispatch leaves the intent queued.
pub fn retry_intent(reason: impl AsRef<str>) -> String {
    format!("{RETRY_INTENT_PREFIX}{}", reason.as_ref())
}

pub fn retry_intent_reason(err: &str) -> Option<&str> {
    err.strip_prefix(RETRY_INTENT_PREFIX)
}

/// Read-only inputs handed to an intent handler.
///
/// Stored and ephemeral dispatch both build this immediately before `handle`.
/// The handler gets only the facts it requested plus the store for explicit
/// query helpers; it cannot reach the runtime pipelines directly.
#[derive(Clone, Default)]
pub struct HandlerContext<'a> {
    facts: BTreeMap<FactId, Fact>,
    store: Option<&'a Store>,
}

impl fmt::Debug for HandlerContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandlerContext")
            .field("facts", &self.facts)
            .field("has_store", &self.store.is_some())
            .finish()
    }
}

impl<'a> HandlerContext<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_facts(facts: impl IntoIterator<Item = Fact>) -> Self {
        Self {
            facts: facts.into_iter().map(|fact| (fact.id, fact)).collect(),
            store: None,
        }
    }

    pub fn with_store(mut self, store: &'a Store) -> Self {
        self.store = Some(store);
        self
    }

    pub fn store(&self) -> Result<&Store, String> {
        self.store
            .ok_or_else(|| "handler context missing store".to_string())
    }

    pub fn fact(&self, id: &FactId) -> Option<&Fact> {
        self.facts.get(id)
    }

    pub fn facts(&self) -> impl Iterator<Item = &Fact> {
        self.facts.values()
    }

    pub fn require_fact(&self, id: &FactId) -> Result<&Fact, String> {
        self.fact(id)
            .ok_or_else(|| format!("handler context missing fact {id:?}"))
    }

    pub fn require_non_local_fact_bytes(&self, id: &FactId) -> Result<&[u8], String> {
        let fact = self.require_fact(id)?;
        if fact.scope == FactScope::Local {
            return Err(format!("handler context refused local fact {id:?}"));
        }
        Ok(&fact.bytes)
    }
}

/// Handler output feeds facts, purges, and follow-up intents back into the
/// same dispatch transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandlerOutput {
    pub facts: Vec<Fact>,
    pub purged_facts: Vec<FactId>,
    pub intents: Vec<Intent>,
}

impl HandlerOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fact(mut self, fact: Fact) -> Self {
        self.facts.push(fact);
        self
    }

    pub fn purge_fact(mut self, id: FactId) -> Self {
        self.purged_facts.push(id);
        self
    }

    pub fn intent(mut self, intent: Intent) -> Self {
        self.intents.push(intent);
        self
    }
}

/// A protocol handler for one or more intent kinds.
pub trait IntentHandler {
    fn accepts(&self, _intent: &Intent) -> bool {
        true
    }

    fn input_fact_ids(&self, _intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(Vec::new())
    }

    fn handle(
        &self,
        intent: &Intent,
        context: &HandlerContext<'_>,
    ) -> Result<HandlerOutput, String>;
}

/// Restart-local state and SQL-backed dispatch for protocol intents.
///
/// Durable deferred/atomic intents live in SQLite. Ephemeral intents do not:
/// they are intentionally restart-local and are queued here. The fact cache is
/// only a dispatch convenience for ephemeral handlers; persisted facts remain
/// the source of truth.
#[derive(Debug, Default)]
pub struct IntentPipeline {
    fact_cache: BTreeMap<FactId, Fact>,
    ephemeral_intents: Vec<Intent>,
    ephemeral_intent_keys: BTreeMap<Vec<u8>, usize>,
}

impl IntentPipeline {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn submit_intent_to_store(
        &mut self,
        store: &Store,
        intent: Intent,
    ) -> Result<bool, String> {
        if intent.execution == IntentExecution::Ephemeral {
            return self.record_ephemeral_intent(intent);
        }
        let inserted = store
            .write_transaction(|tx| record_intent_in_tx(tx, &intent))
            .map_err(|err| format!("submit intent: {err}"))?;
        Ok(inserted)
    }

    pub(crate) fn ephemeral_intents(&self) -> &[Intent] {
        &self.ephemeral_intents
    }

    pub(crate) fn validate_intents(&self, intents: &[Intent]) -> Result<(), String> {
        self.validate_intents_ignoring_key(intents, None)
    }

    pub(crate) fn validate_intents_ignoring_key(
        &self,
        intents: &[Intent],
        ignored_key: Option<&[u8]>,
    ) -> Result<(), String> {
        let mut proposed = BTreeMap::<Vec<u8>, &Intent>::new();
        for intent in intents {
            let key = intent_row_key(intent);
            if !ignored_key.is_some_and(|ignored| ignored == key.as_slice()) {
                if let Some(existing_index) = self.ephemeral_intent_keys.get(&key) {
                    if self.ephemeral_intents[*existing_index] != *intent {
                        return Err(format!(
                            "intent idempotence key conflict for {}",
                            intent.kind.as_str()
                        ));
                    }
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

    pub(crate) fn record_ephemeral_intent(&mut self, intent: Intent) -> Result<bool, String> {
        let key = intent_row_key(&intent);
        if let Some(existing_index) = self.ephemeral_intent_keys.get(&key) {
            if self.ephemeral_intents[*existing_index] == intent {
                return Ok(false);
            }
            return Err(format!(
                "intent idempotence key conflict for {}",
                intent.kind.as_str()
            ));
        }
        self.ephemeral_intent_keys
            .insert(key, self.ephemeral_intents.len());
        self.ephemeral_intents.push(intent);
        Ok(true)
    }

    pub(crate) fn forget_purged_fact(&mut self, owner: FactId) {
        self.fact_cache.remove(&owner);
    }

    pub(crate) fn remember_fact(&mut self, fact: Fact) {
        self.fact_cache.entry(fact.id).or_insert(fact);
    }

    fn remove_ephemeral_intent_key(&mut self, key: &[u8]) -> Result<(), String> {
        let Some(index) = self.ephemeral_intent_keys.get(key).copied() else {
            return Ok(());
        };
        self.ephemeral_intents.remove(index);
        self.rebuild_ephemeral_intent_keys()
    }

    fn pop_next_intent_matching(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        accepts_execution: impl Fn(&Intent) -> bool,
    ) -> Result<Option<(usize, Intent)>, String> {
        let Some(index) = self
            .ephemeral_intents
            .iter()
            .position(|intent| accepts_execution(intent) && handler.accepts(intent))
        else {
            return Ok(None);
        };
        let intent = self.ephemeral_intents.remove(index);
        self.rebuild_ephemeral_intent_keys()?;
        Ok(Some((index, intent)))
    }

    fn restore_intent(&mut self, index: usize, intent: Intent) -> Result<(), String> {
        let index = index.min(self.ephemeral_intents.len());
        self.ephemeral_intents.insert(index, intent);
        self.rebuild_ephemeral_intent_keys()
    }

    fn rebuild_ephemeral_intent_keys(&mut self) -> Result<(), String> {
        self.ephemeral_intent_keys.clear();
        for (index, intent) in self.ephemeral_intents.iter().enumerate() {
            let key = intent_row_key(intent);
            if self.ephemeral_intent_keys.insert(key, index).is_some() {
                return Err(format!(
                    "duplicate intent idempotence key for {}",
                    intent.kind.as_str()
                ));
            }
        }
        Ok(())
    }
}

/// Dispatch stored deferred intents with the facts requested by the handler.
pub(crate) fn dispatch_deferred_intents_from_store_with_fact_context(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    dispatch_stored_intents_matching(
        intent_pipeline,
        handler,
        store,
        IntentExecution::Deferred,
        HandlerContextMode::InputFacts,
        allowed_tables,
        limit,
    )
}

/// Dispatch stored atomic intents.
///
/// Atomic intents are already part of the runtime's deterministic row-mutation
/// vocabulary, so handlers receive an empty fact context and the transaction
/// applies any emitted row changes with the handled-intent deletion.
pub(crate) fn dispatch_atomic_intents_from_store(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    dispatch_stored_intents_matching(
        intent_pipeline,
        handler,
        store,
        IntentExecution::Atomic,
        HandlerContextMode::Empty,
        allowed_tables,
        limit,
    )
}

/// Dispatch restart-local intents.
///
/// Ephemeral intents are not deleted from SQLite because they were never
/// persisted. The loop removes one from memory, runs it, and restores it on any
/// non-committed failure.
pub(crate) fn dispatch_ephemeral_intents_with_fact_context_and_store(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    dispatch_ephemeral_intents_matching(intent_pipeline, handler, store, allowed_tables, limit)
}

/// Shared stored-intent loop.
///
/// Each iteration follows the visible pipeline: claim one matching intent,
/// load its handler context, run the handler, prepare output, commit output,
/// then update restart-local memory and the report.
fn dispatch_stored_intents_matching(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    execution: IntentExecution,
    context_mode: HandlerContextMode,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    let mut report = DispatchReport::default();
    while report.handled < limit {
        let Some(stored) = claim_stored_intent(store, handler, execution)? else {
            break;
        };
        let context = load_handler_context(store, handler, &stored.intent, context_mode)?;
        let Some(output) = run_handler(handler, &stored.intent, &context, &mut report)? else {
            break;
        };
        let output = prepare_handler_output(intent_pipeline, output, &stored.key, allowed_tables)?;
        let commit = commit_handler_output(store, &stored.key, &output, allowed_tables)?;
        if !finish_handler_output(intent_pipeline, stored.key, output, commit, &mut report)? {
            continue;
        }
    }
    Ok(report)
}

/// Restart-local sibling of `dispatch_stored_intents_matching`.
///
/// The shape is intentionally parallel, but restoration replaces SQL deletion:
/// until `commit_ephemeral_handler_output` succeeds, the intent is put back at
/// its original queue position.
fn dispatch_ephemeral_intents_matching(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    let mut report = DispatchReport::default();
    while report.handled < limit {
        let Some((intent_index, intent)) = intent_pipeline
            .pop_next_intent_matching(handler, |intent| {
                intent.execution == IntentExecution::Ephemeral
            })?
        else {
            break;
        };
        let input_ids = match handler.input_fact_ids(&intent) {
            Ok(input_ids) => input_ids,
            Err(err) => {
                intent_pipeline.restore_intent(intent_index, intent)?;
                return Err(err);
            }
        };
        let mut context_facts = BTreeMap::new();
        for fact_id in input_ids {
            let mut fact = intent_pipeline.fact_cache.get(&fact_id).cloned();
            if fact.is_none() {
                fact = persisted_fact(store, &fact_id)?;
                if let Some(fact) = &fact {
                    intent_pipeline.remember_fact(fact.clone());
                }
            }
            if let Some(fact) = fact {
                context_facts.insert(fact_id, fact);
            }
        }
        let context = HandlerContext::with_facts(context_facts.into_values()).with_store(store);
        let output = match handler.handle(&intent, &context) {
            Ok(output) => output,
            Err(err) => {
                intent_pipeline.restore_intent(intent_index, intent)?;
                if retry_intent_reason(&err).is_some()
                    || err.starts_with("handler context missing fact ")
                {
                    report.retries += 1;
                    break;
                }
                return Err(err);
            }
        };
        let output = match prepare_ephemeral_handler_output(intent_pipeline, output, allowed_tables)
        {
            Ok(output) => output,
            Err(err) => {
                intent_pipeline.restore_intent(intent_index, intent)?;
                return Err(err);
            }
        };
        let commit = match commit_ephemeral_handler_output(store, &output, allowed_tables) {
            Ok(commit) => commit,
            Err(err) => {
                intent_pipeline.restore_intent(intent_index, intent)?;
                return Err(err);
            }
        };
        finish_ephemeral_handler_output(intent_pipeline, output, commit, &mut report)?;
        report.handled += 1;
    }
    Ok(report)
}

/// Validate and split ephemeral handler output before the transaction.
fn prepare_ephemeral_handler_output(
    intent_pipeline: &IntentPipeline,
    output: HandlerOutput,
    allowed_tables: &[TableName],
) -> Result<HandlerOutputParts, String> {
    intent_pipeline.validate_intents(&output.intents)?;
    validate_atomic_row_intents(&output.intents, allowed_tables)?;
    Ok(split_handler_output(output))
}

/// Commit durable effects emitted by an ephemeral handler.
///
/// The handled ephemeral intent itself is absent from this transaction because
/// it only lived in memory.
fn commit_ephemeral_handler_output(
    store: &Store,
    output: &HandlerOutputParts,
    allowed_tables: &[TableName],
) -> Result<EphemeralHandlerCommit, String> {
    let (atomic_rows, atomic_deletes) =
        atomic_row_mutations(&output.atomic_intents, allowed_tables)?;
    store
        .write_transaction(|tx| {
            for purged in &output.purged_facts {
                purge_fact_in_tx(tx, *purged)?;
            }

            let mut facts_inserted = 0usize;
            for fact in &output.facts {
                if insert_fact_and_pending_in_tx(tx, fact)? {
                    facts_inserted += 1;
                }
            }

            tx.insert_table_rows_in_tx(atomic_rows)?;
            for delete in atomic_deletes {
                tx.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
            }

            let mut persisted_intents = 0usize;
            for intent in &output.durable_intents {
                if record_intent_in_tx(tx, intent)? {
                    persisted_intents += 1;
                }
            }

            Ok(EphemeralHandlerCommit {
                facts_inserted,
                atomic_intents: output.atomic_intents.len(),
                persisted_intents,
            })
        })
        .map_err(|err| format!("commit ephemeral handler output: {err}"))
}

/// Record restart-local effects after an ephemeral handler commit.
fn finish_ephemeral_handler_output(
    intent_pipeline: &mut IntentPipeline,
    output: HandlerOutputParts,
    commit: EphemeralHandlerCommit,
    report: &mut DispatchReport,
) -> Result<(), String> {
    for purged in &output.purged_facts {
        intent_pipeline.forget_purged_fact(*purged);
    }
    for fact in output.facts {
        intent_pipeline.remember_fact(fact);
    }
    let mut cached_ephemeral = 0usize;
    for intent in output.ephemeral_intents {
        if intent_pipeline.record_ephemeral_intent(intent)? {
            cached_ephemeral += 1;
        }
    }
    report.facts += commit.facts_inserted;
    report.intents += commit.atomic_intents + commit.persisted_intents + cached_ephemeral;
    Ok(())
}

/// Return the first stored intent accepted by this handler and execution mode.
fn claim_stored_intent(
    store: &Store,
    handler: &(impl IntentHandler + ?Sized),
    execution: IntentExecution,
) -> Result<Option<StoredIntent>, String> {
    for (key, value) in store
        .table_rows(INTENTS)
        .map_err(|err| format!("load stored intents: {err}"))?
    {
        let intent = decode_intent_row(&key, &value)?;
        if intent.execution == execution && handler.accepts(&intent) {
            return Ok(Some(StoredIntent { key, intent }));
        }
    }
    Ok(None)
}

/// Build the fact/store view a stored-intent handler requested.
fn load_handler_context<'a>(
    store: &'a Store,
    handler: &(impl IntentHandler + ?Sized),
    intent: &Intent,
    mode: HandlerContextMode,
) -> Result<HandlerContext<'a>, String> {
    let context = match mode {
        HandlerContextMode::Empty => HandlerContext::new(),
        HandlerContextMode::InputFacts => {
            let mut facts = Vec::new();
            for id in handler.input_fact_ids(intent)? {
                if let Some(fact) = persisted_fact(store, &id)? {
                    facts.push(fact);
                }
            }
            HandlerContext::with_facts(facts)
        }
    };
    Ok(context.with_store(store))
}

/// Run a handler and convert retry markers into report state.
fn run_handler(
    handler: &(impl IntentHandler + ?Sized),
    intent: &Intent,
    context: &HandlerContext<'_>,
    report: &mut DispatchReport,
) -> Result<Option<HandlerOutput>, String> {
    match handler.handle(intent, context) {
        Ok(output) => Ok(Some(output)),
        Err(err) => {
            if is_retryable_handler_error(&err) {
                report.retries += 1;
                Ok(None)
            } else {
                Err(err)
            }
        }
    }
}

/// Validate and split stored handler output before opening the commit.
fn prepare_handler_output(
    intent_pipeline: &IntentPipeline,
    output: HandlerOutput,
    handled_intent_key: &[u8],
    allowed_tables: &[TableName],
) -> Result<HandlerOutputParts, String> {
    intent_pipeline.validate_intents_ignoring_key(&output.intents, Some(handled_intent_key))?;
    validate_atomic_row_intents(&output.intents, allowed_tables)?;
    Ok(split_handler_output(output))
}

/// Commit the complete output of one stored intent.
///
/// This is the durable boundary for stored dispatch: deleting the handled
/// intent, purging facts, admitting emitted facts, applying atomic rows, and
/// recording deferred intents happen together.
fn commit_handler_output(
    store: &Store,
    handled_intent_key: &[u8],
    output: &HandlerOutputParts,
    allowed_tables: &[TableName],
) -> Result<HandlerCommit, String> {
    store
        .write_transaction(|tx| {
            let deleted = tx.delete_table_rows_in_tx(INTENTS, vec![handled_intent_key.to_vec()])?;
            if deleted == 0 {
                return Ok(HandlerCommit::default());
            }

            for purged in &output.purged_facts {
                purge_fact_in_tx(tx, *purged)?;
            }

            let mut facts_inserted = 0usize;
            for fact in &output.facts {
                if insert_fact_and_pending_in_tx(tx, fact)? {
                    facts_inserted += 1;
                }
            }

            let (atomic_rows, atomic_deletes) =
                atomic_row_mutations(&output.atomic_intents, allowed_tables)
                    .map_err(sqlite_string_error)?;
            tx.insert_table_rows_in_tx(atomic_rows)?;
            for delete in atomic_deletes {
                tx.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
            }

            let mut persisted_intents = 0usize;
            for intent in &output.durable_intents {
                if record_intent_in_tx(tx, intent)? {
                    persisted_intents += 1;
                }
            }

            Ok(HandlerCommit {
                handled: true,
                facts: facts_inserted,
                atomic_intents: output.atomic_intents.len(),
                persisted_intents,
            })
        })
        .map_err(|err| format!("commit stored handler output: {err}"))
}

/// Update restart-local memory after a stored-intent commit.
fn finish_handler_output(
    intent_pipeline: &mut IntentPipeline,
    handled_intent_key: Vec<u8>,
    output: HandlerOutputParts,
    commit: HandlerCommit,
    report: &mut DispatchReport,
) -> Result<bool, String> {
    intent_pipeline.remove_ephemeral_intent_key(&handled_intent_key)?;
    if !commit.handled {
        return Ok(false);
    }

    for purged in &output.purged_facts {
        intent_pipeline.forget_purged_fact(*purged);
    }
    for fact in output.facts {
        intent_pipeline.remember_fact(fact);
    }
    let mut cached_ephemeral = 0usize;
    for intent in output.ephemeral_intents {
        if intent_pipeline.record_ephemeral_intent(intent)? {
            cached_ephemeral += 1;
        }
    }

    report.handled += 1;
    report.facts += commit.facts;
    report.intents += commit.atomic_intents + commit.persisted_intents + cached_ephemeral;
    Ok(true)
}

/// Split handler output by execution class once, before any commit logic.
fn split_handler_output(output: HandlerOutput) -> HandlerOutputParts {
    let mut atomic_intents = Vec::new();
    let mut durable_intents = Vec::new();
    let mut ephemeral_intents = Vec::new();
    for intent in output.intents {
        match intent.execution {
            IntentExecution::Atomic => atomic_intents.push(intent),
            IntentExecution::Deferred => durable_intents.push(intent),
            IntentExecution::Ephemeral => ephemeral_intents.push(intent),
        }
    }
    HandlerOutputParts {
        facts: output.facts,
        purged_facts: output.purged_facts,
        atomic_intents,
        durable_intents,
        ephemeral_intents,
    }
}

fn is_retryable_handler_error(err: &str) -> bool {
    retry_intent_reason(err).is_some() || err.starts_with("handler context missing fact ")
}

#[derive(Debug, Clone, Copy)]
enum HandlerContextMode {
    Empty,
    InputFacts,
}

struct StoredIntent {
    key: Vec<u8>,
    intent: Intent,
}

#[derive(Debug, Default)]
struct HandlerCommit {
    handled: bool,
    facts: usize,
    atomic_intents: usize,
    persisted_intents: usize,
}

#[derive(Debug, Default)]
struct EphemeralHandlerCommit {
    facts_inserted: usize,
    atomic_intents: usize,
    persisted_intents: usize,
}

struct HandlerOutputParts {
    facts: Vec<Fact>,
    purged_facts: Vec<FactId>,
    atomic_intents: Vec<Intent>,
    durable_intents: Vec<Intent>,
    ephemeral_intents: Vec<Intent>,
}
