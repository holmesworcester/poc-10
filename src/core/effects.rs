//! Shared side-effect language committed by runtime work.
//!
//! Projection and intent handlers reduce to this structure before the SQL
//! runtime workers commit their output. The structure is intentionally
//! mechanical: it names ordinary facts, priority facts, incoming facts, purges,
//! row mutations, durable intents, ephemeral intents, and version replay
//! rebuild requests. It does not contain callbacks, open sockets, command
//! receipts, or protocol-specific execution state.
//!
//! If a new kind of runtime effect needs atomic commit with projection or
//! intent dispatch, add it here and teach `project_fact::commit_effects` how
//! to validate and write it. If it is only display data for a command, keep it
//! in that command's receipt instead.

use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, IntentRowMutation};
use std::collections::BTreeMap;
use vstd::prelude::*;

/// Storage version contract carried by one effect batch.
///
/// Normal protocol projectors and handlers declare the storage shape they were
/// written to touch. Maintenance work, such as the update fact that repairs an
/// old database, must explicitly bypass this guard so it can run while storage
/// is stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageRequirement {
    /// The runtime storage marker must match this version before commit.
    Current(u32),
    /// Maintenance work that is allowed to commit while storage is stale.
    MaintenanceBypass,
}

impl Default for StorageRequirement {
    fn default() -> Self {
        Self::MaintenanceBypass
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMetadata {
    pub origin_addr: Vec<u8>,
    pub received_at_local_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEffects {
    /// Storage precondition checked before this batch commits.
    pub storage_requirement: StorageRequirement,
    /// New facts to admit and mark pending for projection.
    pub facts: Vec<Fact>,
    /// Control-plane facts that must project before ordinary pending facts.
    pub priority_facts: Vec<Fact>,
    /// Outside-origin projectable inputs that are not durable until projection retains them.
    pub incoming_facts: Vec<Fact>,
    /// Optional transport metadata for incoming facts emitted by projectors.
    pub incoming_fact_metadata: BTreeMap<FactId, IncomingMetadata>,
    /// Existing facts to remove with their derived core-owned rows.
    pub purged_facts: Vec<FactId>,
    /// Intent or live-runtime table mutations validated against the runtime allowlist.
    pub row_mutations: Vec<IntentRowMutation>,
    /// Durable queued work for handlers.
    pub intents: Vec<Intent>,
    /// Connection-local queued work, dropped on restart.
    pub local_intents: Vec<Intent>,
    /// Version-upgrade repair: wipe resettable derived/runtime state and replay all retained facts.
    pub version_replay_rebuild: bool,
}

impl Default for RuntimeEffects {
    fn default() -> Self {
        Self {
            storage_requirement: StorageRequirement::default(),
            facts: Vec::new(),
            priority_facts: Vec::new(),
            incoming_facts: Vec::new(),
            incoming_fact_metadata: BTreeMap::new(),
            purged_facts: Vec::new(),
            row_mutations: Vec::new(),
            intents: Vec::new(),
            local_intents: Vec::new(),
            version_replay_rebuild: false,
        }
    }
}

impl RuntimeEffects {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
            && self.priority_facts.is_empty()
            && self.incoming_facts.is_empty()
            && self.incoming_fact_metadata.is_empty()
            && self.purged_facts.is_empty()
            && self.row_mutations.is_empty()
            && self.intents.is_empty()
            && self.local_intents.is_empty()
            && !self.version_replay_rebuild
    }

    pub fn with_storage_requirement(self, requirement: StorageRequirement) -> Self {
        runtime_effects_with_storage_requirement(self, requirement)
    }

    pub fn fact(self, fact: Fact) -> Self {
        runtime_effects_with_fact(self, fact)
    }

    pub fn priority_fact(self, fact: Fact) -> Self {
        runtime_effects_with_priority_fact(self, fact)
    }

    pub fn incoming_fact(self, fact: Fact) -> Self {
        runtime_effects_with_incoming_fact(self, fact)
    }

    pub fn incoming_fact_with_metadata(self, fact: Fact, metadata: IncomingMetadata) -> Self {
        runtime_effects_with_incoming_fact_metadata(self, fact, metadata)
    }

    pub fn purge_fact(self, id: FactId) -> Self {
        runtime_effects_with_purge_fact(self, id)
    }

    pub fn row_mutation(self, mutation: IntentRowMutation) -> Self {
        runtime_effects_with_intent_row_mutation(self, mutation)
    }

    pub fn intent(self, intent: Intent) -> Self {
        runtime_effects_with_intent(self, intent)
    }

    pub fn local_intent(self, intent: Intent) -> Self {
        runtime_effects_with_local_intent(self, intent)
    }

    /// Request the version-upgrade wipe plus retained-fact replay effect.
    pub fn version_replay_rebuild(self) -> Self {
        runtime_effects_with_version_replay_rebuild(self)
    }
}

verus! {
/// Append a durable fact without changing any other runtime effect field.
fn runtime_effects_with_fact(
    mut effects: RuntimeEffects,
    fact: Fact,
) -> (updated: RuntimeEffects)
    ensures
        updated.storage_requirement == effects.storage_requirement,
        updated.facts@ == effects.facts@.push(fact),
        updated.priority_facts@ == effects.priority_facts@,
        updated.incoming_facts@ == effects.incoming_facts@,
        updated.incoming_fact_metadata == effects.incoming_fact_metadata,
        updated.purged_facts@ == effects.purged_facts@,
        updated.row_mutations@ == effects.row_mutations@,
        updated.intents@ == effects.intents@,
        updated.local_intents@ == effects.local_intents@,
        updated.version_replay_rebuild == effects.version_replay_rebuild,
{
    effects.facts.push(fact);
    effects
}

/// Append a priority fact without changing any other runtime effect field.
fn runtime_effects_with_priority_fact(
    mut effects: RuntimeEffects,
    fact: Fact,
) -> (updated: RuntimeEffects)
    ensures
        updated.storage_requirement == effects.storage_requirement,
        updated.facts@ == effects.facts@,
        updated.priority_facts@ == effects.priority_facts@.push(fact),
        updated.incoming_facts@ == effects.incoming_facts@,
        updated.incoming_fact_metadata == effects.incoming_fact_metadata,
        updated.purged_facts@ == effects.purged_facts@,
        updated.row_mutations@ == effects.row_mutations@,
        updated.intents@ == effects.intents@,
        updated.local_intents@ == effects.local_intents@,
        updated.version_replay_rebuild == effects.version_replay_rebuild,
{
    effects.priority_facts.push(fact);
    effects
}

/// Append an incoming fact without changing any other runtime effect field.
fn runtime_effects_with_incoming_fact(
    mut effects: RuntimeEffects,
    fact: Fact,
) -> (updated: RuntimeEffects)
    ensures
        updated.storage_requirement == effects.storage_requirement,
        updated.facts@ == effects.facts@,
        updated.priority_facts@ == effects.priority_facts@,
        updated.incoming_facts@ == effects.incoming_facts@.push(fact),
        updated.incoming_fact_metadata == effects.incoming_fact_metadata,
        updated.purged_facts@ == effects.purged_facts@,
        updated.row_mutations@ == effects.row_mutations@,
        updated.intents@ == effects.intents@,
        updated.local_intents@ == effects.local_intents@,
        updated.version_replay_rebuild == effects.version_replay_rebuild,
{
    effects.incoming_facts.push(fact);
    effects
}

/// Append an incoming fact and attach its transport metadata.
///
/// This proof covers the vector append and unrelated effect fields. The exact
/// map update remains ordinary Rust until core has a proof-friendly map helper.
fn runtime_effects_with_incoming_fact_metadata(
    mut effects: RuntimeEffects,
    fact: Fact,
    metadata: IncomingMetadata,
) -> (updated: RuntimeEffects)
    ensures
        updated.storage_requirement == effects.storage_requirement,
        updated.facts@ == effects.facts@,
        updated.priority_facts@ == effects.priority_facts@,
        updated.incoming_facts@ == effects.incoming_facts@.push(fact),
        updated.purged_facts@ == effects.purged_facts@,
        updated.row_mutations@ == effects.row_mutations@,
        updated.intents@ == effects.intents@,
        updated.local_intents@ == effects.local_intents@,
        updated.version_replay_rebuild == effects.version_replay_rebuild,
{
    effects.incoming_fact_metadata.insert(fact.id, metadata);
    effects.incoming_facts.push(fact);
    effects
}

/// Override the storage guard carried by a runtime effect batch.
///
/// The production router uses this after selecting a fact route so the route,
/// not the leaf projector, controls the storage-version precondition checked
/// before commit.
fn runtime_effects_with_storage_requirement(
    mut effects: RuntimeEffects,
    requirement: StorageRequirement,
) -> (updated: RuntimeEffects)
    ensures
        updated.storage_requirement == requirement,
        updated.facts@ == effects.facts@,
        updated.priority_facts@ == effects.priority_facts@,
        updated.incoming_facts@ == effects.incoming_facts@,
        updated.incoming_fact_metadata == effects.incoming_fact_metadata,
        updated.purged_facts@ == effects.purged_facts@,
        updated.row_mutations@ == effects.row_mutations@,
        updated.intents@ == effects.intents@,
        updated.local_intents@ == effects.local_intents@,
        updated.version_replay_rebuild == effects.version_replay_rebuild,
{
    effects.storage_requirement = requirement;
    effects
}

/// Append an intent/live-runtime row mutation to a runtime effect batch.
///
/// Projected rows use `ProjectionOutput::row_mutation`; this helper keeps the
/// intent-side builder explicit and proof-checks that it only appends to the
/// intent row-mutation list.
fn runtime_effects_with_intent_row_mutation(
    mut effects: RuntimeEffects,
    mutation: IntentRowMutation,
) -> (updated: RuntimeEffects)
    ensures
        updated.storage_requirement == effects.storage_requirement,
        updated.facts@ == effects.facts@,
        updated.priority_facts@ == effects.priority_facts@,
        updated.incoming_facts@ == effects.incoming_facts@,
        updated.incoming_fact_metadata == effects.incoming_fact_metadata,
        updated.purged_facts@ == effects.purged_facts@,
        updated.row_mutations@ == effects.row_mutations@.push(mutation),
        updated.intents@ == effects.intents@,
        updated.local_intents@ == effects.local_intents@,
        updated.version_replay_rebuild == effects.version_replay_rebuild,
{
    effects.row_mutations.push(mutation);
    effects
}

/// Append a purge request without changing any other runtime effect field.
fn runtime_effects_with_purge_fact(
    mut effects: RuntimeEffects,
    id: FactId,
) -> (updated: RuntimeEffects)
    ensures
        updated.storage_requirement == effects.storage_requirement,
        updated.facts@ == effects.facts@,
        updated.priority_facts@ == effects.priority_facts@,
        updated.incoming_facts@ == effects.incoming_facts@,
        updated.incoming_fact_metadata == effects.incoming_fact_metadata,
        updated.purged_facts@ == effects.purged_facts@.push(id),
        updated.row_mutations@ == effects.row_mutations@,
        updated.intents@ == effects.intents@,
        updated.local_intents@ == effects.local_intents@,
        updated.version_replay_rebuild == effects.version_replay_rebuild,
{
    effects.purged_facts.push(id);
    effects
}

/// Append a durable intent without changing any other runtime effect field.
fn runtime_effects_with_intent(
    mut effects: RuntimeEffects,
    intent: Intent,
) -> (updated: RuntimeEffects)
    ensures
        updated.storage_requirement == effects.storage_requirement,
        updated.facts@ == effects.facts@,
        updated.priority_facts@ == effects.priority_facts@,
        updated.incoming_facts@ == effects.incoming_facts@,
        updated.incoming_fact_metadata == effects.incoming_fact_metadata,
        updated.purged_facts@ == effects.purged_facts@,
        updated.row_mutations@ == effects.row_mutations@,
        updated.intents@ == effects.intents@.push(intent),
        updated.local_intents@ == effects.local_intents@,
        updated.version_replay_rebuild == effects.version_replay_rebuild,
{
    effects.intents.push(intent);
    effects
}

/// Append a local intent without changing any other runtime effect field.
fn runtime_effects_with_local_intent(
    mut effects: RuntimeEffects,
    intent: Intent,
) -> (updated: RuntimeEffects)
    ensures
        updated.storage_requirement == effects.storage_requirement,
        updated.facts@ == effects.facts@,
        updated.priority_facts@ == effects.priority_facts@,
        updated.incoming_facts@ == effects.incoming_facts@,
        updated.incoming_fact_metadata == effects.incoming_fact_metadata,
        updated.purged_facts@ == effects.purged_facts@,
        updated.row_mutations@ == effects.row_mutations@,
        updated.intents@ == effects.intents@,
        updated.local_intents@ == effects.local_intents@.push(intent),
        updated.version_replay_rebuild == effects.version_replay_rebuild,
{
    effects.local_intents.push(intent);
    effects
}

/// Request version-upgrade wipe/replay without changing the effect payload.
///
/// Admission later enforces that this flag is not mixed with emitted facts or
/// intents. This builder proof only states what the production setter changes.
fn runtime_effects_with_version_replay_rebuild(
    mut effects: RuntimeEffects,
) -> (updated: RuntimeEffects)
    ensures
        updated.storage_requirement == effects.storage_requirement,
        updated.facts@ == effects.facts@,
        updated.priority_facts@ == effects.priority_facts@,
        updated.incoming_facts@ == effects.incoming_facts@,
        updated.incoming_fact_metadata == effects.incoming_fact_metadata,
        updated.purged_facts@ == effects.purged_facts@,
        updated.row_mutations@ == effects.row_mutations@,
        updated.intents@ == effects.intents@,
        updated.local_intents@ == effects.local_intents@,
        updated.version_replay_rebuild,
{
    effects.version_replay_rebuild = true;
    effects
}
} // verus!

// Tests.
// Ordered most-central-first: this module has one emptiness invariant test.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::db::{TableInsert, TableName, Value};
    use crate::core::facts::{Fact, FactScope};
    use crate::core::intents::{Intent, IntentKind};

    #[test]
    fn runtime_effects_reports_whether_any_runtime_work_exists() {
        assert!(RuntimeEffects::new().is_empty());

        let fact = Fact::new(FactScope::Global, 1, b"child".to_vec());
        assert!(!RuntimeEffects::new().fact(fact).is_empty());
    }

    #[test]
    fn storage_requirement_overwrite_preserves_effect_payload() {
        let fact = Fact::new(FactScope::Global, 1, b"storage guarded fact".to_vec());
        let metadata = IncomingMetadata {
            origin_addr: b"127.0.0.1:10000".to_vec(),
            received_at_local_ms: 123,
        };
        let effects = RuntimeEffects::new()
            .fact(fact.clone())
            .incoming_fact_with_metadata(fact.clone(), metadata)
            .purge_fact([9; 32])
            .version_replay_rebuild();

        let updated = effects
            .clone()
            .with_storage_requirement(StorageRequirement::Current(7));

        assert_eq!(updated.storage_requirement, StorageRequirement::Current(7));
        assert_eq!(updated.facts, effects.facts);
        assert_eq!(updated.priority_facts, effects.priority_facts);
        assert_eq!(updated.incoming_facts, effects.incoming_facts);
        assert_eq!(
            updated.incoming_fact_metadata,
            effects.incoming_fact_metadata
        );
        assert_eq!(updated.purged_facts, effects.purged_facts);
        assert_eq!(updated.row_mutations, effects.row_mutations);
        assert_eq!(updated.intents, effects.intents);
        assert_eq!(updated.local_intents, effects.local_intents);
        assert_eq!(
            updated.version_replay_rebuild,
            effects.version_replay_rebuild
        );
    }

    #[test]
    fn append_builders_touch_only_their_effect_lists() {
        let durable = Fact::new(FactScope::Global, 1, b"durable child".to_vec());
        let priority = Fact::new(FactScope::Global, 2, b"priority child".to_vec());
        let incoming = Fact::new(FactScope::Local, 3, b"incoming child".to_vec());
        let incoming_metadata = IncomingMetadata {
            origin_addr: b"127.0.0.1:20000".to_vec(),
            received_at_local_ms: 44,
        };
        let purge_id = [9; 32];
        let durable_intent = Intent::new(
            IntentKind::new("durable_followup").unwrap(),
            b"key",
            b"payload",
        );
        let local_intent = Intent::new(
            IntentKind::new("local_followup").unwrap(),
            b"local-key",
            b"local-payload",
        );

        let updated = RuntimeEffects::new()
            .with_storage_requirement(StorageRequirement::Current(7))
            .version_replay_rebuild()
            .fact(durable.clone())
            .priority_fact(priority.clone())
            .incoming_fact_with_metadata(incoming.clone(), incoming_metadata.clone())
            .purge_fact(purge_id)
            .intent(durable_intent.clone())
            .local_intent(local_intent.clone());

        assert_eq!(updated.storage_requirement, StorageRequirement::Current(7));
        assert_eq!(updated.facts, vec![durable]);
        assert_eq!(updated.priority_facts, vec![priority]);
        assert_eq!(updated.incoming_facts, vec![incoming]);
        assert_eq!(
            updated
                .incoming_fact_metadata
                .get(&updated.incoming_facts[0].id),
            Some(&incoming_metadata)
        );
        assert_eq!(updated.purged_facts, vec![purge_id]);
        assert!(updated.row_mutations.is_empty());
        assert_eq!(updated.intents, vec![durable_intent]);
        assert_eq!(updated.local_intents, vec![local_intent]);
        assert!(updated.version_replay_rebuild);
    }

    #[test]
    fn intent_row_mutation_builder_preserves_effect_payload() {
        let fact = Fact::new(FactScope::Global, 1, b"intent guarded fact".to_vec());
        let mutation = IntentRowMutation::InsertValues(TableInsert {
            table: TableName::new("intent_rows"),
            columns: &["id"],
            values: vec![Value::Bytes(b"row".to_vec())],
        });
        let effects = RuntimeEffects::new()
            .fact(fact)
            .with_storage_requirement(StorageRequirement::Current(7));

        let updated = effects.clone().row_mutation(mutation.clone());

        assert_eq!(updated.storage_requirement, effects.storage_requirement);
        assert_eq!(updated.facts, effects.facts);
        assert_eq!(updated.priority_facts, effects.priority_facts);
        assert_eq!(updated.incoming_facts, effects.incoming_facts);
        assert_eq!(
            updated.incoming_fact_metadata,
            effects.incoming_fact_metadata
        );
        assert_eq!(updated.purged_facts, effects.purged_facts);
        assert_eq!(updated.row_mutations, vec![mutation]);
        assert_eq!(updated.intents, effects.intents);
        assert_eq!(updated.local_intents, effects.local_intents);
        assert_eq!(
            updated.version_replay_rebuild,
            effects.version_replay_rebuild
        );
    }

    #[test]
    fn version_replay_rebuild_builder_preserves_effect_payload() {
        let fact = Fact::new(FactScope::Global, 1, b"replay guarded fact".to_vec());
        let effects = RuntimeEffects::new()
            .fact(fact)
            .with_storage_requirement(StorageRequirement::Current(7));

        let updated = effects.clone().version_replay_rebuild();

        assert_eq!(updated.storage_requirement, effects.storage_requirement);
        assert_eq!(updated.facts, effects.facts);
        assert_eq!(updated.priority_facts, effects.priority_facts);
        assert_eq!(updated.incoming_facts, effects.incoming_facts);
        assert_eq!(
            updated.incoming_fact_metadata,
            effects.incoming_fact_metadata
        );
        assert_eq!(updated.purged_facts, effects.purged_facts);
        assert_eq!(updated.row_mutations, effects.row_mutations);
        assert_eq!(updated.intents, effects.intents);
        assert_eq!(updated.local_intents, effects.local_intents);
        assert!(updated.version_replay_rebuild);
    }
}
