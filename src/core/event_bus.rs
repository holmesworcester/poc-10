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
//! The bus is deliberately below storage in this slice. The row schemas already
//! name durable tables for facts, context, pending projection, and intents; this
//! module first makes the semantics crisp enough to persist without carrying
//! forward the old lifecycle vocabulary.

use crate::core::context::{
    ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role, Selector,
};
use crate::core::facts::{fact_id, Fact, FactId, FactScope, ScopeKind};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::matchers::{match_context_delta, ContextMatcher};
use crate::core::projection::{run_projection, Projector};
use crate::core::store::{Store, TableName, TableRow};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const FACTS: TableName = TableName::new("facts");
pub const NEEDS: TableName = TableName::new("needs");
pub const OFFERS: TableName = TableName::new("offers");
pub const PENDING_PROJECTION: TableName = TableName::new("pending_projection");
pub const INTENTS: TableName = TableName::new("intents");

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    pub projections: usize,
    pub context_matches: usize,
    pub wakes: usize,
    pub intents: usize,
}

#[derive(Debug, Default)]
pub struct EventBus {
    facts: BTreeMap<FactId, Fact>,
    context_by_owner: BTreeMap<FactId, ContextSet>,
    pending_projection: VecDeque<FactId>,
    pending_owners: BTreeSet<FactId>,
    intents: Vec<Intent>,
}

impl EventBus {
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
            bus.intents.push(decode_intent(&value)?);
        }
        Ok(bus)
    }

    pub fn save(&self, store: &Store) -> Result<(), String> {
        store
            .write_transaction(|tx| {
                replace_table_rows(tx, FACTS, self.fact_rows())?;
                replace_table_rows(tx, NEEDS, self.need_rows())?;
                replace_table_rows(tx, OFFERS, self.offer_rows())?;
                replace_table_rows(tx, PENDING_PROJECTION, self.pending_rows())?;
                replace_table_rows(tx, INTENTS, self.intent_rows())?;
                Ok(())
            })
            .map_err(|err| format!("save event bus: {err}"))
    }

    pub fn submit_fact(&mut self, fact: Fact) -> bool {
        let id = fact.id;
        if self.facts.insert(id, fact).is_some() {
            return false;
        }
        self.wake(id)
    }

    pub fn has_fact(&self, id: &FactId) -> bool {
        self.facts.contains_key(id)
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
        std::mem::take(&mut self.intents)
    }

    pub fn drain(
        &mut self,
        projector: &impl Projector,
        matchers: &[&dyn ContextMatcher],
        limit: usize,
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
            let offers = self.matching_offers_for_owner(&owner, matchers);
            let run = match run_projection(projector, &fact, &previous, offers) {
                Ok(run) => run,
                Err(err) => {
                    self.restore_pending(owner);
                    return Err(err);
                }
            };
            self.replace_context(owner, run.context);
            report.projections += 1;
            report.context_matches +=
                self.wake_context_matches(&run.context_delta, matchers, &mut report);
            report.intents += run.intents.len();
            self.intents.extend(run.intents);
        }
        Ok(report)
    }

    fn wake(&mut self, owner: FactId) -> bool {
        if !self.pending_owners.insert(owner) {
            return false;
        }
        self.pending_projection.push_back(owner);
        true
    }

    fn pop_pending(&mut self) -> Option<FactId> {
        let owner = self.pending_projection.pop_front()?;
        self.pending_owners.remove(&owner);
        Some(owner)
    }

    fn restore_pending(&mut self, owner: FactId) {
        if self.pending_owners.insert(owner) {
            self.pending_projection.push_front(owner);
        }
    }

    fn replace_context(&mut self, owner: FactId, context: ContextSet) {
        if context.needs.is_empty() && context.offers.is_empty() {
            self.context_by_owner.remove(&owner);
        } else {
            self.context_by_owner.insert(owner, context);
        }
    }

    fn wake_context_matches(
        &mut self,
        delta: &ContextSetDelta,
        matchers: &[&dyn ContextMatcher],
        report: &mut DrainReport,
    ) -> usize {
        let needs = self.all_needs();
        let offers = self.all_offers();
        let matches = match_context_delta(delta, &needs, &offers, matchers);
        for matched in &matches {
            if self.wake(matched.need_owner) {
                report.wakes += 1;
            }
        }
        matches.len()
    }

    fn matching_offers_for_owner(
        &self,
        owner: &FactId,
        matchers: &[&dyn ContextMatcher],
    ) -> Vec<ContextOffer> {
        let Some(context) = self.context_by_owner.get(owner) else {
            return Vec::new();
        };
        let offers = self.all_offers();
        let delta = ContextSetDelta {
            added_needs: context.needs.clone(),
            removed_needs: Vec::new(),
            added_offers: Vec::new(),
            removed_offers: Vec::new(),
        };
        let matches = match_context_delta(&delta, &[], &offers, matchers)
            .into_iter()
            .map(|matched| (matched.offer_owner, matched.payload_ref))
            .collect::<BTreeSet<_>>();
        offers
            .into_iter()
            .filter(|offer| matches.contains(&(offer.owner, offer.payload_ref)))
            .collect()
    }

    fn all_needs(&self) -> Vec<ContextNeed> {
        self.context_by_owner
            .values()
            .flat_map(|context| context.needs.iter().cloned())
            .collect()
    }

    fn all_offers(&self) -> Vec<ContextOffer> {
        self.context_by_owner
            .values()
            .flat_map(|context| context.offers.iter().cloned())
            .collect()
    }

    fn fact_rows(&self) -> Vec<TableRow> {
        self.facts
            .values()
            .map(|fact| TableRow {
                table: FACTS,
                key: fact.id.to_vec(),
                value: encode_fact(fact),
            })
            .collect()
    }

    fn need_rows(&self) -> Vec<TableRow> {
        self.context_by_owner
            .values()
            .flat_map(|context| context.needs.iter())
            .map(|need| {
                let value = encode_need(need);
                TableRow {
                    table: NEEDS,
                    key: context_row_key(need.owner, &value),
                    value,
                }
            })
            .collect()
    }

    fn offer_rows(&self) -> Vec<TableRow> {
        self.context_by_owner
            .values()
            .flat_map(|context| context.offers.iter())
            .map(|offer| {
                let value = encode_offer(offer);
                TableRow {
                    table: OFFERS,
                    key: context_row_key(offer.owner, &value),
                    value,
                }
            })
            .collect()
    }

    fn pending_rows(&self) -> Vec<TableRow> {
        self.pending_projection
            .iter()
            .map(|owner| TableRow {
                table: PENDING_PROJECTION,
                key: owner.to_vec(),
                value: Vec::new(),
            })
            .collect()
    }

    fn intent_rows(&self) -> Vec<TableRow> {
        self.intents
            .iter()
            .map(|intent| {
                let value = encode_intent(intent);
                TableRow {
                    table: INTENTS,
                    key: intent_row_key(intent),
                    value,
                }
            })
            .collect()
    }
}

fn replace_table_rows(
    store: &Store,
    table: TableName,
    rows: Vec<TableRow>,
) -> rusqlite::Result<()> {
    let keys = store
        .table_rows(table)?
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    store.delete_table_rows_in_tx(table, keys)?;
    store.insert_table_rows_in_tx(rows)?;
    Ok(())
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

fn encode_intent(intent: &Intent) -> Vec<u8> {
    let mut out = Vec::new();
    put_u8(&mut out, 1);
    put_string_u16(&mut out, intent.kind.as_str());
    put_u8(
        &mut out,
        match intent.execution {
            IntentExecution::Atomic => 0,
            IntentExecution::Deferred => 1,
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
    let len = u32::try_from(bytes.len()).expect("core event bus bytes length fits u32");
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
            .ok_or_else(|| "event bus row length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err(format!(
                "event bus row ended early at {}, needed {} bytes",
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
                "event bus row has {} trailing bytes",
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
        let mut bus = EventBus::new();

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
        let mut bus = EventBus::new();

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
        let mut bus = EventBus::new();

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
    fn new_need_finds_existing_offer_and_wakes_itself() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let offer = Fact::new(FactScope::Global, 1, b"offer".to_vec());
        let need = Fact::new(FactScope::Global, 2, b"need".to_vec());
        let mut bus = EventBus::new();

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
    fn durable_event_bus_preserves_pending_projection_across_restart() {
        let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE])
            .expect("open core schema store");
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let need = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let offer = Fact::new(FactScope::Global, 2, b"offer".to_vec());
        let mut bus = EventBus::new();

        bus.submit_fact(need.clone());
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("initial need drain");
        bus.submit_fact(offer);
        bus.save(&store).expect("save before offer drain");

        let mut restarted = EventBus::load(&store).expect("load bus");
        assert_eq!(restarted.pending_len(), 1);
        let report = restarted
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("restart drain");
        restarted.save(&store).expect("save drained bus");

        assert_eq!(report.projections, 2);
        assert_eq!(report.wakes, 1);
        assert!(restarted.context(&need.id).is_none());
        assert_eq!(restarted.intents().len(), 1);
        let loaded = EventBus::load(&store).expect("reload drained bus");
        assert_eq!(loaded.pending_len(), 0);
        assert_eq!(loaded.intents().len(), 1);
    }

    #[test]
    fn durable_event_bus_round_trips_context_without_standing_need_amplification() {
        let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE])
            .expect("open core schema store");
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let need = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let mut bus = EventBus::new();

        bus.submit_fact(need.clone());
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("need drain");
        bus.save(&store).expect("save bus");

        let mut loaded = EventBus::load(&store).expect("load bus");
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
        let mut bus = EventBus::new();

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
        let mut bus = EventBus::new();

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
        let mut bus = EventBus::new();

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
}
