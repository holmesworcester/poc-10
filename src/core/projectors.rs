//! Projector contract from facts and context to runtime effects.
//!
//! Projection is core's deterministic reactive path. A projector receives one
//! immutable fact plus the context rows core has matched for that fact, and it
//! returns the complete replacement context owned by that fact together with
//! row mutations, self-purge, and follow-up work to commit. The pipeline
//! enforces that a projector only owns context, time wakes, and purges for the
//! fact being projected.
//!
//! Projectors are where protocol facts become protocol state. They decode the
//! fact payload, check scope and context proofs, decide whether enough input is
//! available, and emit rows, needs, offers, time wakes, child facts, or follow-up
//! intents. They do not decide when projection runs and they do not write SQL
//! directly; `pipeline::project_pending_facts` supplies the scheduling and
//! commit boundary.
//!
//! The replacement model is central. `ProjectionOutput` is not "patch these
//! needs" or "add these time wakes"; it is the complete standing context and
//! schedule for the projected fact after this run. If a fact stops needing some
//! context or no longer needs a wake, the projector simply stops emitting it and
//! the projection commit removes the old row.
//!
//! Deletion follows the same owner rule. A target fact keeps a standing need for
//! the deletion, retirement, close, or time context that can remove it. When
//! that context matches, the target projector deletes its own projection rows
//! and may purge only its own fact bytes. Projectors must not purge other facts
//! or rely on a parent projector to discover and delete children.
//!
//! Core may run a projector more than once before committing. If an uncommitted
//! run emits needs that already match stored offers, the projection pipeline grows
//! the supplied `ProjectionContext` and reruns the same projector. Only the final
//! output commits. This deliberately keeps required-vs-watch policy here in the
//! projector instead of moving dependency groups or blockers into core.
//!
//! Protocol projector implementations own admission policy: scope checks,
//! context proof checks, derived rows, offers, needs, time wakes, self-purge,
//! and follow-up intents. This file defines the contract they implement. Keep
//! byte decoding in the fact module's codec and keep user-facing workflows in
//! command modules.

use crate::core::context::{ContextNeed, ContextOffer, ContextSet};
use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, RowMutation};
use std::collections::{BTreeMap, BTreeSet};

/// Matched context and due time ranges visible while projecting one fact.
///
/// Core builds this immediately before calling the projector. It is a snapshot
/// of matched rows for this run, not a live storage handle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionContext {
    offers: Vec<ContextOffer>,
    matched: Vec<MatchedContext>,
    matched_by_need: BTreeMap<ContextNeed, Vec<usize>>,
    time_ranges: Vec<TimeRange>,
}

/// One matched need/offer pair plus the offer owner's payload fact.
///
/// Core constructs this from standing context rows before calling the
/// projector. A projector may inspect the payload, but it must not assume core
/// has validated the protocol semantics of that payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedContext {
    /// The need owned by the fact currently being projected.
    pub need: ContextNeed,
    /// The offer that satisfied the need.
    pub offer: ContextOffer,
    /// Payload fact loaded from the offer owner.
    pub payload: Fact,
}

impl ProjectionContext {
    /// Build context containing only unmatched standing offers.
    ///
    /// This shape is mainly used for facts with no needs; protocol code should
    /// prefer the matched-payload helpers when a proof depends on a need.
    pub fn new(offers: Vec<ContextOffer>) -> Self {
        Self {
            offers,
            matched: Vec::new(),
            matched_by_need: BTreeMap::new(),
            time_ranges: Vec::new(),
        }
    }

    /// Build context from already matched need/offer/payload triples.
    pub fn from_matches(matched: Vec<MatchedContext>) -> Self {
        let mut offers = matched
            .iter()
            .map(|matched| matched.offer.clone())
            .collect::<Vec<_>>();
        offers.sort();
        offers.dedup();
        let matched_by_need = index_matches_by_need(&matched);
        Self {
            offers,
            matched,
            matched_by_need,
            time_ranges: Vec::new(),
        }
    }

    /// Add newly matched context discovered while preparing one projection.
    ///
    /// This is crate-visible because only core should grow projection context.
    /// Projectors receive the resulting snapshot but do not query storage or run
    /// overlap queries themselves.
    pub(crate) fn extend_with_matches(&mut self, other: ProjectionContext) -> bool {
        let mut changed = false;

        let mut seen_offers = self.offers.iter().cloned().collect::<BTreeSet<_>>();
        for offer in other.offers {
            if seen_offers.insert(offer.clone()) {
                self.offers.push(offer);
                changed = true;
            }
        }
        if changed {
            self.offers.sort();
            self.offers.dedup();
        }

        let mut seen_matches = self
            .matched
            .iter()
            .map(|matched| (matched.need.clone(), matched.offer.clone()))
            .collect::<BTreeSet<_>>();
        for matched in other.matched {
            if seen_matches.insert((matched.need.clone(), matched.offer.clone())) {
                self.matched.push(matched);
                changed = true;
            }
        }
        if changed {
            self.matched_by_need = index_matches_by_need(&self.matched);
        }

        changed
    }

    /// Return all distinct offers visible to this projection run.
    pub fn offers(&self) -> &[ContextOffer] {
        &self.offers
    }

    /// Attach due time ranges selected by the daemon's time-wake pass.
    pub fn with_time_ranges(mut self, time_ranges: Vec<TimeRange>) -> Self {
        self.time_ranges = time_ranges;
        self
    }

    /// Return the largest due time in a range containing `at`.
    ///
    /// This is a context check, not a clock read. The daemon already decided
    /// which ranges were due and stored them for this projection pass.
    pub fn time_reached(&self, timeline: &Timeline, at: u64) -> Option<u64> {
        self.time_ranges
            .iter()
            .filter(|range| &range.timeline == timeline && range.contains(at))
            .map(|range| range.end_inclusive)
            .max()
    }

    /// Return the payload fact supplied for an exact need, if any.
    ///
    /// This is a lookup over context core already matched and loaded before
    /// projection. It does not query storage or run overlap queries.
    pub fn payload_for(&self, need: &ContextNeed) -> Option<&Fact> {
        self.matched_entries_for(need)
            .next()
            .map(|matched| &matched.payload)
    }

    pub fn payload_for_checked(
        &self,
        need: &ContextNeed,
        label: &str,
    ) -> Result<Option<&Fact>, String> {
        let Some(matched) = self.matched_entries_for(need).next() else {
            return Ok(None);
        };
        if matched.offer.owner != matched.payload.id {
            return Err(format!("{label} context offer payload mismatch"));
        }
        Ok(Some(&matched.payload))
    }

    /// Decode the first payload for `need` using the owning fact codec.
    pub fn payload_as<C>(&self, need: &ContextNeed) -> Result<Option<C::Payload>, String>
    where
        C: FactCodec,
    {
        self.payload_for(need).map(C::decode_fact).transpose()
    }

    /// Return every matched payload for a need, preserving its offer metadata.
    pub fn matched_payloads_for<'a>(
        &'a self,
        need: &'a ContextNeed,
    ) -> impl Iterator<Item = (&'a ContextOffer, &'a Fact)> + 'a {
        self.matched_entries_for(need)
            .map(|matched| (&matched.offer, &matched.payload))
    }

    /// Return every matched payload decoded through the owning fact codec.
    ///
    /// The owner check is deliberately here because context rows and fact rows
    /// are separate storage records. A mismatch means the projected proof is
    /// not the fact the offer claimed to provide.
    pub fn matched_payloads_as_checked<'a, C>(
        &'a self,
        need: &'a ContextNeed,
        label: &'a str,
    ) -> impl Iterator<Item = Result<(&'a ContextOffer, &'a Fact, C::Payload), String>> + 'a
    where
        C: FactCodec + 'a,
    {
        self.matched_entries_for(need).map(move |matched| {
            if matched.offer.owner != matched.payload.id {
                Err(format!("{label} context offer payload mismatch"))
            } else {
                C::decode_fact(&matched.payload)
                    .map(|decoded| (&matched.offer, &matched.payload, decoded))
            }
        })
    }

    fn matched_entries_for<'a>(
        &'a self,
        need: &ContextNeed,
    ) -> impl Iterator<Item = &'a MatchedContext> + 'a {
        self.matched_by_need
            .get(need)
            .into_iter()
            .flat_map(|indexes| indexes.iter().map(|index| &self.matched[*index]))
    }
}

fn index_matches_by_need(matched: &[MatchedContext]) -> BTreeMap<ContextNeed, Vec<usize>> {
    let mut matched_by_need = BTreeMap::<ContextNeed, Vec<usize>>::new();
    for (index, matched) in matched.iter().enumerate() {
        matched_by_need
            .entry(matched.need.clone())
            .or_default()
            .push(index);
    }
    matched_by_need
}

/// Protocol-defined time-wake namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timeline(String);

impl Timeline {
    /// Build a stable time-wake namespace.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("timeline cannot be empty".to_string());
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid timeline {value:?}"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A scheduled wake owned by one fact.
///
/// Projection output replaces all previous wakes for the owner. The daemon
/// later turns due rows into pending projection plus `TimeRange` context.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeWake {
    /// Fact whose projection owns this wake.
    pub owner: FactId,
    /// Timeline namespace.
    pub timeline: Timeline,
    /// Inclusive scheduled time.
    pub at: u64,
}

/// A due time interval handed to a projector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeRange {
    /// Timeline namespace.
    pub timeline: Timeline,
    /// Lower bound already processed for this daemon admission, if any.
    pub start_exclusive: Option<u64>,
    /// Inclusive upper bound admitted for projection.
    pub end_inclusive: u64,
}

impl TimeRange {
    /// Return whether a scheduled point is inside this due interval.
    pub fn contains(&self, at: u64) -> bool {
        self.start_exclusive.is_none_or(|start| at > start) && at <= self.end_inclusive
    }
}

/// Complete uncommitted output of projecting one fact.
///
/// `needs`, `offers`, and `time_wakes` are the replacement sets owned by the
/// projected fact. `effects` are ordinary runtime effects that commit in the
/// same transaction after ownership checks pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionOutput {
    /// Complete replacement needs for the projected fact.
    pub needs: Vec<ContextNeed>,
    /// Complete replacement offers for the projected fact.
    pub offers: Vec<ContextOffer>,
    /// Complete replacement time wakes for the projected fact.
    pub time_wakes: Vec<TimeWake>,
    /// Child facts, self-purge, row mutations, and intents to commit with this projection.
    pub effects: PipelineEffects,
}

impl ProjectionOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn need(mut self, need: ContextNeed) -> Self {
        self.needs.push(need);
        self
    }

    pub fn offer(mut self, offer: ContextOffer) -> Self {
        self.offers.push(offer);
        self
    }

    pub fn time_wake(mut self, wake: TimeWake) -> Self {
        self.time_wakes.push(wake);
        self
    }

    pub fn row_mutation(mut self, mutation: RowMutation) -> Self {
        self.effects.row_mutations.push(mutation);
        self
    }

    /// Purge the projected fact after its projector has removed owned rows.
    ///
    /// Core verifies at commit preparation that this id is the projected fact
    /// id. Cross-fact deletion must be expressed as context that wakes the
    /// target fact's projector, not as another projector purging it.
    pub fn purge_self(mut self, id: FactId) -> Self {
        self.effects.purged_facts.push(id);
        self
    }

    pub fn fact(mut self, fact: Fact) -> Self {
        self.effects.facts.push(fact);
        self
    }

    pub fn intent(mut self, intent: Intent) -> Self {
        self.effects.intents.push(intent);
        self
    }

    pub fn local_intent(mut self, intent: Intent) -> Self {
        self.effects.local_intents.push(intent);
        self
    }

    pub fn context_set(&self) -> ContextSet {
        ContextSet {
            needs: self.needs.clone(),
            offers: self.offers.clone(),
        }
        .normalized()
    }
}

/// The protocol-facing projection entry point.
///
/// Implement this when the projector wants to own decoding itself. Otherwise,
/// prefer `FactCodec` plus `TypedProjector` so byte layout stays next to the
/// fact module that owns it.
pub trait Projector {
    fn project(&self, fact: &Fact, context: &ProjectionContext)
        -> Result<ProjectionOutput, String>;
}

/// Function pointer used by static projector route tables.
pub type ProjectorFn = fn(&Fact, &ProjectionContext) -> Result<ProjectionOutput, String>;
/// Function that maps an envelope fact to its semantic fact tag.
pub type EffectiveTagFn = fn(&Fact) -> Result<u8, String>;

/// Route from a fact tag to the projector that owns that tag.
#[derive(Debug, Clone, Copy)]
pub struct FactRoute {
    /// Effective fact tag routed to this projector function.
    pub tag: u8,
    pub projector: ProjectorFn,
}

/// Route for envelope facts whose outer tag is not the semantic fact tag.
#[derive(Debug, Clone, Copy)]
pub struct EnvelopeRoute {
    /// Outer fact tag identifying the envelope layout.
    pub outer_tag: u8,
    /// Function that reads the envelope enough to choose the semantic route.
    pub effective_tag: EffectiveTagFn,
}

/// Tag router used by protocol registries.
///
/// Core reads only the first byte and any protocol-supplied envelope tag
/// function. It does not know what a tag means beyond selecting the registered
/// projector function.
#[derive(Debug, Clone, Copy)]
pub struct RouterProjector {
    routes: &'static [FactRoute],
    envelopes: &'static [EnvelopeRoute],
}

impl RouterProjector {
    pub const fn new(routes: &'static [FactRoute], envelopes: &'static [EnvelopeRoute]) -> Self {
        Self { routes, envelopes }
    }

    fn effective_tag(&self, fact: &Fact) -> Result<u8, String> {
        let Some(tag) = fact.bytes.first().copied() else {
            return Err("cannot project empty fact bytes".to_string());
        };
        if let Some(envelope) = self
            .envelopes
            .iter()
            .find(|envelope| envelope.outer_tag == tag)
        {
            return (envelope.effective_tag)(fact);
        }
        Ok(tag)
    }
}

impl Projector for RouterProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let tag = self.effective_tag(fact)?;
        let Some(route) = self.routes.iter().find(|route| route.tag == tag) else {
            return Err(format!("no target projector registered for fact tag {tag}"));
        };
        (route.projector)(fact, context)
    }
}

/// Type-aware decoder supplied by the fact module that owns the wire layout.
///
/// Core owns when decoding happens in the projection call path. Protocol fact
/// modules still own how their bytes become typed payloads, because that
/// semantic shape belongs with the module boundary rather than the generic
/// runtime.
pub trait FactCodec {
    type Payload;

    fn decode_fact(fact: &Fact) -> Result<Self::Payload, String>;
}

/// Projector implementation after core has decoded the input fact.
///
/// A projector should spend its body on admission policy: scope checks,
/// context proof checks, offers, rows, and emitted intents. Byte decoding stays
/// in the codec selected by the `Projector` entry point.
pub trait TypedProjector<C: FactCodec> {
    fn project_typed(
        &self,
        fact: &Fact,
        payload: C::Payload,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String>;
}

/// Decode a fact through `C` and call the typed projector implementation.
pub fn project_typed<C, P>(
    projector: &P,
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String>
where
    C: FactCodec,
    P: TypedProjector<C>,
{
    let payload = C::decode_fact(fact)?;
    projector.project_typed(fact, payload, context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ContextKey, Role};
    use crate::core::facts::FactScope;

    #[test]
    fn projection_output_keeps_context_and_work_separate() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([2; 32]);
        let output = ProjectionOutput::new()
            .need(ContextNeed {
                owner: id,
                role: role.clone(),
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key,
            });

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.offers.len(), 1);
        assert!(output.effects.intents.is_empty());
    }

    #[test]
    fn projection_output_exposes_normalized_replacement_context() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([2; 32]),
            end_key: ContextKey::from_bytes([2; 32]),
        };
        let output = ProjectionOutput::new()
            .need(need.clone())
            .need(need.clone());

        assert_eq!(output.context_set().needs, vec![need]);
    }

    #[test]
    fn projection_context_indexes_matched_payloads_by_need() {
        let role = Role::new("exact").unwrap();
        let need_a = ContextNeed {
            owner: [1; 32],
            role: role.clone(),
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let need_b = ContextNeed {
            owner: [2; 32],
            role: role.clone(),
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([20; 32]),
            end_key: ContextKey::from_bytes([20; 32]),
        };
        let context = ProjectionContext::from_matches(vec![
            matched_context(need_a.clone(), [11; 32]),
            matched_context(need_b.clone(), [22; 32]),
            matched_context(need_a.clone(), [33; 32]),
        ]);

        assert_eq!(context.matched_by_need.get(&need_a), Some(&vec![0, 2]));
        assert_eq!(context.matched_by_need.get(&need_b), Some(&vec![1]));

        let payload_ids = context
            .matched_payloads_for(&need_a)
            .map(|(_offer, payload)| payload.id)
            .collect::<Vec<_>>();
        assert_eq!(payload_ids, vec![[11; 32], [33; 32]]);
        assert_eq!(
            context.payload_for(&need_b).map(|payload| payload.id),
            Some([22; 32])
        );
    }

    #[test]
    fn projection_context_decodes_payload_with_fact_codec() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let context = ProjectionContext::from_matches(vec![matched_context(need.clone(), [7; 32])]);

        assert_eq!(context.payload_as::<FirstByteCodec>(&need), Ok(Some(7)));
        assert_eq!(
            context.payload_as::<FirstByteCodec>(&ContextNeed {
                owner: [2; 32],
                role: Role::new("exact").unwrap(),
                scope: FactScope::Global,
                start_key: ContextKey::from_bytes([20; 32]),
                end_key: ContextKey::from_bytes([20; 32]),
            }),
            Ok(None)
        );
    }

    #[test]
    fn projection_context_decodes_checked_matched_payloads() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let context = ProjectionContext::from_matches(vec![
            matched_context(need.clone(), [7; 32]),
            matched_context(need.clone(), [8; 32]),
        ]);

        let payloads = context
            .matched_payloads_as_checked::<FirstByteCodec>(&need, "typed")
            .map(|matched| {
                let (offer, payload, decoded) = matched?;
                Ok((offer.owner, payload.id, decoded))
            })
            .collect::<Result<Vec<_>, String>>()
            .expect("typed matched payloads");

        assert_eq!(payloads, vec![([7; 32], [7; 32], 7), ([8; 32], [8; 32], 8)]);
    }

    #[test]
    fn checked_typed_payloads_report_offer_payload_mismatch_before_decode() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let mut matched = matched_context(need.clone(), [7; 32]);
        matched.offer.owner = [8; 32];
        matched.payload.bytes.clear();
        let context = ProjectionContext::from_matches(vec![matched]);

        let err = context
            .matched_payloads_as_checked::<FirstByteCodec>(&need, "typed")
            .next()
            .expect("matched payload")
            .expect_err("offer owner mismatch should fail before decode");

        assert_eq!(err, "typed context offer payload mismatch");
    }

    struct FirstByteCodec;

    impl FactCodec for FirstByteCodec {
        type Payload = u8;

        fn decode_fact(fact: &Fact) -> Result<Self::Payload, String> {
            fact.bytes
                .first()
                .copied()
                .ok_or_else(|| "empty typed payload".to_string())
        }
    }

    fn matched_context(need: ContextNeed, payload_id: FactId) -> MatchedContext {
        let payload = Fact {
            id: payload_id,
            scope: need.scope.clone(),
            timestamp: 1,
            bytes: payload_id.to_vec(),
        };
        MatchedContext {
            offer: ContextOffer {
                owner: payload_id,
                role: need.role.clone(),
                scope: need.scope.clone(),
                start_key: need.start_key.clone(),
                end_key: need.end_key.clone(),
            },
            need,
            payload,
        }
    }
}
