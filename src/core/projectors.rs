//! Projector contract for fact plus context to needs, offers, and intents.

use crate::core::context::{ContextNeed, ContextOffer, ContextSet};
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, RowMutation};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionContext {
    offers: Vec<ContextOffer>,
    matched: Vec<MatchedContext>,
    matched_by_need: BTreeMap<ContextNeed, Vec<usize>>,
    time_ranges: Vec<TimeRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedContext {
    pub need: ContextNeed,
    pub offer: ContextOffer,
    pub payload: Fact,
}

impl ProjectionContext {
    pub fn new(offers: Vec<ContextOffer>) -> Self {
        Self {
            offers,
            matched: Vec::new(),
            matched_by_need: BTreeMap::new(),
            time_ranges: Vec::new(),
        }
    }

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

    pub fn offers(&self) -> &[ContextOffer] {
        &self.offers
    }

    pub fn matched_context(&self) -> &[MatchedContext] {
        &self.matched
    }

    pub fn with_time_ranges(mut self, time_ranges: Vec<TimeRange>) -> Self {
        self.time_ranges = time_ranges;
        self
    }

    pub fn time_ranges(&self) -> &[TimeRange] {
        &self.time_ranges
    }

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
    /// projection. It does not query storage or run matcher logic.
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

    pub fn payload_as<C>(&self, need: &ContextNeed) -> Result<Option<C::Payload>, String>
    where
        C: FactCodec,
    {
        self.payload_for(need).map(C::decode_fact).transpose()
    }

    pub fn payload_as_checked<C>(
        &self,
        need: &ContextNeed,
        label: &str,
    ) -> Result<Option<C::Payload>, String>
    where
        C: FactCodec,
    {
        self.payload_for_checked(need, label)?
            .map(C::decode_fact)
            .transpose()
    }

    pub fn matched_payloads_for<'a>(
        &'a self,
        need: &'a ContextNeed,
    ) -> impl Iterator<Item = (&'a ContextOffer, &'a Fact)> + 'a {
        self.matched_entries_for(need)
            .map(|matched| (&matched.offer, &matched.payload))
    }

    pub fn matched_payloads_for_checked<'a>(
        &'a self,
        need: &'a ContextNeed,
        label: &'a str,
    ) -> impl Iterator<Item = Result<(&'a ContextOffer, &'a Fact), String>> + 'a {
        self.matched_entries_for(need).map(move |matched| {
            if matched.offer.owner != matched.payload.id {
                Err(format!("{label} context offer payload mismatch"))
            } else {
                Ok((&matched.offer, &matched.payload))
            }
        })
    }

    pub fn matched_payloads_as_checked<'a, C>(
        &'a self,
        need: &'a ContextNeed,
        label: &'a str,
    ) -> impl Iterator<Item = Result<(&'a ContextOffer, &'a Fact, C::Payload), String>> + 'a
    where
        C: FactCodec + 'a,
    {
        self.matched_payloads_for_checked(need, label)
            .map(|matched| {
                let (offer, payload) = matched?;
                C::decode_fact(payload).map(|decoded| (offer, payload, decoded))
            })
    }

    pub fn offer_owners_matching<'a>(
        &'a self,
        role: &'a crate::core::context::Role,
        scope: &'a crate::core::facts::FactScope,
        selector: &'a crate::core::context::Selector,
    ) -> impl Iterator<Item = FactId> + 'a {
        self.offers
            .iter()
            .filter(move |offer| {
                offer.role == *role && offer.scope == *scope && offer.selector == *selector
            })
            .map(|offer| offer.owner)
    }

    pub fn offer_owners(&self) -> impl Iterator<Item = FactId> + '_ {
        self.offers.iter().map(|offer| offer.owner)
    }

    pub fn payload_facts(&self) -> impl Iterator<Item = &Fact> + '_ {
        self.matched.iter().map(|matched| &matched.payload)
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timeline(String);

impl Timeline {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeWake {
    pub owner: FactId,
    pub timeline: Timeline,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeRange {
    pub timeline: Timeline,
    pub start_exclusive: Option<u64>,
    pub end_inclusive: u64,
}

impl TimeRange {
    pub fn contains(&self, at: u64) -> bool {
        self.start_exclusive.is_none_or(|start| at > start) && at <= self.end_inclusive
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionOutput {
    pub needs: Vec<ContextNeed>,
    pub offers: Vec<ContextOffer>,
    pub time_wakes: Vec<TimeWake>,
    pub row_mutations: Vec<RowMutation>,
    pub intents: Vec<Intent>,
    pub local_intents: Vec<Intent>,
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
        self.row_mutations.push(mutation);
        self
    }

    pub fn intent(mut self, intent: Intent) -> Self {
        self.intents.push(intent);
        self
    }

    pub fn local_intent(mut self, intent: Intent) -> Self {
        self.local_intents.push(intent);
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

pub trait Projector {
    fn project(&self, fact: &Fact, context: &ProjectionContext)
        -> Result<ProjectionOutput, String>;
}

pub type ProjectorFn = fn(&Fact, &ProjectionContext) -> Result<ProjectionOutput, String>;
pub type EffectiveTagFn = fn(&Fact) -> Result<u8, String>;

#[derive(Debug, Clone, Copy)]
pub struct FactRoute {
    pub tag: u8,
    pub projector: ProjectorFn,
}

#[derive(Debug, Clone, Copy)]
pub struct EnvelopeRoute {
    pub outer_tag: u8,
    pub effective_tag: EffectiveTagFn,
}

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
    use crate::core::context::{Role, Selector};
    use crate::core::facts::FactScope;

    #[test]
    fn projection_output_keeps_context_and_work_separate() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([2; 32]);
        let output = ProjectionOutput::new()
            .need(ContextNeed {
                owner: id,
                role: role.clone(),
                scope: FactScope::Global,
                selector: selector.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                selector,
            });

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.offers.len(), 1);
        assert!(output.intents.is_empty());
    }

    #[test]
    fn projection_output_exposes_normalized_replacement_context() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
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
            selector: Selector::from_bytes([10; 32]),
        };
        let need_b = ContextNeed {
            owner: [2; 32],
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([20; 32]),
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
            selector: Selector::from_bytes([10; 32]),
        };
        let context = ProjectionContext::from_matches(vec![matched_context(need.clone(), [7; 32])]);

        assert_eq!(context.payload_as::<FirstByteCodec>(&need), Ok(Some(7)));
        assert_eq!(
            context.payload_as_checked::<FirstByteCodec>(&need, "typed"),
            Ok(Some(7))
        );
        assert_eq!(
            context.payload_as::<FirstByteCodec>(&ContextNeed {
                owner: [2; 32],
                role: Role::new("exact").unwrap(),
                scope: FactScope::Global,
                selector: Selector::from_bytes([20; 32]),
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
            selector: Selector::from_bytes([10; 32]),
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
            selector: Selector::from_bytes([10; 32]),
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
                selector: need.selector.clone(),
            },
            need,
            payload,
        }
    }
}
