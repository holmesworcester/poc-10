//! Projection context visible while processing one fact.

use super::decode::FactCodec;
use super::effects::{TimeRange, Timeline};
use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::Fact;
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
