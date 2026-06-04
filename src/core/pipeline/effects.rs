//! Projection effects and time-wake output for fact pipeline stages.

use crate::core::context::{ContextNeed, ContextOffer, ContextSet};
use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, RowMutation};

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
