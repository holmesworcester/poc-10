//! Projection effects and time-wake output for fact pipeline stages.

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, ContextSet, Role};
use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, RowMutation};

const FACT_PURGED_ROLE: &str = "fact_purged";

/// Context role used by deletion/retention projectors to wake a target fact.
///
/// Core treats purge keys opaquely. Protocol families choose their own stable
/// key shape and validate matched payloads before treating this context as
/// authority. This context is proof and routing only. The target projector must
/// still emit `ProjectionOutput::purge_self` after deleting its own rows so
/// core removes the target fact bytes.
pub fn fact_purged_role() -> Role {
    Role::expect(FACT_PURGED_ROLE)
}

pub fn fact_purged_need(
    owner: FactId,
    scope: crate::core::facts::FactScope,
    key: ContextKey,
) -> ContextNeed {
    ContextNeed {
        owner,
        role: fact_purged_role(),
        scope,
        start_key: key.clone(),
        end_key: key,
    }
}

pub fn fact_purged_offer(
    owner: FactId,
    scope: crate::core::facts::FactScope,
    key: ContextKey,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: fact_purged_role(),
        scope,
        start_key: key.clone(),
        end_key: key,
    }
}

pub fn fact_purged_range_need(
    owner: FactId,
    scope: crate::core::facts::FactScope,
    start_key: ContextKey,
    end_key: ContextKey,
) -> ContextNeed {
    ContextNeed {
        owner,
        role: fact_purged_role(),
        scope,
        start_key,
        end_key,
    }
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

#[cfg(test)]
mod tests {
    use crate::core::facts::FactScope;

    use super::*;

    #[test]
    fn purge_need_and_offer_match_same_opaque_key() {
        let scope = FactScope::Local;
        let key = ContextKey::from_bytes(vec![4, 2, 9]);
        let need = fact_purged_need([1; 32], scope.clone(), key.clone());
        let offer = fact_purged_offer([3; 32], scope.clone(), key);

        assert_eq!(need.role, offer.role);
        assert_eq!(need.scope, scope);
        assert_eq!(need.start_key, offer.start_key);
        assert_eq!(need.end_key, offer.end_key);
    }

    #[test]
    fn purge_range_need_spans_matching_offer_key() {
        let scope = FactScope::Local;
        let need = fact_purged_range_need(
            [1; 32],
            scope.clone(),
            ContextKey::from_bytes(vec![2, 0]),
            ContextKey::from_bytes(vec![2, 255]),
        );
        let offer = fact_purged_offer([3; 32], scope.clone(), ContextKey::from_bytes(vec![2, 9]));

        assert_eq!(need.role, offer.role);
        assert_eq!(need.scope, scope);
        assert!(need.start_key <= offer.start_key);
        assert!(need.end_key >= offer.end_key);
    }
}
