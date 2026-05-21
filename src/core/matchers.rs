//! Context matcher registry for projection wakeups.
//!
//! Core supports two matching mechanisms. Exact roles use the generic
//! `scope_key + role + selector` rows in `context_edges`, and custom matchers
//! provide protocol-owned SQL when exact matching is not expressive enough.
//! This module only records which mechanism applies to each role. It does not
//! interpret selectors, load payloads, or decide whether a match is sufficient
//! for a projector to make progress.
//!
//! If a new relationship can be expressed as exact equality, add its role to
//! `ContextMatchers::new`. If the relationship needs range, prefix, visibility,
//! or other protocol semantics, implement `ContextMatcher` in the module that
//! owns those semantics and register it here through the runtime description.

use crate::core::context::{ContextNeed, ContextOffer, Role};
use crate::core::select;
use crate::core::store::Store;
use std::collections::BTreeSet;

pub trait ContextMatcher {
    /// The context role this matcher owns.
    ///
    /// Core uses this as a routing key. A matcher must not claim a broad role
    /// it cannot wake from both sides, because the pipeline will ask it about
    /// every added need and every added offer for that role.
    fn role(&self) -> &Role;

    /// Return offers that satisfy one stored need.
    ///
    /// This is used when assembling `ProjectionContext` for a pending fact.
    /// The returned offers must be current standing context rows whose owner is
    /// the fact core should load as payload.
    fn matching_offers_for_need_from_store(
        &self,
        _store: &Store,
        _need: &ContextNeed,
    ) -> Result<Vec<ContextOffer>, String> {
        Ok(Vec::new())
    }

    /// Select pending projection owners woken by a newly added need.
    ///
    /// The select runs inside the projection transaction. It must return one
    /// column named `owner`, and it may read only the tables declared in the
    /// returned `Select`.
    fn wake_select_for_added_need(&self, _need: &ContextNeed) -> Result<select::Select, String> {
        Ok(select::Select::empty())
    }

    /// Select pending projection owners woken by a newly added offer.
    ///
    /// This is the mirror of `wake_select_for_added_need`: the matcher owns the
    /// protocol SQL, while core owns inserting the selected owners into the
    /// pending projection queue.
    fn wake_select_for_added_offer(&self, _offer: &ContextOffer) -> Result<select::Select, String> {
        Ok(select::Select::empty())
    }
}

/// All context matching declarations used by one runtime.
///
/// The split between `exact_roles` and `custom` is intentional. Exact matching
/// stays in core's generic SQL; custom matching stays in the protocol modules
/// that own the meaning of non-exact selectors.
pub struct ContextMatchers {
    exact_roles: BTreeSet<Role>,
    custom: Vec<Box<dyn ContextMatcher>>,
}

impl ContextMatchers {
    pub fn empty() -> Self {
        Self {
            exact_roles: BTreeSet::new(),
            custom: Vec::new(),
        }
    }

    pub fn new(
        exact_roles: impl IntoIterator<Item = Role>,
        custom: Vec<Box<dyn ContextMatcher>>,
    ) -> Self {
        Self {
            exact_roles: exact_roles.into_iter().collect(),
            custom,
        }
    }

    pub fn exact_roles(&self) -> &BTreeSet<Role> {
        &self.exact_roles
    }

    pub fn has_exact_role(&self, role: &Role) -> bool {
        self.exact_roles.contains(role)
    }

    pub fn custom(&self) -> impl Iterator<Item = &dyn ContextMatcher> {
        self.custom
            .iter()
            .map(|matcher| matcher.as_ref() as &dyn ContextMatcher)
    }

    pub fn custom_for_role<'a>(
        &'a self,
        role: &'a Role,
    ) -> impl Iterator<Item = &'a dyn ContextMatcher> + 'a {
        self.custom().filter(move |matcher| matcher.role() == role)
    }
}
