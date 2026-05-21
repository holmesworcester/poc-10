//! Core context matching.

use crate::core::context::{ContextNeed, ContextOffer, Role};
use std::collections::BTreeSet;

pub trait ContextMatcher {
    fn role(&self) -> &Role;

    fn matches(&self, need: &ContextNeed, offer: &ContextOffer) -> bool;
}

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
