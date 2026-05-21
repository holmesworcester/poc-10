//! Core context matching.

use crate::core::context::{ContextNeed, ContextOffer, Role};
use crate::core::select;
use crate::core::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextRoleDeclaration {
    pub role: &'static str,
    pub need_selector: &'static [SelectorFieldDeclaration],
    pub offer_selector: &'static [SelectorFieldDeclaration],
    pub matcher: ContextMatcherDeclaration,
}

impl ContextRoleDeclaration {
    pub const fn exact(role: &'static str) -> Self {
        Self {
            role,
            need_selector: &[],
            offer_selector: &[],
            matcher: ContextMatcherDeclaration::ExactSelector,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectorFieldDeclaration {
    pub name: &'static str,
    pub ty: SelectorFieldType,
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorFieldType {
    U8,
    U16,
    U64,
    FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextMatcherDeclaration {
    ExactSelector,
    SelectOnlySql {
        added_need: SelectOnlyMatcherSql,
        added_offer: SelectOnlyMatcherSql,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectOnlyMatcherSql {
    pub sql: &'static str,
    pub result: SelectOnlyMatcherResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectOnlyMatcherResult {
    OffersForNeed,
    NeedsForOffer,
}

pub trait ContextMatcher {
    fn role(&self) -> &Role;

    fn declaration(&self) -> Option<ContextRoleDeclaration> {
        None
    }

    fn exact_selector_role(&self) -> Option<&Role> {
        None
    }

    fn matching_offers_for_need_from_store(
        &self,
        _store: &Store,
        _need: &ContextNeed,
    ) -> Result<Vec<ContextOffer>, String> {
        Ok(Vec::new())
    }

    fn wake_select_for_added_need(&self, _need: &ContextNeed) -> Result<select::Select, String> {
        Ok(select::Select::empty())
    }

    fn wake_select_for_added_offer(&self, _offer: &ContextOffer) -> Result<select::Select, String> {
        Ok(select::Select::empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactSelectorMatcher {
    role: Role,
}

impl ExactSelectorMatcher {
    pub fn new(role: Role) -> Self {
        Self { role }
    }
}

impl ContextMatcher for ExactSelectorMatcher {
    fn role(&self) -> &Role {
        &self.role
    }

    fn exact_selector_role(&self) -> Option<&Role> {
        Some(&self.role)
    }
}
