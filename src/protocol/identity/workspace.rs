//! Workspace fact family.
//!
//! Workspace facts are the root identity object for most protocol state.
//! Projection materializes workspace rows and context that users, endpoints,
//! content, encryption, and sync all depend on. Commands here create or inspect
//! workspaces; local membership helpers expose this store's capabilities for
//! command contexts.

pub mod cli;
pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_WORKSPACE: u8 = layout::TYPE_WORKSPACE;

pub fn scope(workspace_id: crate::core::facts::FactId) -> crate::core::facts::FactScope {
    crate::core::facts::FactScope::Scoped {
        kind: crate::core::facts::ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::WorkspaceFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::WorkspaceFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
