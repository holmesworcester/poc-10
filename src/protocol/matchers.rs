//! Protocol context matcher surface.
//!
//! Fact modules emit these generic need/offer shapes from their projectors.
//! Matcher modules are organized by matching relation, not by fact module.

use crate::core::matchers::ContextRoleDeclaration;

pub mod coverage;
pub mod exact;
pub mod range;
mod sql;
pub mod wrap_source;

pub use coverage::*;
pub use exact::*;
pub use range::*;
pub use wrap_source::*;

pub const CONTEXT_ROLE_DECLARATIONS: &[ContextRoleDeclaration] = &[
    ContextRoleDeclaration::exact(CONNECTION_EPHEMERAL_SECRET_ROLE),
    ContextRoleDeclaration::exact(CONNECTION_INVITE_SECRET_ROLE),
    ContextRoleDeclaration::exact(CONNECTION_REQUEST_ROLE),
    ContextRoleDeclaration::exact(CONTENT_FILE_ROLE),
    ContextRoleDeclaration::exact(CONTENT_MESSAGE_ROLE),
    ContextRoleDeclaration::exact(CONTENT_MESSAGE_META_ROLE),
    ContextRoleDeclaration::exact(CONTENT_DELETED_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_ADMIN_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_DEVICE_INVITE_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_DEVICE_INVITE_KEY_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_ENDPOINT_SHARED_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_INVITE_SECRET_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_INVITE_SERVER_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_INVITE_SERVER_KEY_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_USER_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_USER_INVITE_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_USER_INVITE_KEY_ROLE),
    ContextRoleDeclaration::exact(IDENTITY_WORKSPACE_ROLE),
    ContextRoleDeclaration::exact(LOCAL_RECIPIENT_KEY_ROLE),
    ContextRoleDeclaration::exact(LOCAL_SECRET_SOURCE_ROLE),
    ContextRoleDeclaration::exact(LOCAL_SIGNER_SECRET_ROLE),
    ContextRoleDeclaration::exact(RECIPIENT_KEY_ROLE),
    ContextRoleDeclaration::exact(RECIPIENT_SUPERSEDED_ROLE),
    ContextRoleDeclaration::exact(REMOVAL_FRONTIER_ROLE),
    SECRET_COVERAGE_CONTEXT_ROLE,
    ContextRoleDeclaration::exact(CONTENT_SIGNER_ROLE),
    ContextRoleDeclaration::exact(SYNC_EXACT_FACT_ROLE),
    ContextRoleDeclaration::exact(SYNC_KEY_WRAP_ROLE),
    RANGE_FACT_CONTEXT_ROLE,
    ContextRoleDeclaration::exact(TRANSIT_RECEIVED_ROLE),
    WRAP_SOURCE_CONTEXT_ROLE,
];

pub fn context_role_declaration(role: &str) -> Option<&'static ContextRoleDeclaration> {
    CONTEXT_ROLE_DECLARATIONS
        .iter()
        .find(|declaration| declaration.role == role)
}
