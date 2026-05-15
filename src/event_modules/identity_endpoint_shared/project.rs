//! Poc-10 endpoint-shared projector.
//!
//! Decodes a shared endpoint identity fact and emits a single `PutRow` atomic
//! intent into `identity_endpoint_shared_rows` keyed by
//! `workspace_id || endpoint_shared_id` (the endpoint shared id is the fact id).
//!
//! Legacy parity gaps (intentional, see commit message):
//!
//! - The legacy projector requires the payload to be carried by a signed
//!   envelope and validates the signer against either a device invite or an
//!   invite server. The target tree has not yet ported the signed-envelope,
//!   device_invite, or invite_server modules, so signed-envelope decoding and
//!   signer-public-key matching are deferred.
//! - The legacy projector also walks a `DependencyContext` to confirm the
//!   workspace and user-authority bindings declared in the payload match the
//!   authorising invite, and to require that the role declared in the payload
//!   matches the invite type. Dependency-context plumbing is not part of the
//!   `ProjectionContext` yet, so those cross-event checks are deferred.
//! - The legacy projector additionally writes an `identity.endpoint_memberships`
//!   index row keyed by `endpoint_id || workspace_id` for duplicate-join
//!   preflight. That row is part of the membership/connection ingress story
//!   and depends on the invite checks above; it is deferred until the
//!   dependency-context port lands.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::endpoint_shared_row;

#[derive(Debug, Clone, Default)]
pub struct EndpointSharedProjector;

impl EndpointSharedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EndpointSharedProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Global {
            return Err("endpoint shared fact must have global scope".to_string());
        }
        let event = layout::decode_fact(&fact.bytes)?;
        if event.endpoint_id.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared endpoint_id cannot be empty".to_string());
        }
        if event.signing_public_key.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared signing_public_key cannot be empty".to_string());
        }
        if event.workspace_id.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared workspace_id cannot be empty".to_string());
        }
        if event.device_name.as_bytes().contains(&0) {
            return Err("endpoint device name cannot contain NUL".to_string());
        }
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(endpoint_shared_row(fact.id, &event)?).into_intent()))
    }
}
