//! Local content-message authoring capabilities.
//!
//! Sending a message needs two local secrets: the endpoint signing key and the
//! current local removal-frontier key. This module is the command boundary that
//! assembles those capabilities from already-projected local state. It is not a
//! projector and it is not a query module for display state.

use crate::core::command_context::{
    IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use crate::core::runtime::Runtime;
use crate::protocol::encryption;
use crate::protocol::identity;

pub struct ContentMessageVault {
    signing: LocalSigningCapability,
    encryption: LocalEncryptionCapability,
}

impl ContentMessageVault {
    pub fn for_workspace(runtime: &Runtime, workspace_id: [u8; 32]) -> Result<Self, String> {
        let endpoint = identity::endpoint::local_endpoint::local_endpoint(runtime.store())?
            .ok_or_else(|| "local endpoint is not initialized".to_string())?;
        identity::workspace::local_membership::local_membership(runtime.store(), workspace_id)?
            .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
        let encryption = latest_local_key_secret(runtime, workspace_id)?;
        Ok(Self {
            signing: LocalSigningCapability {
                workspace_id,
                signer_id: endpoint.endpoint,
                public_key: endpoint.signing_public_key,
                private_key: endpoint.signing_secret,
            },
            encryption: LocalEncryptionCapability {
                workspace_id: encryption.workspace_id,
                frontier_id: encryption.frontier_id,
                owner_endpoint_id: encryption.owner_endpoint_id,
                created_at_ms: encryption.created_at_ms,
                key_secret: encryption.key_secret,
            },
        })
    }
}

impl IdentityVault for ContentMessageVault {
    fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        if self.signing.workspace_id == workspace_id {
            Ok(self.signing.clone())
        } else {
            Err("signing capability is not for requested workspace".to_string())
        }
    }

    fn local_encryption_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        if self.encryption.workspace_id == workspace_id {
            Ok(self.encryption.clone())
        } else {
            Err("encryption capability is not for requested workspace".to_string())
        }
    }
}

fn latest_local_key_secret(
    runtime: &Runtime,
    workspace_id: [u8; 32],
) -> Result<encryption::local_key_secret::fact::LocalKeySecretFact, String> {
    runtime
        .facts()
        .filter_map(|fact| {
            encryption::local_key_secret::layout::decode_local_key_secret(fact.body())
                .ok()
                .filter(|secret| secret.workspace_id == workspace_id)
        })
        .max_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.frontier_id.cmp(&right.frontier_id))
        })
        .ok_or_else(|| "no local key frontier is available for this workspace".to_string())
}
