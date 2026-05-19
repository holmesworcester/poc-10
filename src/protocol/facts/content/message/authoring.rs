//! Local content-message authoring capabilities.
//!
//! Sending a message needs two local secrets: the endpoint signing key and the
//! current local removal-frontier key. This module is the command boundary that
//! assembles those capabilities from already-projected local state. It is not a
//! projector and it is not a query module for display state.

use crate::core::command_context::{
    IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use crate::protocol::facts::encryption;
use crate::protocol::facts::identity;
use crate::protocol::runtime::ProtocolRuntime;

pub struct ContentMessageVault {
    signing: LocalSigningCapability,
    encryption: LocalEncryptionCapability,
}

impl ContentMessageVault {
    pub fn for_workspace(
        runtime: &ProtocolRuntime,
        workspace_id: [u8; 32],
    ) -> Result<Self, String> {
        let endpoint = identity::endpoint::local_endpoint::local_endpoint(runtime.store())?
            .ok_or_else(|| "local endpoint is not initialized".to_string())?;
        identity::workspace::local_membership::local_membership(runtime.store(), workspace_id)?
            .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
        let encryption = latest_local_key_secret(runtime, workspace_id)?;
        Ok(Self {
            signing: LocalSigningCapability {
                fact: identity::signed_fact::fact::LocalSignerSecretFact {
                    workspace_id,
                    signer_id: endpoint.endpoint,
                    public_key: endpoint.signing_public_key,
                    private_key: endpoint.signing_secret,
                },
            },
            encryption: LocalEncryptionCapability { fact: encryption },
        })
    }
}

impl IdentityVault for ContentMessageVault {
    fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        if self.signing.fact.workspace_id == workspace_id {
            Ok(self.signing.clone())
        } else {
            Err("signing capability is not for requested workspace".to_string())
        }
    }

    fn local_encryption_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        if self.encryption.fact.workspace_id == workspace_id {
            Ok(self.encryption.clone())
        } else {
            Err("encryption capability is not for requested workspace".to_string())
        }
    }
}

fn latest_local_key_secret(
    runtime: &ProtocolRuntime,
    workspace_id: [u8; 32],
) -> Result<encryption::fact::LocalKeySecretFact, String> {
    runtime
        .facts()
        .filter_map(|fact| {
            encryption::layout::decode_local_key_secret(fact.body())
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
