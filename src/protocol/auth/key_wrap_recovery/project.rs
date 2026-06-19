pub mod decode {
    //! Byte decoding for local key-wrap recovery facts.

    use crate::core::wire;

    use super::super::encode::{
        validate_fact, wire_err, KEY_WRAP_RECOVERY_BYTES, TYPE_KEY_WRAP_RECOVERY,
    };
    use super::super::fact::KeyWrapRecoveryFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<KeyWrapRecoveryFact, String> {
        wire::expect_len(bytes, KEY_WRAP_RECOVERY_BYTES).map_err(wire_err)?;
        if bytes[0] != TYPE_KEY_WRAP_RECOVERY {
            return Err("expected key wrap recovery".to_string());
        }
        let fact = KeyWrapRecoveryFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            frontier_id: bytes[33..65].try_into().unwrap(),
            recipient_key_id: bytes[65..97].try_into().unwrap(),
            key_wrap_id: bytes[97..129].try_into().unwrap(),
            local_recipient_key_id: bytes[129..161].try_into().unwrap(),
        };
        validate_fact(&fact)?;
        Ok(fact)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::key_wrap_recovery::encode::{
            encode_fact, KEY_WRAP_RECOVERY_BYTES,
        };

        fn sample_fact() -> KeyWrapRecoveryFact {
            KeyWrapRecoveryFact {
                workspace_id: [1; 32],
                frontier_id: [2; 32],
                recipient_key_id: [3; 32],
                key_wrap_id: [4; 32],
                local_recipient_key_id: [5; 32],
            }
        }

        #[test]
        fn key_wrap_recovery_roundtrips_fixed_width() {
            let fact = sample_fact();

            let encoded = encode_fact(&fact).expect("encode key wrap recovery");

            assert_eq!(encoded.len(), KEY_WRAP_RECOVERY_BYTES);
            assert_eq!(
                decode_fact(&encoded).expect("decode key wrap recovery"),
                fact
            );
        }
    }
}

pub mod authenticate {
    //! Local key-wrap recovery authenticator.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::KeyWrapRecoveryFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        recovery: KeyWrapRecoveryFact,
        _context: &ProjectionContext,
    ) -> Result<KeyWrapRecoveryFact, String> {
        verify_fact_id(fact)?;
        Ok(recovery)
    }
}

pub mod adapt {
    //! Key-wrap recovery semantic adapter.

    use super::super::fact::KeyWrapRecoveryFact;

    pub(crate) fn adapt(source: KeyWrapRecoveryFact) -> Result<KeyWrapRecoveryFact, String> {
        Ok(source)
    }
}

// Local key-wrap recovery projector.
//
// POLICY. A key-wrap recovery fact is admitted only locally. Projection waits
// for the accepted key wrap, recipient key, frontier, and exact local recipient
// material, then emits the recovered local secret fact.

use crate::core::context::ContextNeed;
use crate::core::facts::Fact;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::key_wrap::project::{matched_payload_fact, require_local_scope};
use crate::protocol::auth::key_wrap::unwrap_key_wrap_fact;

use super::fact::KeyWrapRecoveryFact;

pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::key_wrap_recovery::project::KeyWrapRecoveryProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct KeyWrapRecoveryProjector;

impl KeyWrapRecoveryProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for KeyWrapRecoveryProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl KeyWrapRecoveryProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        recovery: KeyWrapRecoveryFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_key_wrap_recovery(fact, context, recovery)
    }
}

fn project_key_wrap_recovery(
    fact: &Fact,
    projection_context: &ProjectionContext,
    recovery: KeyWrapRecoveryFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    require_local_scope(fact)?;
    let scope = crate::protocol::auth::workspace::scope(recovery.workspace_id);

    // 2. Context: exact wrap, recipient, frontier, and local recipient facts.
    let key_wrap_need = ContextNeed::range(
        fact.id,
        "sync_key_wrap",
        scope.clone(),
        recovery.key_wrap_id,
        recovery.key_wrap_id,
    );
    let recipient_need = ContextNeed::range(
        fact.id,
        "recipient_key",
        scope.clone(),
        recovery.recipient_key_id,
        recovery.recipient_key_id,
    );
    let frontier_need = ContextNeed::range(
        fact.id,
        "auth_removal_frontier",
        scope.clone(),
        recovery.frontier_id,
        recovery.frontier_id,
    );
    let local_recipient_need = ContextNeed::range(
        fact.id,
        "local_recipient_key",
        scope,
        recovery.recipient_key_id,
        recovery.recipient_key_id,
    );
    let output = ProjectionOutput::new()
        .need(key_wrap_need.clone())
        .need(recipient_need.clone())
        .need(frontier_need.clone())
        .need(local_recipient_need.clone());
    let Some(key_wrap_fact) = matched_payload_fact(projection_context, &key_wrap_need) else {
        return Ok(output);
    };
    let Some(recipient_fact) = matched_payload_fact(projection_context, &recipient_need) else {
        return Ok(output);
    };
    let Some(frontier_fact) = matched_payload_fact(projection_context, &frontier_need) else {
        return Ok(output);
    };
    let Some(local_recipient_fact) =
        matching_local_recipient_fact(projection_context, &local_recipient_need, &recovery)
    else {
        return Ok(output);
    };
    // 3. Materialize: recovered local secret fact.
    Ok(output.fact(unwrap_key_wrap_fact(
        &recovery,
        key_wrap_fact,
        local_recipient_fact,
        recipient_fact,
        frontier_fact,
    )?))
}

fn matching_local_recipient_fact<'a>(
    projection_context: &'a ProjectionContext,
    need: &'a ContextNeed,
    recovery: &KeyWrapRecoveryFact,
) -> Option<&'a Fact> {
    projection_context
        .matched_payloads_for(need)
        .map(|(_, payload)| payload)
        .find(|payload| payload.id == recovery.local_recipient_key_id)
}
