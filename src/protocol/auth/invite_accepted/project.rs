pub mod decode {
    //! Byte decoding for invite-accepted facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! hash checks live in the local `authenticate` module.

    use crate::core::wire;
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::connection::request::{
        encode::ADDR_BLOCK_BYTES, project::decode::decode_optional_addr,
    };

    use super::super::encode::{FACT_BYTES, TYPE_INVITE_ACCEPTED};
    use super::super::fact::InviteAcceptedFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<InviteAcceptedFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_INVITE_ACCEPTED {
            return Err("expected invite_accepted fact".to_string());
        }
        let mut cursor = 1;
        let workspace_id = take_id(bytes, &mut cursor);
        let invite_fact_id = take_id(bytes, &mut cursor);
        let bootstrap_hash = take_id(bytes, &mut cursor);
        let bootstrap_secret = take_id(bytes, &mut cursor);
        let accepted_endpoint_id = take_id(bytes, &mut cursor);
        let bootstrap_endpoint_id = take_id(bytes, &mut cursor);
        let mut addr = [0u8; ADDR_BLOCK_BYTES];
        addr.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
        cursor += ADDR_BLOCK_BYTES;
        let user_authority = take_id(bytes, &mut cursor);
        let endpoint_role = EndpointRole::from_u8(bytes[cursor])?;
        cursor += 1;
        let identity_scope = match bytes[cursor] {
            0 => false,
            1 => true,
            other => {
                return Err(format!(
                    "invite_accepted identity_scope has invalid value {other}"
                ))
            }
        };
        let bootstrap_addr = decode_optional_addr(&addr)?
            .ok_or_else(|| "invite_accepted bootstrap_addr cannot be empty".to_string())?;
        Ok(InviteAcceptedFact {
            workspace_id,
            invite_fact_id,
            bootstrap_hash,
            bootstrap_secret,
            accepted_endpoint_id,
            bootstrap_endpoint_id,
            bootstrap_addr,
            user_authority_fact_id: (user_authority != [0; 32]).then_some(user_authority),
            endpoint_role,
            identity_scope,
        })
    }

    fn take_id(bytes: &[u8], cursor: &mut usize) -> [u8; 32] {
        let mut out = [0; 32];
        out.copy_from_slice(&bytes[*cursor..*cursor + 32]);
        *cursor += 32;
        out
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
        use crate::protocol::auth::invite_accepted::encode::{encode_fact, FACT_BYTES};

        fn fact() -> InviteAcceptedFact {
            InviteAcceptedFact {
                workspace_id: [1; 32],
                invite_fact_id: [2; 32],
                bootstrap_hash: crate::protocol::auth::invite_secret::fact::bootstrap_secret_hash(
                    &[7; 32],
                ),
                bootstrap_secret: [7; 32],
                accepted_endpoint_id: [5; 32],
                bootstrap_endpoint_id: [6; 32],
                bootstrap_addr: "127.0.0.1:41000".parse().unwrap(),
                user_authority_fact_id: Some([8; 32]),
                endpoint_role: EndpointRole::Device,
                identity_scope: true,
            }
        }

        #[test]
        fn invite_accepted_fact_roundtrips_fixed_width() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = 0;
            assert!(decode_fact(&encoded).is_err());
        }
    }
}
pub mod authenticate {
    //! Invite-accepted authenticator.
    //!
    //! POLICY. Authenticating an `invite_accepted` fact proves, over its bytes
    //! alone:
    //!   1. LAYOUT. The bytes decode to a canonical invite-accepted fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   FIELDS. The workspace, invite, bootstrap secret/hash, accepted endpoint,
    //!      and bootstrap endpoint fields are non-zero, and the hash matches the
    //!      retained secret.
    //!
    //! This is a local membership fact, not a signed shared proof, so there is no
    //! fact-boundary signature. Admission scope (`Local`) is interpretation the
    //! projector owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};
    use crate::protocol::auth::invite_secret::fact::bootstrap_secret_hash;

    use super::super::fact::InviteAcceptedFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        accepted: InviteAcceptedFact,
        _context: &ProjectionContext,
    ) -> Result<InviteAcceptedFact, String> {
        prove_decoded_invite_accepted(fact, accepted)
    }

    fn prove_decoded_invite_accepted(
        fact: &Fact,
        accepted: InviteAcceptedFact,
    ) -> Result<InviteAcceptedFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // Non-zero fact id fields.
        if accepted.workspace_id == [0; 32]
            || accepted.invite_fact_id == [0; 32]
            || accepted.bootstrap_hash == [0; 32]
            || accepted.bootstrap_secret == [0; 32]
            || accepted.accepted_endpoint_id == [0; 32]
            || accepted.bootstrap_endpoint_id == [0; 32]
        {
            return Err("invite_accepted fact has empty fact id field".to_string());
        }
        if accepted.bootstrap_hash != bootstrap_secret_hash(&accepted.bootstrap_secret) {
            return Err("invite_accepted bootstrap hash does not match secret".to_string());
        }
        Ok(accepted)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
        use crate::protocol::auth::invite_accepted::encode;
        use crate::protocol::auth::invite_accepted::fact::InviteAcceptedFact;
        use crate::protocol::auth::invite_secret::fact::bootstrap_secret_hash;

        fn canonical_fact() -> Fact {
            let accepted = InviteAcceptedFact {
                workspace_id: [1; 32],
                invite_fact_id: [2; 32],
                bootstrap_hash: bootstrap_secret_hash(&[7; 32]),
                bootstrap_secret: [7; 32],
                accepted_endpoint_id: [5; 32],
                bootstrap_endpoint_id: [6; 32],
                bootstrap_addr: "127.0.0.1:41000".parse().unwrap(),
                user_authority_fact_id: None,
                endpoint_role: EndpointRole::Device,
                identity_scope: true,
            };
            let bytes = encode::encode_fact(&accepted).expect("encode invite_accepted");
            Fact::new(FactScope::Local, 100, bytes)
        }

        fn authenticate(fact: &Fact) -> Result<InviteAcceptedFact, String> {
            let decoded = super::super::decode::decode_fact(fact.body())?;
            super::authenticate(fact, decoded, &ProjectionContext::default())
        }

        fn is_invalid(fact: &Fact) -> bool {
            authenticate(fact).is_err()
        }

        #[test]
        fn authenticates_canonical_fact() {
            assert!(authenticate(&canonical_fact()).is_ok());
        }

        #[test]
        fn rejects_wrong_tag() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes[0] ^= 0xff;
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }

        #[test]
        fn rejects_truncated_bytes() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes.pop();
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }

        #[test]
        fn rejects_id_not_matching_bytes() {
            let canonical = canonical_fact();
            let forged = Fact {
                id: [0; 32],
                scope: canonical.scope.clone(),
                timestamp: canonical.timestamp,
                bytes: canonical.bytes.clone(),
            };
            assert!(is_invalid(&forged));
        }
    }
}
pub mod adapt {
    //! Invite-accepted semantic adapter.
    //!
    //! The current invite_accepted wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::InviteAcceptedFact;

    pub(crate) fn adapt(source: InviteAcceptedFact) -> Result<InviteAcceptedFact, String> {
        Ok(source)
    }
}

// Poc-10 invite-accepted projector.
//
// POLICY. An invite_accepted fact is admitted iff:
//   1. STRUCTURAL. The fact is local-only and all fact id/hash fields are
//      non-zero.
//   2. CONTEXT. No separate local admission metadata is required; the accepted
//      fact carries the invite-link bootstrap context.
//   3. MATERIALIZE. Write the invite_accepted row and publish accepted
//      workspace context for identity-scoped links plus connection bootstrap
//      context for maintenance. Broader network effects remain explicit
//      intent-handler work.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use super::{derived_invite_secret_fact_id, invite_accepted_row};

/// Projector route metadata for the invite_accepted fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::invite_accepted::project::InviteAcceptedProjector");

#[derive(Debug, Clone, Default)]
pub struct InviteAcceptedProjector;

impl InviteAcceptedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for InviteAcceptedProjector {
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

impl InviteAcceptedProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        accepted: super::fact::InviteAcceptedFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("invite_accepted fact must have local scope".to_string());
        }

        // 3. Materialize.
        let invite_secret_id = derived_invite_secret_fact_id(&accepted)?;
        let mut output = ProjectionOutput::new()
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "connection_invite_secret",
                crate::core::facts::FactScope::Local,
                invite_secret_id,
                invite_secret_id,
            ))
            .row_mutation(RowMutation::PutRow(invite_accepted_row(
                fact.id, &accepted,
            )?));
        if accepted.identity_scope {
            output = output.offer(super::workspace_accepted_offer(
                fact.id,
                accepted.workspace_id,
            ));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::invite_secret::fact::bootstrap_secret_hash;

    #[test]
    fn invite_accepted_offers_accepted_workspace_not_workspace_authority() {
        let (_accepted, accepted_fact) = super::super::author::accepted_fact(
            [1; 32],
            [2; 32],
            bootstrap_secret_hash(&[7; 32]),
            [7; 32],
            [3; 32],
            [4; 32],
            "127.0.0.1:41000".parse().unwrap(),
            None,
            EndpointRole::Device,
            true,
            11,
        )
        .expect("accepted fact");

        let output = InviteAcceptedProjector::new()
            .project(&accepted_fact, &ProjectionContext::default())
            .expect("accepted invite projects");

        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == super::super::AUTH_WORKSPACE_ACCEPTED_ROLE));
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "connection_invite_secret"));
        assert!(!output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "auth_workspace"));
    }

    #[test]
    fn non_identity_acceptance_does_not_offer_workspace_acceptance() {
        let (_accepted, accepted_fact) = super::super::author::accepted_fact(
            [1; 32],
            [2; 32],
            bootstrap_secret_hash(&[7; 32]),
            [7; 32],
            [3; 32],
            [4; 32],
            "127.0.0.1:41000".parse().unwrap(),
            None,
            EndpointRole::Device,
            false,
            11,
        )
        .expect("accepted fact");

        let output = InviteAcceptedProjector::new()
            .project(&accepted_fact, &ProjectionContext::default())
            .expect("accepted invite projects");

        assert!(!output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == super::super::AUTH_WORKSPACE_ACCEPTED_ROLE));
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "connection_invite_secret"));
    }
}
