pub mod decode {
    //! Byte decoding for content-message-deletion target facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{CONTENT_MESSAGE_DELETION_BYTES, TYPE_CONTENT_MESSAGE_DELETION};
    use super::super::fact::ContentMessageDeletionFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<ContentMessageDeletionFact, String> {
        let mut reader = wire::Reader::new(bytes);
        reader
            .expect_len(CONTENT_MESSAGE_DELETION_BYTES)
            .map_err(wire_err)?;
        let tag = reader.u8().map_err(wire_err)?;
        if tag != TYPE_CONTENT_MESSAGE_DELETION {
            return Err("expected content message deletion fact".to_string());
        }
        let fact = ContentMessageDeletionFact {
            workspace_id: reader.array().map_err(wire_err)?,
            created_at_ms: reader.u64be().map_err(wire_err)?,
            target_message_id: reader.array().map_err(wire_err)?,
            target_frontier_id: reader.array().map_err(wire_err)?,
            target_minute: reader.u64be().map_err(wire_err)?,
            author_user_id: reader.array().map_err(wire_err)?,
            signer_id: reader.array().map_err(wire_err)?,
            signer_public_key: reader.array().map_err(wire_err)?,
        };
        reader.finish().map_err(wire_err)?;
        Ok(fact)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::content::message_deletion::encode::{
            encode_fact, CONTENT_MESSAGE_DELETION_BYTES, TYPE_CONTENT_MESSAGE_DELETION,
        };

        fn fact() -> ContentMessageDeletionFact {
            ContentMessageDeletionFact {
                workspace_id: [1; 32],
                created_at_ms: 9_000,
                target_message_id: [2; 32],
                target_frontier_id: [3; 32],
                target_minute: 7,
                author_user_id: [4; 32],
                signer_id: [9; 32],
                signer_public_key: [10; 32],
            }
        }

        #[test]
        fn content_message_deletion_roundtrips_fixed_width() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), CONTENT_MESSAGE_DELETION_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = TYPE_CONTENT_MESSAGE_DELETION.wrapping_add(1);
            assert!(decode_fact(&encoded).is_err());
        }
    }
}
pub mod authenticate {
    //! Content-message-deletion authenticator.
    //!
    //! POLICY. Authenticating a `content_message_deletion` fact proves, over its
    //! canonical bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical content-message-deletion fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!
    //! Admission scope is unsigned local metadata, not part of these bytes, so the
    //! workspace-scope check is interpretation the projector owns. The authority of
    //! the signer, target message, and author user is proven from other facts, also
    //! in the projector.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::ContentMessageDeletionFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        deletion: ContentMessageDeletionFact,
        _context: &ProjectionContext,
    ) -> Result<ContentMessageDeletionFact, String> {
        prove_decoded_message_deletion(fact, deletion)
    }

    fn prove_decoded_message_deletion(
        fact: &Fact,
        deletion: ContentMessageDeletionFact,
    ) -> Result<ContentMessageDeletionFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(deletion)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::command::LocalSigningCapability;
        use crate::core::crypto;
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::content::message_deletion::author::delete_message;
        use crate::protocol::content::message_deletion::fact::ContentMessageDeletionFact;

        const PRIVATE_KEY: [u8; 32] = [7; 32];
        const WORKSPACE_ID: [u8; 32] = [1; 32];

        fn signing_capability() -> LocalSigningCapability {
            LocalSigningCapability {
                workspace_id: WORKSPACE_ID,
                signer_id: [2; 32],
                public_key: crypto::ed25519_public_key(&PRIVATE_KEY),
                private_key: PRIVATE_KEY,
            }
        }

        fn canonical_fact() -> Fact {
            delete_message(
                &signing_capability(),
                WORKSPACE_ID,
                100,
                [3; 32],
                [4; 32],
                3,
                [5; 32],
            )
            .expect("content message deletion fact")
        }

        fn authenticate(fact: &Fact) -> Result<ContentMessageDeletionFact, String> {
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
    //! Content-message-deletion semantic adapter.
    //!
    //! The current message_deletion wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::ContentMessageDeletionFact;

    pub(crate) fn adapt(
        source: ContentMessageDeletionFact,
    ) -> Result<ContentMessageDeletionFact, String> {
        Ok(source)
    }
}

// Poc-10 content-message-deletion projector.
//
// POLICY. A content_message_deletion is admitted iff:
//   1. STRUCTURAL. The fact is workspace-scoped, signed, and contains a
//      deletion payload for one message and author user.
//   2. AUTHORITY. The signer, target message, and author contexts prove the
//      deletion author is the target message author in the same workspace.
//      This uses authenticated message metadata, so deletes do not wait for
//      encrypted message text to open.
//   3. MATERIALIZE. Once authorized, write the deletion row, publish the
//      fact_purged offer, and share the deletion fact.

use crate::core::facts::Fact;
use crate::core::intents::{RowMutation, TableInsert, Value};
use crate::core::project_fact::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};

use crate::protocol::auth::signature;
use crate::protocol::auth::user;
use crate::protocol::content::message;
use crate::protocol::content::message::project::{self, FactSigner};
use crate::protocol::registry::read_models;
use crate::protocol::sync::shared_fact::project::{
    context_have_from_optional_needs, share_fact_with_sync,
};

use super::queries::MessageDeletionRow;

/// Projector route metadata for the message_deletion fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("content::message_deletion::project::ContentMessageDeletionProjector");

fn message_deletion_row(input: MessageDeletionRow) -> TableInsert {
    read_models::MESSAGE_DELETIONS.insert(vec![
        Value::Bytes(input.workspace_id.to_vec()),
        Value::Bytes(input.target_message_id.to_vec()),
        Value::Bytes(input.deletion_id.to_vec()),
        Value::U64(input.created_at_ms),
        Value::Bytes(input.author_user_id.to_vec()),
    ])
}

#[derive(Debug, Clone, Default)]
pub struct ContentMessageDeletionProjector;

impl ContentMessageDeletionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentMessageDeletionProjector {
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

impl ContentMessageDeletionProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        deletion: super::fact::ContentMessageDeletionFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(deletion.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Authority and signature evidence.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            scope.clone(),
            fact.id,
            deletion.signer_public_key,
        )?;
        let signer_need = project::signer_need(fact.id, deletion.workspace_id, deletion.signer_id);
        let target_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_message_meta",
            scope.clone(),
            deletion.target_message_id,
            deletion.target_message_id,
        );
        let author_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user",
            crate::core::facts::FactScope::Global,
            deletion.author_user_id,
            deletion.author_user_id,
        );
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            deletion.workspace_id,
            fact.id,
            deletion.signer_public_key,
            "message deletion",
        )? {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(author_need),
            ]));
        }
        if !project::validate_signer_context(
            context,
            &signer_need,
            FactSigner {
                signer_id: deletion.signer_id,
                signer_public_key: deletion.signer_public_key,
            },
            deletion.workspace_id,
            Some(deletion.author_user_id),
            "message deletion",
        )? {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(author_need),
            ]));
        }
        let Some(target_fact) = context_payload(context, &target_need, "message deletion target")?
        else {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(author_need),
            ]));
        };
        let Some(author_fact) = context_payload(context, &author_need, "message deletion author")?
        else {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(author_need),
            ]));
        };
        validate_target_message(&deletion, target_fact)?;
        validate_author_user(&deletion, author_fact)?;
        let context_have = context_have_from_optional_needs(
            context,
            [
                Some(&signature_need),
                Some(&signer_need),
                Some(&target_need),
                Some(&author_need),
            ],
        );

        // 3. Materialize.
        let row = message_deletion_row(MessageDeletionRow {
            workspace_id: deletion.workspace_id,
            target_message_id: deletion.target_message_id,
            deletion_id: fact.id,
            created_at_ms: deletion.created_at_ms,
            author_user_id: deletion.author_user_id,
        });
        Ok(share_fact_with_sync(
            output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(author_need),
            ])
            .offer(crate::core::project_fact::fact_purged_offer(
                fact.id,
                scope,
                project::fact_purged_key(
                    deletion.target_frontier_id,
                    deletion.target_minute,
                    deletion.target_message_id,
                ),
            ))
            .row_mutation(RowMutation::InsertValues(row)),
            deletion.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    project::context_payload(context, need, label)
}

fn output_with_needs(
    needs: impl IntoIterator<Item = Option<crate::core::context::ContextNeed>>,
) -> ProjectionOutput {
    needs
        .into_iter()
        .flatten()
        .fold(ProjectionOutput::new(), |output, need| output.need(need))
}

fn validate_target_message(
    deletion: &super::fact::ContentMessageDeletionFact,
    target_fact: &Fact,
) -> Result<(), String> {
    if target_fact.id != deletion.target_message_id {
        return Err("message deletion target context payload id mismatch".to_string());
    }
    let target = project::decode_typed_fact(
        target_fact,
        message::TYPE_CONTENT_MESSAGE,
        "message deletion target",
        message::decode_fact_payload,
    )
    .map_err(|_| "message deletion target context must be a content message".to_string())?;
    if target.workspace_id != deletion.workspace_id {
        return Err("message deletion target workspace does not match deletion".to_string());
    }
    if target.frontier_id != deletion.target_frontier_id {
        return Err("message deletion target frontier does not match deletion".to_string());
    }
    if target.minute != deletion.target_minute {
        return Err("message deletion target minute does not match deletion".to_string());
    }
    if target.author_user_id != deletion.author_user_id {
        return Err("message deletion author is not the target message author".to_string());
    }
    Ok(())
}

fn validate_author_user(
    deletion: &super::fact::ContentMessageDeletionFact,
    author_fact: &Fact,
) -> Result<(), String> {
    if author_fact.id != deletion.author_user_id {
        return Err("message deletion author context payload id mismatch".to_string());
    }
    let author = user::decode_fact_payload(author_fact.body())
        .map_err(|_| "message deletion author context must be an identity user".to_string())?;
    if author.workspace_id != deletion.workspace_id {
        return Err("message deletion author workspace does not match deletion".to_string());
    }
    Ok(())
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content message deletion fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod row_tests {
    use super::*;
    use crate::core::intents::Value;
    use crate::protocol::content::message_deletion::queries::MessageDeletionRow;

    const MESSAGE_DELETION_COLUMNS: &[&str] = read_models::MESSAGE_DELETIONS.columns;

    #[test]
    fn message_deletion_row_round_trips() {
        let input = MessageDeletionRow {
            workspace_id: [1; 32],
            target_message_id: [2; 32],
            deletion_id: [3; 32],
            created_at_ms: 7_777,
            author_user_id: [4; 32],
        };
        let row = message_deletion_row(input);
        assert_eq!(row.table, super::super::MESSAGE_DELETION_ROWS);
        assert_eq!(row.columns, MESSAGE_DELETION_COLUMNS);
        assert_eq!(row.values[0], Value::Bytes(vec![1; 32]));
        assert_eq!(row.values[1], Value::Bytes(vec![2; 32]));
        assert_eq!(row.values[2], Value::Bytes(vec![3; 32]));
        assert_eq!(row.values[3], Value::U64(7_777));
        assert_eq!(row.values[4], Value::Bytes(vec![4; 32]));
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactId, FactScope};
    use topo::core::intents::RowMutation;
    use topo::core::project_fact::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::auth;
    use topo::protocol::auth::endpoint_shared::{
        encode as endpoint_shared_layout,
        fact::{EndpointRole, EndpointSharedFact},
    };
    use topo::protocol::content::message::{
        encode as message_encode,
        fact::{ContentMessageFact, MessageCiphertext},
    };
    use topo::protocol::content::message_deletion::fact::ContentMessageDeletionFact;
    use topo::protocol::content::message_deletion::project::decode;
    use topo::protocol::content::message_deletion::{encode, project, MESSAGE_DELETION_ROWS};

    use topo::protocol::auth::user::{encode as user_layout, fact::UserFact};

    const CONTENT_SIGNING_KEY: [u8; 32] = [7; 32];
    const ENDPOINT_AUTHORITY_KEY: [u8; 32] = [13; 32];
    const CONTENT_SIGNER_ID: FactId = [8; 32];

    #[test]
    fn content_message_deletion_projector_materializes_authorized_author_delete() {
        let workspace_id = [9; 32];
        let author_user_id = user_fact(workspace_id, [22; 32], "alice");
        let message_fact = message_fact(workspace_id, author_user_id.id);
        let (deletion, fact) =
            deletion_fact(workspace_id, message_fact.id, author_user_id.id, 12_345);

        let output = project::ContentMessageDeletionProjector::new()
            .project(
                &fact,
                &authorized_context(&fact, &message_fact, &author_user_id),
            )
            .expect("project deletion");

        assert_eq!(output.needs.len(), 4);
        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role, "fact_purged");
        assert_eq!(output.effects.intents.len(), 1);
        assert_eq!(
            output.effects.intents[0].kind.as_str(),
            "share_fact_with_sync"
        );
        assert_eq!(output.effects.row_mutations.len(), 1);
        let RowMutation::InsertValues(stored) = &output.effects.row_mutations[0] else {
            panic!("expected insert values mutation");
        };
        assert_eq!(stored.table, MESSAGE_DELETION_ROWS);
        assert_eq!(
            stored.values[0],
            topo::core::intents::Value::Bytes(deletion.workspace_id.to_vec())
        );
        assert_eq!(
            stored.values[1],
            topo::core::intents::Value::Bytes(deletion.target_message_id.to_vec())
        );
        assert_eq!(
            stored.values[2],
            topo::core::intents::Value::Bytes(fact.id.to_vec())
        );
        assert_eq!(stored.values[3], topo::core::intents::Value::U64(12_345));
        assert_eq!(
            stored.values[4],
            topo::core::intents::Value::Bytes(deletion.author_user_id.to_vec())
        );
    }

    #[test]
    fn content_message_deletion_projector_waits_for_target_and_author_context() {
        let workspace_id = [9; 32];
        let author_user_id = [22; 32];
        let (deletion, fact) = deletion_fact(workspace_id, [11; 32], author_user_id, 12_345);

        let output = project::ContentMessageDeletionProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("missing context is a need, not an unauthorized delete");

        assert!(output.effects.intents.is_empty());
        assert!(output.offers.is_empty());
        assert_eq!(output.needs.len(), 4);
        assert!(output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "signature_proof"));
        assert!(output
            .needs
            .contains(&crate::core::context::ContextNeed::range(
                fact.id,
                "content_signer",
                crate::protocol::auth::workspace::scope(deletion.workspace_id),
                CONTENT_SIGNER_ID,
                CONTENT_SIGNER_ID
            )));
        assert!(output
            .needs
            .contains(&crate::core::context::ContextNeed::range(
                fact.id,
                "content_message_meta",
                crate::protocol::auth::workspace::scope(deletion.workspace_id),
                deletion.target_message_id,
                deletion.target_message_id
            )));
        assert!(output
            .needs
            .contains(&crate::core::context::ContextNeed::range(
                fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                deletion.author_user_id,
                deletion.author_user_id
            )));
    }

    #[test]
    fn content_message_deletion_projector_waits_for_author_after_target_is_known() {
        let workspace_id = [9; 32];
        let author_user_id = [22; 32];
        let message_fact = message_fact(workspace_id, author_user_id);
        let (deletion, fact) = deletion_fact(workspace_id, message_fact.id, author_user_id, 12_345);
        let signer_fact = signer_fact(workspace_id, author_user_id);

        let output = project::ContentMessageDeletionProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signature_match(&fact),
                    signer_match(&fact, &signer_fact),
                    target_match(&fact, &message_fact),
                ]),
            )
            .expect("missing author is a need, not an unauthorized delete");

        assert!(output.effects.intents.is_empty());
        assert!(output.offers.is_empty());
        assert_eq!(output.needs.len(), 4);
        assert!(output
            .needs
            .contains(&crate::core::context::ContextNeed::range(
                fact.id,
                "content_message_meta",
                crate::protocol::auth::workspace::scope(deletion.workspace_id),
                deletion.target_message_id,
                deletion.target_message_id
            )));
        assert!(output
            .needs
            .contains(&crate::core::context::ContextNeed::range(
                fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                deletion.author_user_id,
                deletion.author_user_id
            )));
    }

    #[test]
    fn content_message_deletion_projector_rejects_non_author_delete() {
        let workspace_id = [9; 32];
        let message_author = user_fact(workspace_id, [22; 32], "alice");
        let deleter = user_fact(workspace_id, [44; 32], "mallory");
        let message_fact = message_fact(workspace_id, message_author.id);
        let (_deletion, fact) = deletion_fact(workspace_id, message_fact.id, deleter.id, 12_345);

        let err = project::ContentMessageDeletionProjector::new()
            .project(&fact, &authorized_context(&fact, &message_fact, &deleter))
            .expect_err("non-author deletion must reject");

        assert!(err.contains("not the target message author"), "{err}");
    }

    #[test]
    fn content_message_deletion_projector_rejects_author_from_other_workspace() {
        let workspace_id = [9; 32];
        let author_user_id = user_fact([8; 32], [22; 32], "alice");
        let message_fact = message_fact(workspace_id, author_user_id.id);
        let (_deletion, fact) =
            deletion_fact(workspace_id, message_fact.id, author_user_id.id, 12_345);

        let err = project::ContentMessageDeletionProjector::new()
            .project(
                &fact,
                &authorized_context(&fact, &message_fact, &author_user_id),
            )
            .expect_err("author from other workspace must reject");

        assert!(err.contains("author workspace"), "{err}");
    }

    #[test]
    fn content_message_deletion_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
        let err = project::ContentMessageDeletionProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("deletion") || err.to_lowercase().contains("length"),
            "{err}"
        );
    }

    fn deletion_fact(
        workspace_id: FactId,
        target_message_id: FactId,
        author_user_id: FactId,
        created_at_ms: u64,
    ) -> (ContentMessageDeletionFact, Fact) {
        let deletion = ContentMessageDeletionFact {
            workspace_id,
            created_at_ms,
            target_message_id,
            target_frontier_id: [3; 32],
            target_minute: 12,
            author_user_id,
            signer_id: CONTENT_SIGNER_ID,
            signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
        };
        let fact = Fact::new(
            crate::protocol::auth::workspace::scope(deletion.workspace_id),
            deletion.created_at_ms,
            encode::encode_fact(&deletion).expect("encode deletion"),
        );
        (deletion, fact)
    }

    fn message_fact(workspace_id: FactId, author_user_id: FactId) -> Fact {
        let message = ContentMessageFact {
            workspace_id,
            author_user_id,
            created_at_ms: 12_000,
            signer_id: CONTENT_SIGNER_ID,
            signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
            frontier_id: [3; 32],
            local_history_node_secret_id: [0; 32],
            expires_at_minute: u64::MAX,
            retention_policy_id: [0; 32],
            minute: 12,
            nonce: [5; crate::protocol::content::message::fact::NONCE_BYTES],
            ciphertext: MessageCiphertext::new(&vec![
                6;
                crate::protocol::content::message::fact::CIPHERTEXT_BYTES
            ])
            .expect("message ciphertext"),
        };
        Fact::new(
            crate::protocol::auth::workspace::scope(workspace_id),
            message.created_at_ms,
            message_encode::encode_fact(&message).expect("encode message"),
        )
    }

    fn signer_fact(workspace_id: FactId, author_user_id: FactId) -> Fact {
        let signer = EndpointSharedFact {
            created_at_ms: 7_000,
            workspace_id,
            user_authority_fact_id: author_user_id,
            endpoint_id: CONTENT_SIGNER_ID,
            signing_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
            endpoint_role: EndpointRole::Device,
            device_name: auth::endpoint_shared::fact::EndpointDeviceName::new("alice-device")
                .expect("device name"),
            signer_id: [1; 32],
            signer_public_key: crypto::ed25519_public_key(&ENDPOINT_AUTHORITY_KEY),
        };
        Fact::new(
            FactScope::Global,
            signer.created_at_ms,
            endpoint_shared_layout::encode_fact(&signer).expect("encode endpoint shared"),
        )
    }

    fn user_fact(workspace_id: FactId, public_key: [u8; 32], username: &str) -> Fact {
        let signing_key = [21; 32];
        let user = UserFact {
            created_at_ms: 8_000,
            workspace_id,
            public_key,
            username: auth::user::fact::Username::new(username).expect("username"),
            signer_id: [23; 32],
            signer_public_key: crypto::ed25519_public_key(&signing_key),
        };
        Fact::new(
            FactScope::Global,
            user.created_at_ms,
            user_layout::encode_fact(&user).expect("encode user"),
        )
    }

    fn authorized_context(
        deletion_fact: &Fact,
        target_fact: &Fact,
        author_fact: &Fact,
    ) -> ProjectionContext {
        let deletion = deletion_from_fact(deletion_fact);
        let signer_fact = signer_fact(deletion.workspace_id, author_fact.id);
        ProjectionContext::from_matches(vec![
            signature_match(deletion_fact),
            signer_match(deletion_fact, &signer_fact),
            target_match(deletion_fact, target_fact),
            author_match(deletion_fact, author_fact),
        ])
    }

    fn signature_match(deletion_fact: &Fact) -> MatchedContext {
        let deletion = deletion_from_fact(deletion_fact);
        let signature = auth::signature::author::create_signature(
            deletion.workspace_id,
            deletion_fact.id,
            &CONTENT_SIGNING_KEY,
            deletion.created_at_ms,
        )
        .expect("signature evidence");
        let scope = crate::protocol::auth::workspace::scope(deletion.workspace_id);
        MatchedContext {
            need: auth::signature::project::signature_proof_need(
                deletion_fact.id,
                scope.clone(),
                deletion_fact.id,
                deletion.signer_public_key,
            )
            .expect("signature need"),
            offer: auth::signature::project::signature_proof_offer(
                signature.id,
                scope,
                deletion_fact.id,
                deletion.signer_public_key,
            )
            .expect("signature offer"),
            payload: signature,
        }
    }

    fn signer_match(deletion_fact: &Fact, signer_fact: &Fact) -> MatchedContext {
        let deletion = deletion_from_fact(deletion_fact);
        let scope = crate::protocol::auth::workspace::scope(deletion.workspace_id);
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                deletion_fact.id,
                "content_signer",
                scope.clone(),
                CONTENT_SIGNER_ID,
                CONTENT_SIGNER_ID,
            ),
            offer: crate::core::context::ContextOffer::range(
                signer_fact.id,
                "content_signer",
                scope,
                CONTENT_SIGNER_ID,
                CONTENT_SIGNER_ID,
            ),
            payload: signer_fact.clone(),
        }
    }

    fn target_match(deletion_fact: &Fact, target_fact: &Fact) -> MatchedContext {
        let deletion = deletion_from_fact(deletion_fact);
        let scope = crate::protocol::auth::workspace::scope(deletion.workspace_id);
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                deletion_fact.id,
                "content_message_meta",
                scope.clone(),
                target_fact.id,
                target_fact.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                target_fact.id,
                "content_message_meta",
                scope,
                target_fact.id,
                target_fact.id,
            ),
            payload: target_fact.clone(),
        }
    }

    fn deletion_from_fact(deletion_fact: &Fact) -> ContentMessageDeletionFact {
        decode::decode_fact(&deletion_fact.bytes).expect("decode deletion")
    }

    fn author_match(deletion_fact: &Fact, author_fact: &Fact) -> MatchedContext {
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                deletion_fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                author_fact.id,
                author_fact.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                author_fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                author_fact.id,
                author_fact.id,
            ),
            payload: author_fact.clone(),
        }
    }
}
