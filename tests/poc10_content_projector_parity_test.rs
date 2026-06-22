use topo::core::crypto;
use topo::core::facts::{Fact, FactId, FactScope};
use topo::core::project_fact::{MatchedContext, ProjectionContext, Projector};
use topo::protocol::auth;
use topo::protocol::content;

const WORKSPACE: FactId = [7; 32];
const CONTENT_SIGNING_KEY: [u8; 32] = [9; 32];
const ENDPOINT_AUTHORITY_KEY: [u8; 32] = [11; 32];
const CONTENT_ENDPOINT_ID: FactId = [21; 32];

#[test]
fn content_facts_without_signature_evidence_wait() {
    let message = message_fact_without_signature_evidence(WORKSPACE, [31; 32]);
    let output = content::message::project::ContentMessageProjector::new()
        .project(&message, &ProjectionContext::default())
        .expect("message without signature evidence parks");
    assert!(output.offers.is_empty());
    assert!(output
        .needs
        .iter()
        .any(|need| need.role == "signature_proof"));

    let file = file_fact_without_signature_evidence(WORKSPACE, [31; 32]);
    assert_waits_for_signature(
        content::file::project::ContentFileProjector::new()
            .project(&file, &ProjectionContext::default())
            .expect("raw file parks on signature evidence"),
    );

    let reaction = content::reaction::fact::ContentReactionFact {
        workspace_id: WORKSPACE,
        created_at_ms: 80_000,
        target_message_id: [55; 32],
        author_user_id: [31; 32],
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
        nonce: [6; content::reaction::fact::REACTION_NONCE_BYTES],
        ciphertext: content::reaction::fact::ReactionCiphertext::new(b"sealed-reaction")
            .expect("reaction ciphertext"),
    };
    let reaction = Fact::new(
        topo::protocol::auth::workspace::scope(WORKSPACE),
        reaction.created_at_ms,
        content::reaction::encode::encode_fact(&reaction).expect("encode reaction"),
    );
    assert_waits_for_signature(
        content::reaction::project::ContentReactionProjector::new()
            .project(&reaction, &ProjectionContext::default())
            .expect("raw reaction parks on signature evidence"),
    );

    let deletion = content::message_deletion::fact::ContentMessageDeletionFact {
        workspace_id: WORKSPACE,
        created_at_ms: 90_000,
        target_message_id: [55; 32],
        target_frontier_id: [3; 32],
        target_minute: 1,
        author_user_id: [31; 32],
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
    };
    let deletion = Fact::new(
        topo::protocol::auth::workspace::scope(WORKSPACE),
        deletion.created_at_ms,
        content::message_deletion::encode::encode_fact(&deletion).expect("encode deletion"),
    );
    assert_waits_for_signature(
        content::message_deletion::project::ContentMessageDeletionProjector::new()
            .project(&deletion, &ProjectionContext::default())
            .expect("raw message deletion parks on signature evidence"),
    );

    let deletion = content::file_deletion::fact::ContentFileDeletionFact {
        workspace_id: WORKSPACE,
        created_at_ms: 100_000,
        target_file_id: [33; 32],
        author_user_id: [31; 32],
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
    };
    let deletion = Fact::new(
        topo::protocol::auth::workspace::scope(WORKSPACE),
        deletion.created_at_ms,
        content::file_deletion::encode::encode_fact(&deletion).expect("encode file deletion"),
    );
    assert_waits_for_signature(
        content::file_deletion::project::ContentFileDeletionProjector::new()
            .project(&deletion, &ProjectionContext::default())
            .expect("raw file deletion parks on signature evidence"),
    );
}

#[test]
fn signed_content_message_rejects_signer_not_authorized_by_author() {
    let author = user_fact(WORKSPACE, [31; 32], "alice");
    let wrong_author = user_fact(WORKSPACE, [32; 32], "mallory");
    let signer = endpoint_shared_fact(WORKSPACE, wrong_author.id, CONTENT_SIGNING_KEY);
    let message = content::message::fact::ContentMessageFact {
        workspace_id: WORKSPACE,
        author_user_id: author.id,
        created_at_ms: 60_000,
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
        frontier_id: [3; 32],
        local_history_node_secret_id: [0; 32],
        expires_at_minute: u64::MAX,
        retention_policy_id: [0; 32],
        minute: 1,
        nonce: [5; content::message::fact::NONCE_BYTES],
        ciphertext: content::message::fact::MessageCiphertext::new(&vec![
            6;
            content::message::fact::CIPHERTEXT_BYTES
        ])
        .expect("message ciphertext"),
    };
    let fact = content_fact_with_signer_key(
        CONTENT_ENDPOINT_ID,
        CONTENT_SIGNING_KEY,
        content::message::encode::encode_fact(&message).expect("encode message"),
        message.created_at_ms,
    );
    let signature = signature_fact(&fact, message.created_at_ms);

    let err = content::message::project::ContentMessageProjector::new()
        .project(
            &fact,
            &ProjectionContext::from_matches(vec![
                message_signature_match(&fact, &message, &signature),
                message_signer_match(&fact, &message, &signer),
            ]),
        )
        .expect_err("signer for another author must fail");

    assert!(err.contains("not authorized by the named author"), "{err}");
}

#[test]
fn signed_content_file_waits_for_signer_before_parent_or_author_intents() {
    let author = user_fact(WORKSPACE, [31; 32], "alice");
    let file = content::file::fact::ContentFileFact {
        workspace_id: WORKSPACE,
        created_at_ms: 70_000,
        message_id: [55; 32],
        author_user_id: author.id,
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
        file_id: [33; 32],
        blob_bytes: 1_024,
        total_slices: 1,
        slice_bytes: content::file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES as u32,
        root_hash: [44; content::file::fact::FILE_ROOT_HASH_BYTES],
        sealed_metadata: content::file::fact::SealedMetadata::new(b"sealed")
            .expect("sealed metadata"),
    };
    let fact = content_fact_with_signer_key(
        CONTENT_ENDPOINT_ID,
        CONTENT_SIGNING_KEY,
        content::file::encode::encode_fact(&file).expect("encode file"),
        file.created_at_ms,
    );

    let output = content::file::project::ContentFileProjector::new()
        .project(&fact, &ProjectionContext::default())
        .expect("missing context waits");

    assert!(output.effects.intents.is_empty());
    assert!(output.offers.is_empty());
    assert!(output
        .needs
        .contains(&topo::core::context::ContextNeed::range(
            fact.id,
            "content_signer",
            topo::protocol::auth::workspace::scope(WORKSPACE),
            CONTENT_ENDPOINT_ID,
            CONTENT_ENDPOINT_ID
        )));
}

#[test]
fn signed_content_file_rejects_signer_not_authorized_by_author() {
    let author = user_fact(WORKSPACE, [31; 32], "alice");
    let wrong_author = user_fact(WORKSPACE, [32; 32], "mallory");
    let signer = endpoint_shared_fact(WORKSPACE, wrong_author.id, CONTENT_SIGNING_KEY);
    let file = content::file::fact::ContentFileFact {
        workspace_id: WORKSPACE,
        created_at_ms: 70_000,
        message_id: [55; 32],
        author_user_id: author.id,
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
        file_id: [33; 32],
        blob_bytes: 1_024,
        total_slices: 1,
        slice_bytes: content::file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES as u32,
        root_hash: [44; content::file::fact::FILE_ROOT_HASH_BYTES],
        sealed_metadata: content::file::fact::SealedMetadata::new(b"sealed")
            .expect("sealed metadata"),
    };
    let fact = content_fact_with_signer_key(
        CONTENT_ENDPOINT_ID,
        CONTENT_SIGNING_KEY,
        content::file::encode::encode_fact(&file).expect("encode file"),
        file.created_at_ms,
    );

    let err = content::file::project::ContentFileProjector::new()
        .project(
            &fact,
            &ProjectionContext::from_matches(vec![
                signature_match(&fact),
                signer_match(&fact, &signer),
            ]),
        )
        .expect_err("signer for another author must fail");

    assert!(err.contains("not authorized by the named author"), "{err}");
}

#[test]
fn signed_content_reaction_rejects_signer_not_authorized_by_author() {
    let target_author = user_fact(WORKSPACE, [30; 32], "bob");
    let reaction_author = user_fact(WORKSPACE, [31; 32], "alice");
    let wrong_author = user_fact(WORKSPACE, [32; 32], "mallory");
    let target = message_fact(WORKSPACE, target_author.id);
    let signer = endpoint_shared_fact(WORKSPACE, wrong_author.id, CONTENT_SIGNING_KEY);
    let reaction = content::reaction::fact::ContentReactionFact {
        workspace_id: WORKSPACE,
        created_at_ms: 80_000,
        target_message_id: target.id,
        author_user_id: reaction_author.id,
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
        nonce: [6; content::reaction::fact::REACTION_NONCE_BYTES],
        ciphertext: content::reaction::fact::ReactionCiphertext::new(b"sealed-reaction")
            .expect("reaction ciphertext"),
    };
    let fact = content_fact_with_signer_key(
        CONTENT_ENDPOINT_ID,
        CONTENT_SIGNING_KEY,
        content::reaction::encode::encode_fact(&reaction).expect("encode reaction"),
        reaction.created_at_ms,
    );

    let err = content::reaction::project::ContentReactionProjector::new()
        .project(
            &fact,
            &ProjectionContext::from_matches(vec![
                signature_match(&fact),
                signer_match(&fact, &signer),
            ]),
        )
        .expect_err("signer for another author must fail");

    assert!(err.contains("not authorized by the named author"), "{err}");
}

#[test]
fn signed_message_deletion_does_not_offer_until_signer_is_validated() {
    let author = user_fact(WORKSPACE, [31; 32], "alice");
    let target = message_fact(WORKSPACE, author.id);
    let deletion = content::message_deletion::fact::ContentMessageDeletionFact {
        workspace_id: WORKSPACE,
        created_at_ms: 90_000,
        target_message_id: target.id,
        target_frontier_id: [3; 32],
        target_minute: 1,
        author_user_id: author.id,
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
    };
    let fact = content_fact_with_signer_key(
        CONTENT_ENDPOINT_ID,
        CONTENT_SIGNING_KEY,
        content::message_deletion::encode::encode_fact(&deletion).expect("encode deletion"),
        deletion.created_at_ms,
    );

    let output = content::message_deletion::project::ContentMessageDeletionProjector::new()
        .project(
            &fact,
            &ProjectionContext::from_matches(vec![
                message_match(&fact, &target),
                author_match(&fact, &author),
            ]),
        )
        .expect("missing signer waits");

    assert!(output.effects.intents.is_empty());
    assert!(output.offers.is_empty());
    assert!(output
        .needs
        .contains(&topo::core::context::ContextNeed::range(
            fact.id,
            "content_signer",
            topo::protocol::auth::workspace::scope(WORKSPACE),
            CONTENT_ENDPOINT_ID,
            CONTENT_ENDPOINT_ID
        )));
}

#[test]
fn signed_file_deletion_rejects_signer_not_authorized_by_author() {
    let file_author = user_fact(WORKSPACE, [31; 32], "alice");
    let deleter = user_fact(WORKSPACE, [32; 32], "mallory");
    let target = file_fact(WORKSPACE, file_author.id);
    let signer = endpoint_shared_fact(WORKSPACE, file_author.id, CONTENT_SIGNING_KEY);
    let deletion = content::file_deletion::fact::ContentFileDeletionFact {
        workspace_id: WORKSPACE,
        created_at_ms: 100_000,
        target_file_id: target.id,
        author_user_id: deleter.id,
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
    };
    let fact = content_fact_with_signer_key(
        CONTENT_ENDPOINT_ID,
        CONTENT_SIGNING_KEY,
        content::file_deletion::encode::encode_fact(&deletion).expect("encode deletion"),
        deletion.created_at_ms,
    );

    let err = content::file_deletion::project::ContentFileDeletionProjector::new()
        .project(
            &fact,
            &ProjectionContext::from_matches(vec![
                signature_match(&fact),
                signer_match(&fact, &signer),
            ]),
        )
        .expect_err("signer for another author must fail");

    assert!(err.contains("not authorized by the named author"), "{err}");
}

fn endpoint_shared_fact(
    workspace_id: FactId,
    user_authority_fact_id: FactId,
    content_signing_key: [u8; 32],
) -> Fact {
    let endpoint = auth::endpoint_shared::fact::EndpointSharedFact {
        created_at_ms: 1,
        workspace_id,
        user_authority_fact_id,
        endpoint_id: CONTENT_ENDPOINT_ID,
        signing_public_key: crypto::ed25519_public_key(&content_signing_key),
        endpoint_role: auth::endpoint_shared::fact::EndpointRole::Device,
        device_name: auth::endpoint_shared::fact::EndpointDeviceName::new("laptop")
            .expect("device name"),
        signer_id: [8; 32],
        signer_public_key: crypto::ed25519_public_key(&ENDPOINT_AUTHORITY_KEY),
    };
    let bytes = auth::endpoint_shared::encode::encode_fact(&endpoint).expect("endpoint_shared");
    Fact::new(FactScope::Global, endpoint.created_at_ms, bytes)
}

fn user_fact(workspace_id: FactId, public_key: [u8; 32], username: &str) -> Fact {
    let user_private = [12; 32];
    let user = auth::user::fact::UserFact {
        created_at_ms: 2,
        workspace_id,
        public_key,
        username: auth::user::fact::Username::new(username).expect("username"),
        signer_id: [13; 32],
        signer_public_key: crypto::ed25519_public_key(&user_private),
    };
    Fact::new(
        FactScope::Global,
        user.created_at_ms,
        auth::user::encode::encode_fact(&user).expect("encode user"),
    )
}

fn message_fact(workspace_id: FactId, author_user_id: FactId) -> Fact {
    let message = content::message::fact::ContentMessageFact {
        workspace_id,
        author_user_id,
        created_at_ms: 60_000,
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
        frontier_id: [3; 32],
        local_history_node_secret_id: [0; 32],
        expires_at_minute: u64::MAX,
        retention_policy_id: [0; 32],
        minute: 1,
        nonce: [5; content::message::fact::NONCE_BYTES],
        ciphertext: content::message::fact::MessageCiphertext::new(&vec![
            6;
            content::message::fact::CIPHERTEXT_BYTES
        ])
        .expect("message ciphertext"),
    };
    Fact::new(
        topo::protocol::auth::workspace::scope(workspace_id),
        message.created_at_ms,
        content::message::encode::encode_fact(&message).expect("encode message"),
    )
}

fn message_fact_without_signature_evidence(workspace_id: FactId, author_user_id: FactId) -> Fact {
    let message = content::message::fact::ContentMessageFact {
        workspace_id,
        author_user_id,
        created_at_ms: 60_000,
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
        frontier_id: [3; 32],
        local_history_node_secret_id: [0; 32],
        expires_at_minute: u64::MAX,
        retention_policy_id: [0; 32],
        minute: 1,
        nonce: [5; content::message::fact::NONCE_BYTES],
        ciphertext: content::message::fact::MessageCiphertext::new(&vec![
            6;
            content::message::fact::CIPHERTEXT_BYTES
        ])
        .expect("message ciphertext"),
    };
    Fact::new(
        topo::protocol::auth::workspace::scope(workspace_id),
        message.created_at_ms,
        content::message::encode::encode_fact(&message).expect("encode message"),
    )
}

fn file_fact(workspace_id: FactId, author_user_id: FactId) -> Fact {
    let file = content::file::fact::ContentFileFact {
        workspace_id,
        created_at_ms: 70_000,
        message_id: [55; 32],
        author_user_id,
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
        file_id: [33; 32],
        blob_bytes: 1_024,
        total_slices: 1,
        slice_bytes: content::file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES as u32,
        root_hash: [44; content::file::fact::FILE_ROOT_HASH_BYTES],
        sealed_metadata: content::file::fact::SealedMetadata::new(b"sealed")
            .expect("sealed metadata"),
    };
    Fact::new(
        topo::protocol::auth::workspace::scope(workspace_id),
        file.created_at_ms,
        content::file::encode::encode_fact(&file).expect("encode file"),
    )
}

fn file_fact_without_signature_evidence(workspace_id: FactId, author_user_id: FactId) -> Fact {
    let file = content::file::fact::ContentFileFact {
        workspace_id,
        created_at_ms: 70_000,
        message_id: [55; 32],
        author_user_id,
        signer_id: CONTENT_ENDPOINT_ID,
        signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
        file_id: [33; 32],
        blob_bytes: 1_024,
        total_slices: 1,
        slice_bytes: content::file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES as u32,
        root_hash: [44; content::file::fact::FILE_ROOT_HASH_BYTES],
        sealed_metadata: content::file::fact::SealedMetadata::new(b"sealed")
            .expect("sealed metadata"),
    };
    Fact::new(
        topo::protocol::auth::workspace::scope(workspace_id),
        file.created_at_ms,
        content::file::encode::encode_fact(&file).expect("encode file"),
    )
}

fn content_fact_with_signer_key(
    _signer_id: FactId,
    private_key: [u8; 32],
    payload: Vec<u8>,
    timestamp: u64,
) -> Fact {
    let signed = sign_payload(private_key, payload).expect("attach signer key");
    Fact::new(
        topo::protocol::auth::workspace::scope(WORKSPACE),
        timestamp,
        signed,
    )
}

fn sign_payload(private_key: [u8; 32], payload: Vec<u8>) -> Result<Vec<u8>, String> {
    match payload.first().copied() {
        Some(content::message::TYPE_CONTENT_MESSAGE) => {
            let mut fact = content::message::project::decode::decode_fact(&payload)?;
            fact.signer_public_key = crypto::ed25519_public_key(&private_key);
            content::message::encode::encode_fact(&fact)
        }
        Some(content::file::TYPE_CONTENT_FILE) => {
            let mut fact = content::file::project::decode::decode_fact(&payload)?;
            fact.signer_public_key = crypto::ed25519_public_key(&private_key);
            content::file::encode::encode_fact(&fact)
        }
        Some(content::reaction::TYPE_CONTENT_REACTION) => {
            let mut fact = content::reaction::project::decode::decode_fact(&payload)?;
            fact.signer_public_key = crypto::ed25519_public_key(&private_key);
            content::reaction::encode::encode_fact(&fact)
        }
        Some(content::message_deletion::TYPE_CONTENT_MESSAGE_DELETION) => {
            let mut fact = content::message_deletion::project::decode::decode_fact(&payload)?;
            fact.signer_public_key = crypto::ed25519_public_key(&private_key);
            content::message_deletion::encode::encode_fact(&fact)
        }
        Some(content::file_deletion::TYPE_CONTENT_FILE_DELETION) => {
            let mut fact = content::file_deletion::project::decode::decode_fact(&payload)?;
            fact.signer_public_key = crypto::ed25519_public_key(&private_key);
            content::file_deletion::encode::encode_fact(&fact)
        }
        _ => Err("unsupported test payload type".to_string()),
    }
}

fn assert_waits_for_signature(output: topo::core::project_fact::ProjectionOutput) {
    assert!(output.offers.is_empty());
    assert!(output.effects.intents.is_empty());
    assert!(output
        .needs
        .iter()
        .any(|need| need.role.as_str() == "signature_proof"));
}

fn signature_match(fact: &Fact) -> MatchedContext {
    let scope = topo::protocol::auth::workspace::scope(WORKSPACE);
    let signer_public_key = crypto::ed25519_public_key(&CONTENT_SIGNING_KEY);
    let signature = auth::signature::author::create_signature(
        WORKSPACE,
        fact.id,
        &CONTENT_SIGNING_KEY,
        fact.timestamp,
    )
    .expect("signature evidence");
    MatchedContext::new(
        auth::signature::project::signature_proof_need(
            fact.id,
            scope.clone(),
            fact.id,
            signer_public_key,
        )
        .expect("signature need"),
        auth::signature::project::signature_proof_offer(
            signature.id,
            scope,
            fact.id,
            signer_public_key,
        )
        .expect("signature offer"),
        signature,
    )
    .expect("matched signature context")
}

fn signer_match(owner: &Fact, signer: &Fact) -> MatchedContext {
    MatchedContext::new(
        topo::core::context::ContextNeed::range(
            owner.id,
            "content_signer",
            topo::protocol::auth::workspace::scope(WORKSPACE),
            CONTENT_ENDPOINT_ID,
            CONTENT_ENDPOINT_ID,
        ),
        topo::core::context::ContextOffer::range(
            signer.id,
            "content_signer",
            topo::protocol::auth::workspace::scope(WORKSPACE),
            CONTENT_ENDPOINT_ID,
            CONTENT_ENDPOINT_ID,
        ),
        signer.clone(),
    )
    .expect("matched signer context")
}

fn message_signer_match(
    owner: &Fact,
    message: &content::message::fact::ContentMessageFact,
    signer: &Fact,
) -> MatchedContext {
    MatchedContext::new(
        topo::core::context::ContextNeed::range(
            owner.id,
            "content_signer",
            topo::protocol::auth::workspace::scope(message.workspace_id),
            message.signer_id,
            message.signer_id,
        ),
        topo::core::context::ContextOffer::range(
            signer.id,
            "content_signer",
            topo::protocol::auth::workspace::scope(message.workspace_id),
            message.signer_id,
            message.signer_id,
        ),
        signer.clone(),
    )
    .expect("matched message signer context")
}

fn signature_fact(target: &Fact, created_at_ms: u64) -> Fact {
    auth::signature::author::create_signature(
        WORKSPACE,
        target.id,
        &CONTENT_SIGNING_KEY,
        created_at_ms,
    )
    .expect("signature fact")
}

fn message_signature_match(
    owner: &Fact,
    message: &content::message::fact::ContentMessageFact,
    signature: &Fact,
) -> MatchedContext {
    let scope = topo::protocol::auth::workspace::scope(message.workspace_id);
    MatchedContext::new(
        auth::signature::project::signature_proof_need(
            owner.id,
            scope.clone(),
            owner.id,
            message.signer_public_key,
        )
        .expect("signature need"),
        auth::signature::project::signature_proof_offer(
            signature.id,
            scope,
            owner.id,
            message.signer_public_key,
        )
        .expect("signature offer"),
        signature.clone(),
    )
    .expect("matched message signature context")
}

fn author_match(owner: &Fact, author: &Fact) -> MatchedContext {
    MatchedContext::new(
        topo::core::context::ContextNeed::range(
            owner.id,
            "auth_user",
            topo::core::facts::FactScope::Global,
            author.id,
            author.id,
        ),
        topo::core::context::ContextOffer::range(
            author.id,
            "auth_user",
            topo::core::facts::FactScope::Global,
            author.id,
            author.id,
        ),
        author.clone(),
    )
    .expect("matched author context")
}

fn message_match(owner: &Fact, message: &Fact) -> MatchedContext {
    MatchedContext::new(
        topo::core::context::ContextNeed::range(
            owner.id,
            "content_message",
            topo::protocol::auth::workspace::scope(WORKSPACE),
            message.id,
            message.id,
        ),
        topo::core::context::ContextOffer::range(
            message.id,
            "content_message",
            topo::protocol::auth::workspace::scope(WORKSPACE),
            message.id,
            message.id,
        ),
        message.clone(),
    )
    .expect("matched message context")
}

#[allow(dead_code)]
fn file_fact_match(owner: &Fact, file: &Fact) -> MatchedContext {
    MatchedContext::new(
        topo::core::context::ContextNeed::range(
            owner.id,
            "sync_exact_fact",
            file.scope.clone(),
            file.id,
            file.id,
        ),
        topo::core::context::ContextOffer::range(
            file.id,
            "sync_exact_fact",
            file.scope.clone(),
            file.id,
            file.id,
        ),
        file.clone(),
    )
    .expect("matched file context")
}
