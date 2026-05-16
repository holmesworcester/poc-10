use topo::core::crypto;
use topo::core::facts::{Fact, FactId, FactScope};
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::protocol::facts::content;
use topo::protocol::facts::identity;

const WORKSPACE: FactId = [7; 32];
const CONTENT_SIGNING_KEY: [u8; 32] = [9; 32];
const ENDPOINT_AUTHORITY_KEY: [u8; 32] = [11; 32];

#[test]
fn signed_content_event_waits_for_endpoint_shared_signer_context() {
    let signer = endpoint_shared_fact(WORKSPACE, [22; 32], CONTENT_SIGNING_KEY);
    let event = content::event::fact::ContentEventFact {
        workspace_id: WORKSPACE,
        timestamp: 12,
        payload: b"hello".to_vec(),
    };
    let fact = signed_fact_in_workspace(
        signer.id,
        CONTENT_SIGNING_KEY,
        content::event::layout::encode_fact(&event).expect("encode event"),
        event.timestamp,
    );

    let output = content::event::project::ContentEventProjector::new()
        .project(&fact, &ProjectionContext::default())
        .expect("missing signer waits");

    assert!(output.intents.is_empty());
    assert!(output.offers.is_empty());
    assert!(output.needs.contains(&topo::protocol::matchers::exact_need(
        fact.id,
        topo::protocol::matchers::endpoint_shared_role(),
        signer.id
    )));
}

#[test]
fn signed_content_event_rejects_signer_public_key_mismatch() {
    let signer = endpoint_shared_fact(WORKSPACE, [22; 32], [10; 32]);
    let event = content::event::fact::ContentEventFact {
        workspace_id: WORKSPACE,
        timestamp: 12,
        payload: b"hello".to_vec(),
    };
    let fact = signed_fact_in_workspace(
        signer.id,
        CONTENT_SIGNING_KEY,
        content::event::layout::encode_fact(&event).expect("encode event"),
        event.timestamp,
    );

    let err = content::event::project::ContentEventProjector::new()
        .project(
            &fact,
            &ProjectionContext::from_matches(vec![signer_match(&fact, &signer)]),
        )
        .expect_err("wrong signer key must fail");

    assert!(err.contains("public key does not match"), "{err}");
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
        frontier_id: [3; 32],
        minute: 1,
        leaf_id: [4; 32],
        sealed_body_ref: [5; 32],
    };
    let fact = signed_fact_in_workspace(
        signer.id,
        CONTENT_SIGNING_KEY,
        content::message::layout::encode_fact(&message).expect("encode message"),
        message.created_at_ms,
    );

    let err = content::message::project::ContentMessageProjector::new()
        .project(
            &fact,
            &ProjectionContext::from_matches(vec![signer_match(&fact, &signer)]),
        )
        .expect_err("signer for another author must fail");

    assert!(err.contains("not authorized by the named author"), "{err}");
}

#[test]
fn signed_content_file_waits_for_signer_before_parent_or_author_intents() {
    let author = user_fact(WORKSPACE, [31; 32], "alice");
    let signer = endpoint_shared_fact(WORKSPACE, author.id, CONTENT_SIGNING_KEY);
    let file = content::file::fact::ContentFileFact {
        workspace_id: WORKSPACE,
        created_at_ms: 70_000,
        message_id: [55; 32],
        author_user_id: author.id,
        file_id: [33; 32],
        blob_bytes: 1_024,
        total_slices: 1,
        slice_bytes: 1_024,
        root_hash: [44; content::file::fact::FILE_ROOT_HASH_BYTES],
        sealed_metadata: b"sealed".to_vec(),
    };
    let fact = signed_fact_in_workspace(
        signer.id,
        CONTENT_SIGNING_KEY,
        content::file::layout::encode_fact(&file).expect("encode file"),
        file.created_at_ms,
    );

    let output = content::file::project::ContentFileProjector::new()
        .project(&fact, &ProjectionContext::default())
        .expect("missing context waits");

    assert!(output.intents.is_empty());
    assert!(output.offers.is_empty());
    assert!(output.needs.contains(&topo::protocol::matchers::exact_need(
        fact.id,
        topo::protocol::matchers::endpoint_shared_role(),
        signer.id
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
        file_id: [33; 32],
        blob_bytes: 1_024,
        total_slices: 1,
        slice_bytes: 1_024,
        root_hash: [44; content::file::fact::FILE_ROOT_HASH_BYTES],
        sealed_metadata: b"sealed".to_vec(),
    };
    let fact = signed_fact_in_workspace(
        signer.id,
        CONTENT_SIGNING_KEY,
        content::file::layout::encode_fact(&file).expect("encode file"),
        file.created_at_ms,
    );

    let err = content::file::project::ContentFileProjector::new()
        .project(
            &fact,
            &ProjectionContext::from_matches(vec![signer_match(&fact, &signer)]),
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
        nonce: [6; content::reaction::fact::REACTION_NONCE_BYTES],
        ciphertext: b"sealed-reaction".to_vec(),
    };
    let fact = signed_fact_in_workspace(
        signer.id,
        CONTENT_SIGNING_KEY,
        content::reaction::layout::encode_fact(&reaction).expect("encode reaction"),
        reaction.created_at_ms,
    );

    let err = content::reaction::project::ContentReactionProjector::new()
        .project(
            &fact,
            &ProjectionContext::from_matches(vec![signer_match(&fact, &signer)]),
        )
        .expect_err("signer for another author must fail");

    assert!(err.contains("not authorized by the named author"), "{err}");
}

#[test]
fn signed_message_deletion_does_not_offer_until_signer_is_validated() {
    let author = user_fact(WORKSPACE, [31; 32], "alice");
    let signer = endpoint_shared_fact(WORKSPACE, author.id, CONTENT_SIGNING_KEY);
    let target = message_fact(WORKSPACE, author.id);
    let deletion = content::message_deletion::fact::ContentMessageDeletionFact {
        workspace_id: WORKSPACE,
        created_at_ms: 90_000,
        target_message_id: target.id,
        author_user_id: author.id,
    };
    let fact = signed_fact_in_workspace(
        signer.id,
        CONTENT_SIGNING_KEY,
        content::message_deletion::layout::encode_fact(&deletion).expect("encode deletion"),
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

    assert!(output.intents.is_empty());
    assert!(output.offers.is_empty());
    assert!(output.needs.contains(&topo::protocol::matchers::exact_need(
        fact.id,
        topo::protocol::matchers::endpoint_shared_role(),
        signer.id
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
    };
    let fact = signed_fact_in_workspace(
        signer.id,
        CONTENT_SIGNING_KEY,
        content::file_deletion::layout::encode_fact(&deletion).expect("encode deletion"),
        deletion.created_at_ms,
    );

    let err = content::file_deletion::project::ContentFileDeletionProjector::new()
        .project(
            &fact,
            &ProjectionContext::from_matches(vec![signer_match(&fact, &signer)]),
        )
        .expect_err("signer for another author must fail");

    assert!(err.contains("not authorized by the named author"), "{err}");
}

fn endpoint_shared_fact(
    workspace_id: FactId,
    user_authority_fact_id: FactId,
    content_signing_key: [u8; 32],
) -> Fact {
    let endpoint = identity::endpoint_shared::fact::EndpointSharedFact {
        created_at_ms: 1,
        workspace_id,
        user_authority_fact_id,
        endpoint_id: [21; 32],
        signing_public_key: crypto::ed25519_public_key(&content_signing_key),
        endpoint_role: identity::endpoint_shared::fact::EndpointRole::Device,
        device_name: "laptop".to_string(),
    };
    let bytes = identity::signed_fact::create::sign_payload_bytes(
        [8; 32],
        &ENDPOINT_AUTHORITY_KEY,
        identity::endpoint_shared::layout::encode_fact(&endpoint).expect("encode endpoint_shared"),
    )
    .expect("sign endpoint_shared");
    Fact::new(FactScope::Global, endpoint.created_at_ms, bytes)
}

fn user_fact(workspace_id: FactId, public_key: [u8; 32], username: &str) -> Fact {
    let user = identity::user::fact::UserFact {
        created_at_ms: 2,
        workspace_id,
        public_key,
        username: username.to_string(),
    };
    Fact::new(
        FactScope::Global,
        user.created_at_ms,
        identity::user::layout::encode_fact(&user).expect("encode user"),
    )
}

fn message_fact(workspace_id: FactId, author_user_id: FactId) -> Fact {
    let message = content::message::fact::ContentMessageFact {
        workspace_id,
        author_user_id,
        created_at_ms: 60_000,
        frontier_id: [3; 32],
        minute: 1,
        leaf_id: [4; 32],
        sealed_body_ref: [5; 32],
    };
    Fact::new(
        topo::protocol::matchers::workspace_scope(workspace_id),
        message.created_at_ms,
        content::message::layout::encode_fact(&message).expect("encode message"),
    )
}

fn file_fact(workspace_id: FactId, author_user_id: FactId) -> Fact {
    let file = content::file::fact::ContentFileFact {
        workspace_id,
        created_at_ms: 70_000,
        message_id: [55; 32],
        author_user_id,
        file_id: [33; 32],
        blob_bytes: 1_024,
        total_slices: 1,
        slice_bytes: 1_024,
        root_hash: [44; content::file::fact::FILE_ROOT_HASH_BYTES],
        sealed_metadata: b"sealed".to_vec(),
    };
    Fact::new(
        topo::protocol::matchers::workspace_scope(workspace_id),
        file.created_at_ms,
        content::file::layout::encode_fact(&file).expect("encode file"),
    )
}

fn signed_fact_in_workspace(
    signer_id: FactId,
    private_key: [u8; 32],
    payload: Vec<u8>,
    timestamp: u64,
) -> Fact {
    Fact::new(
        topo::protocol::matchers::workspace_scope(WORKSPACE),
        timestamp,
        identity::signed_fact::create::sign_payload_bytes(signer_id, &private_key, payload)
            .expect("sign content fact"),
    )
}

fn signer_match(owner: &Fact, signer: &Fact) -> MatchedContext {
    MatchedContext {
        need: topo::protocol::matchers::exact_need(
            owner.id,
            topo::protocol::matchers::endpoint_shared_role(),
            signer.id,
        ),
        offer: topo::protocol::matchers::exact_offer(
            signer.id,
            topo::protocol::matchers::endpoint_shared_role(),
        ),
        payload: signer.clone(),
    }
}

fn author_match(owner: &Fact, author: &Fact) -> MatchedContext {
    MatchedContext {
        need: topo::protocol::matchers::exact_need(
            owner.id,
            topo::protocol::matchers::user_role(),
            author.id,
        ),
        offer: topo::protocol::matchers::exact_offer(
            author.id,
            topo::protocol::matchers::user_role(),
        ),
        payload: author.clone(),
    }
}

fn message_match(owner: &Fact, message: &Fact) -> MatchedContext {
    MatchedContext {
        need: topo::protocol::matchers::message_need(
            owner.id,
            topo::protocol::matchers::workspace_scope(WORKSPACE),
            message.id,
        ),
        offer: topo::protocol::matchers::message_offer(
            message.id,
            topo::protocol::matchers::workspace_scope(WORKSPACE),
            message.id,
        ),
        payload: message.clone(),
    }
}

#[allow(dead_code)]
fn file_event_match(owner: &Fact, file: &Fact) -> MatchedContext {
    MatchedContext {
        need: topo::protocol::matchers::exact_fact_need(owner.id, file.scope.clone(), file.id),
        offer: topo::protocol::matchers::exact_fact_offer(
            file.id,
            file.scope.clone(),
            file.id,
            file.id,
        ),
        payload: file.clone(),
    }
}
