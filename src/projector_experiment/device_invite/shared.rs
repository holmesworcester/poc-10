//! Exhaustive invariants for the device_invite projector.
//!
//! Each invariant is a free function generic over `P: Projector`. A variant
//! plugs into the battery via `run_all_invariants(&projector)`.
//!
//! Style-agnostic: assertions touch only observable behavior (output needs,
//! offers, intents, error strings).

#![cfg(test)]

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{MatchedContext, ProjectionContext, Projector};
use crate::event_modules::identity_device_invite::{fact::DeviceInviteFact, layout, rows};
use crate::event_modules::identity_endpoint_shared::{
    fact::{EndpointRole, EndpointSharedFact},
    layout as endpoint_shared_layout,
};
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::{fact::UserFact, layout as user_layout};
use crate::event_modules::identity_user_invite::{
    fact::UserInviteFact, layout as user_invite_layout,
};
use crate::event_modules::identity_workspace::{fact::WorkspaceFact, layout as workspace_layout};
use crate::event_modules::signed_fact;

const WORKSPACE_ID: [u8; 32] = [1; 32];
const USER_INVITE_PRIVATE_KEY: [u8; 32] = [8; 32];
const USER_PRIVATE_KEY: [u8; 32] = [9; 32];
const DEVICE_INVITE_PRIVATE_KEY: [u8; 32] = [10; 32];
const ENDPOINT_SIGNER_PRIVATE_KEY: [u8; 32] = [11; 32];
const ENDPOINT_ID: [u8; 32] = [3; 32];

// --- scenario builders --------------------------------------------------------

pub struct UserSignedScenario {
    pub invite: DeviceInviteFact,
    pub fact: Fact,
    pub user_fact: Fact,
    pub user_invite_fact: Fact,
    pub workspace_fact: Fact,
}

pub fn user_signed_scenario() -> UserSignedScenario {
    let workspace_fact = workspace_fact(WORKSPACE_ID);
    let user_invite = UserInviteFact {
        created_at_ms: 1,
        public_key: crypto::ed25519_public_key(&USER_INVITE_PRIVATE_KEY),
        workspace_id: WORKSPACE_ID,
        authority_event_id: WORKSPACE_ID,
    };
    let user_invite_fact = signed_fact_with_payload(
        WORKSPACE_ID,
        USER_INVITE_PRIVATE_KEY,
        user_invite_layout::encode_fact(&user_invite).expect("encode user_invite"),
        1,
    );
    let user = UserFact {
        created_at_ms: 2,
        workspace_id: WORKSPACE_ID,
        public_key: crypto::ed25519_public_key(&USER_PRIVATE_KEY),
        username: "alice".to_string(),
    };
    let user_fact = signed_fact_with_payload(
        user_invite_fact.id,
        USER_INVITE_PRIVATE_KEY,
        user_layout::encode_fact(&user).expect("encode user"),
        2,
    );
    let invite = DeviceInviteFact {
        created_at_ms: 11,
        workspace_id: WORKSPACE_ID,
        user_authority_event_id: user_fact.id,
        user_invite_event_id: Some(user_invite_fact.id),
        public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
    };
    let fact = signed_fact_with_payload(
        user_fact.id,
        USER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode device_invite"),
        invite.created_at_ms,
    );
    UserSignedScenario {
        invite,
        fact,
        user_fact,
        user_invite_fact,
        workspace_fact,
    }
}

pub struct EndpointSignedScenario {
    pub invite: DeviceInviteFact,
    pub fact: Fact,
    pub endpoint_fact: Fact,
    pub workspace_fact: Fact,
}

pub fn endpoint_signed_scenario() -> EndpointSignedScenario {
    let workspace_fact = workspace_fact(WORKSPACE_ID);
    let user_authority_event_id = [50; 32];
    let endpoint = EndpointSharedFact {
        created_at_ms: 4,
        workspace_id: WORKSPACE_ID,
        user_authority_event_id,
        endpoint_id: ENDPOINT_ID,
        signing_public_key: crypto::ed25519_public_key(&ENDPOINT_SIGNER_PRIVATE_KEY),
        endpoint_role: EndpointRole::Device,
        device_name: "laptop".to_string(),
    };
    let endpoint_fact = signed_fact_with_payload(
        [44; 32],
        [45; 32],
        endpoint_shared_layout::encode_fact(&endpoint).expect("encode endpoint_shared"),
        4,
    );
    let invite = DeviceInviteFact {
        created_at_ms: 11,
        workspace_id: WORKSPACE_ID,
        user_authority_event_id,
        user_invite_event_id: None,
        public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
    };
    let fact = signed_fact_with_payload(
        endpoint_fact.id,
        ENDPOINT_SIGNER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode device_invite"),
        11,
    );
    EndpointSignedScenario {
        invite,
        fact,
        endpoint_fact,
        workspace_fact,
    }
}

pub fn workspace_fact(workspace_id: [u8; 32]) -> Fact {
    Fact {
        id: workspace_id,
        scope: FactScope::Global,
        timestamp: 1,
        bytes: workspace_layout::encode_fact(&WorkspaceFact {
            created_at_ms: 1,
            public_key: [7; 32],
            name: "Workspace".to_string(),
        })
        .expect("encode workspace"),
    }
}

pub fn signed_fact_with_payload(
    signer_id: [u8; 32],
    private_key: [u8; 32],
    payload: Vec<u8>,
    timestamp: u64,
) -> Fact {
    let bytes = signed_fact::create::sign_payload_bytes(signer_id, &private_key, payload)
        .expect("sign fact");
    Fact::new(FactScope::Global, timestamp, bytes)
}

// --- match builders -----------------------------------------------------------

fn workspace_match(owner: [u8; 32], workspace: Fact) -> MatchedContext {
    MatchedContext {
        need: identity_matchers::exact_need(owner, identity_matchers::workspace_role(), workspace.id),
        offer: identity_matchers::workspace_offer(workspace.id),
        payload: workspace,
    }
}

fn user_match(owner: [u8; 32], user: Fact) -> MatchedContext {
    MatchedContext {
        need: identity_matchers::exact_need(owner, identity_matchers::user_role(), user.id),
        offer: identity_matchers::exact_offer(user.id, identity_matchers::user_role()),
        payload: user,
    }
}

fn user_invite_match(owner: [u8; 32], user_invite: Fact) -> MatchedContext {
    MatchedContext {
        need: identity_matchers::exact_need(
            owner,
            identity_matchers::user_invite_role(),
            user_invite.id,
        ),
        offer: identity_matchers::user_invite_offer(user_invite.id),
        payload: user_invite,
    }
}

fn endpoint_shared_match(owner: [u8; 32], endpoint: Fact) -> MatchedContext {
    MatchedContext {
        need: identity_matchers::exact_need(
            owner,
            identity_matchers::endpoint_shared_role(),
            endpoint.id,
        ),
        offer: identity_matchers::exact_offer(endpoint.id, identity_matchers::endpoint_shared_role()),
        payload: endpoint,
    }
}

fn user_signed_full_context(s: &UserSignedScenario) -> ProjectionContext {
    ProjectionContext::from_matches(vec![
        workspace_match(s.fact.id, s.workspace_fact.clone()),
        user_match(s.fact.id, s.user_fact.clone()),
        user_invite_match(s.fact.id, s.user_invite_fact.clone()),
    ])
}

fn endpoint_signed_full_context(s: &EndpointSignedScenario) -> ProjectionContext {
    ProjectionContext::from_matches(vec![
        workspace_match(s.fact.id, s.workspace_fact.clone()),
        endpoint_shared_match(s.fact.id, s.endpoint_fact.clone()),
    ])
}

fn expect_err<P: Projector>(p: &P, fact: &Fact, ctx: &ProjectionContext, fragment: &str) {
    let err = p
        .project(fact, ctx)
        .expect_err(&format!("projector must reject; expected '{fragment}'"));
    assert!(
        err.contains(fragment),
        "expected error containing '{fragment}', got '{err}'",
    );
}

// --- structural invariants ----------------------------------------------------

pub fn rejects_local_scope<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let mut fact = s.fact.clone();
    fact.scope = FactScope::Local;
    expect_err(p, &fact, &ProjectionContext::new(Vec::new()), "global scope");
}

pub fn rejects_unsigned_fact<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let unsigned = Fact::new(
        FactScope::Global,
        11,
        layout::encode_fact(&s.invite).expect("encode"),
    );
    expect_err(p, &unsigned, &ProjectionContext::new(Vec::new()), "must be signed");
}

pub fn rejects_signed_envelope_with_wrong_inner_type<P: Projector>(p: &P) {
    // Sign a workspace payload but call it a device_invite envelope. Easiest
    // way: sign the WorkspaceFact bytes; the envelope decodes but inner_type
    // is workspace, not device_invite.
    let workspace_bytes = workspace_layout::encode_fact(&WorkspaceFact {
        created_at_ms: 1,
        public_key: [2; 32],
        name: "ws".into(),
    })
    .expect("encode workspace");
    let bytes = signed_fact::create::sign_payload_bytes(
        WORKSPACE_ID,
        &USER_PRIVATE_KEY,
        workspace_bytes,
    )
    .expect("sign workspace bytes");
    let fact = Fact::new(FactScope::Global, 1, bytes);
    expect_err(
        p,
        &fact,
        &ProjectionContext::new(Vec::new()),
        "does not contain a device_invite",
    );
}

pub fn rejects_zero_workspace_id<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let mut invite = s.invite;
    invite.workspace_id = [0; 32];
    let fact = signed_fact_with_payload(
        s.user_fact.id,
        USER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode"),
        1,
    );
    expect_err(p, &fact, &ProjectionContext::new(Vec::new()), "workspace_id");
}

pub fn rejects_zero_user_authority<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let mut invite = s.invite;
    invite.user_authority_event_id = [0; 32];
    let fact = signed_fact_with_payload(
        s.user_fact.id,
        USER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode"),
        1,
    );
    expect_err(p, &fact, &ProjectionContext::new(Vec::new()), "user_authority");
}

pub fn rejects_zero_public_key<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let mut invite = s.invite;
    invite.public_key = [0; 32];
    let fact = signed_fact_with_payload(
        s.user_fact.id,
        USER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode"),
        1,
    );
    expect_err(p, &fact, &ProjectionContext::new(Vec::new()), "public_key");
}

// --- need-declaration shapes --------------------------------------------------

pub fn user_signed_with_no_context_declares_three_needs<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let out = p
        .project(&s.fact, &ProjectionContext::new(Vec::new()))
        .expect("user-signed parks");
    assert!(out.intents.is_empty());
    assert!(out.offers.is_empty());
    assert_eq!(out.needs.len(), 3, "user-signed declares workspace + user + user_invite");
    assert!(out
        .needs
        .iter()
        .any(|n| n.role == identity_matchers::workspace_role()));
    assert!(out
        .needs
        .iter()
        .any(|n| n.role == identity_matchers::user_role()
            && n.selector.as_bytes() == &s.invite.user_authority_event_id));
    assert!(out
        .needs
        .iter()
        .any(|n| n.role == identity_matchers::user_invite_role()
            && n.selector.as_bytes() == s.invite.user_invite_event_id.as_ref().unwrap()));
}

pub fn endpoint_signed_with_no_context_declares_two_needs<P: Projector>(p: &P) {
    let s = endpoint_signed_scenario();
    let out = p
        .project(&s.fact, &ProjectionContext::new(Vec::new()))
        .expect("endpoint-signed parks");
    assert!(out.intents.is_empty());
    assert!(out.offers.is_empty());
    assert_eq!(out.needs.len(), 2, "endpoint-signed declares workspace + endpoint_shared");
    assert!(out
        .needs
        .iter()
        .any(|n| n.role == identity_matchers::workspace_role()));
    assert!(out
        .needs
        .iter()
        .any(|n| n.role == identity_matchers::endpoint_shared_role()));
}

pub fn endpoint_signed_with_only_workspace_still_parks<P: Projector>(p: &P) {
    let s = endpoint_signed_scenario();
    let context = ProjectionContext::from_matches(vec![workspace_match(
        s.fact.id,
        s.workspace_fact.clone(),
    )]);
    let out = p
        .project(&s.fact, &context)
        .expect("endpoint-signed parks waiting for endpoint_shared");
    assert!(out.intents.is_empty());
    assert!(out.offers.is_empty());
    assert!(out
        .needs
        .iter()
        .any(|n| n.role == identity_matchers::endpoint_shared_role()));
}

// --- success cases ------------------------------------------------------------

pub fn user_signed_materializes_on_full_context<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let out = p
        .project(&s.fact, &user_signed_full_context(&s))
        .expect("user-signed materializes");
    assert_eq!(out.intents.len(), 1, "one PutRow intent on success");
    assert_eq!(out.offers.len(), 2, "device_invite role + key offer");
    assert!(out
        .offers
        .iter()
        .any(|o| o.role == identity_matchers::device_invite_role()));
    assert!(out
        .offers
        .iter()
        .any(|o| o.role == identity_matchers::device_invite_key_role()));
}

pub fn endpoint_signed_materializes_on_full_context<P: Projector>(p: &P) {
    let s = endpoint_signed_scenario();
    let out = p
        .project(&s.fact, &endpoint_signed_full_context(&s))
        .expect("endpoint-signed materializes");
    assert_eq!(out.intents.len(), 1);
    assert_eq!(out.offers.len(), 2);
}

pub fn materialized_row_round_trips<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let out = p
        .project(&s.fact, &user_signed_full_context(&s))
        .expect("user-signed materializes");
    let intent = out.intents.first().expect("expected put_row intent");
    let row_intent =
        AtomicIntent::from_intent(intent, &[rows::DEVICE_INVITE_ROWS]).expect("row intent");
    let AtomicIntent::PutRow(stored) = row_intent else {
        panic!("expected put row");
    };
    let row = rows::decode_device_invite_row(&stored.key, &stored.value).expect("decode row");
    assert_eq!(row.workspace_id, WORKSPACE_ID);
    assert_eq!(row.device_invite_id, s.fact.id);
    assert_eq!(row.created_at_ms, 11);
    assert_eq!(row.user_authority_event_id, s.user_fact.id);
    assert_eq!(row.user_invite_event_id, Some(s.user_invite_fact.id));
    assert_eq!(row.public_key, s.invite.public_key);
}

// --- workspace authority ------------------------------------------------------

pub fn rejects_workspace_context_payload_id_mismatch<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let mut payload = s.workspace_fact.clone();
    payload.id = [0xee; 32];
    let need = identity_matchers::exact_need(
        s.fact.id,
        identity_matchers::workspace_role(),
        s.workspace_fact.id,
    );
    let context = ProjectionContext::from_matches(vec![
        MatchedContext {
            need,
            offer: identity_matchers::workspace_offer(s.workspace_fact.id),
            payload,
        },
        user_match(s.fact.id, s.user_fact.clone()),
        user_invite_match(s.fact.id, s.user_invite_fact.clone()),
    ]);
    expect_err(p, &s.fact, &context, "workspace context payload id mismatch");
}

pub fn rejects_workspace_payload_that_is_not_workspace<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    // Replace the workspace payload's bytes with a user fact's bytes — wrong type.
    let mut payload = s.workspace_fact.clone();
    payload.bytes = s.user_fact.bytes.clone();
    let context = ProjectionContext::from_matches(vec![
        MatchedContext {
            need: identity_matchers::exact_need(
                s.fact.id,
                identity_matchers::workspace_role(),
                s.workspace_fact.id,
            ),
            offer: identity_matchers::workspace_offer(s.workspace_fact.id),
            payload,
        },
        user_match(s.fact.id, s.user_fact.clone()),
        user_invite_match(s.fact.id, s.user_invite_fact.clone()),
    ]);
    expect_err(p, &s.fact, &context, "workspace");
}

// --- user-signed path validation ----------------------------------------------

pub fn rejects_user_signed_when_signer_id_is_not_user<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    // Sign the invite with someone else's signer_id while still claiming the user
    // as authority. The projector must reject this.
    let mut invite = s.invite;
    invite.user_authority_event_id = s.user_fact.id;
    let fact = signed_fact_with_payload(
        [0xaa; 32],
        USER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode"),
        11,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(fact.id, s.workspace_fact.clone()),
        user_match(fact.id, s.user_fact.clone()),
        user_invite_match(fact.id, s.user_invite_fact.clone()),
    ]);
    expect_err(p, &fact, &context, "signer user");
}

pub fn rejects_user_payload_id_mismatch<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let mut payload = s.user_fact.clone();
    payload.id = [0xff; 32];
    let need = identity_matchers::exact_need(
        s.fact.id,
        identity_matchers::user_role(),
        s.user_fact.id,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(s.fact.id, s.workspace_fact.clone()),
        MatchedContext {
            need,
            offer: identity_matchers::exact_offer(s.user_fact.id, identity_matchers::user_role()),
            payload,
        },
        user_invite_match(s.fact.id, s.user_invite_fact.clone()),
    ]);
    expect_err(p, &s.fact, &context, "user context payload id mismatch");
}

pub fn rejects_user_payload_not_signed_user<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    // Replace the user payload's bytes with the user_invite payload's bytes
    // (different inner type).
    let mut payload = s.user_fact.clone();
    payload.bytes = s.user_invite_fact.bytes.clone();
    let need = identity_matchers::exact_need(
        s.fact.id,
        identity_matchers::user_role(),
        s.user_fact.id,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(s.fact.id, s.workspace_fact.clone()),
        MatchedContext {
            need,
            offer: identity_matchers::exact_offer(s.user_fact.id, identity_matchers::user_role()),
            payload,
        },
        user_invite_match(s.fact.id, s.user_invite_fact.clone()),
    ]);
    expect_err(p, &s.fact, &context, "user or endpoint_shared");
}

pub fn rejects_user_signed_signer_key_mismatch<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    // Sign the device_invite with a DIFFERENT private key whose public key
    // does not match the user public key. signer_id stays set to the user fact
    // so we hit the public-key check.
    let fact = signed_fact_with_payload(
        s.user_fact.id,
        [0x42; 32],
        layout::encode_fact(&s.invite).expect("encode"),
        11,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(fact.id, s.workspace_fact.clone()),
        user_match(fact.id, s.user_fact.clone()),
        user_invite_match(fact.id, s.user_invite_fact.clone()),
    ]);
    expect_err(p, &fact, &context, "public key");
}

pub fn rejects_user_signed_wrong_workspace<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    // Build a user fact whose workspace_id is different.
    let foreign_user = UserFact {
        created_at_ms: 2,
        workspace_id: [0x77; 32],
        public_key: crypto::ed25519_public_key(&USER_PRIVATE_KEY),
        username: "alice".to_string(),
    };
    let foreign_user_fact = signed_fact_with_payload(
        s.user_invite_fact.id,
        USER_INVITE_PRIVATE_KEY,
        user_layout::encode_fact(&foreign_user).expect("encode user"),
        2,
    );
    let invite = DeviceInviteFact {
        created_at_ms: 11,
        workspace_id: WORKSPACE_ID,
        user_authority_event_id: foreign_user_fact.id,
        user_invite_event_id: Some(s.user_invite_fact.id),
        public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
    };
    let fact = signed_fact_with_payload(
        foreign_user_fact.id,
        USER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode"),
        11,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(fact.id, s.workspace_fact.clone()),
        user_match(fact.id, foreign_user_fact),
        user_invite_match(fact.id, s.user_invite_fact.clone()),
    ]);
    expect_err(p, &fact, &context, "different workspace");
}

pub fn rejects_user_signed_user_not_signed_by_named_user_invite<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    // Rebuild user signed by a *different* user_invite than the device_invite
    // claims. signer_id on the user envelope must equal invite.user_invite_event_id.
    let other_user_invite_fact_id = [0xab; 32];
    let user = UserFact {
        created_at_ms: 2,
        workspace_id: WORKSPACE_ID,
        public_key: crypto::ed25519_public_key(&USER_PRIVATE_KEY),
        username: "alice".to_string(),
    };
    let user_fact = signed_fact_with_payload(
        other_user_invite_fact_id,
        USER_INVITE_PRIVATE_KEY,
        user_layout::encode_fact(&user).expect("encode user"),
        2,
    );
    let invite = DeviceInviteFact {
        created_at_ms: 11,
        workspace_id: WORKSPACE_ID,
        user_authority_event_id: user_fact.id,
        user_invite_event_id: Some(s.user_invite_fact.id),
        public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
    };
    let fact = signed_fact_with_payload(
        user_fact.id,
        USER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode"),
        11,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(fact.id, s.workspace_fact.clone()),
        user_match(fact.id, user_fact),
        user_invite_match(fact.id, s.user_invite_fact.clone()),
    ]);
    expect_err(p, &fact, &context, "does not match signed user");
}

pub fn rejects_user_invite_payload_id_mismatch<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    let mut payload = s.user_invite_fact.clone();
    payload.id = [0xcc; 32];
    let need = identity_matchers::exact_need(
        s.fact.id,
        identity_matchers::user_invite_role(),
        s.user_invite_fact.id,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(s.fact.id, s.workspace_fact.clone()),
        user_match(s.fact.id, s.user_fact.clone()),
        MatchedContext {
            need,
            offer: identity_matchers::user_invite_offer(s.user_invite_fact.id),
            payload,
        },
    ]);
    expect_err(p, &s.fact, &context, "user_invite context payload id mismatch");
}

pub fn rejects_user_invite_payload_not_user_invite<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    // Replace user_invite payload bytes with user bytes — wrong inner type.
    let mut payload = s.user_invite_fact.clone();
    payload.bytes = s.user_fact.bytes.clone();
    let context = ProjectionContext::from_matches(vec![
        workspace_match(s.fact.id, s.workspace_fact.clone()),
        user_match(s.fact.id, s.user_fact.clone()),
        MatchedContext {
            need: identity_matchers::exact_need(
                s.fact.id,
                identity_matchers::user_invite_role(),
                s.user_invite_fact.id,
            ),
            offer: identity_matchers::user_invite_offer(s.user_invite_fact.id),
            payload,
        },
    ]);
    expect_err(p, &s.fact, &context, "user_invite");
}

pub fn rejects_user_invite_wrong_workspace<P: Projector>(p: &P) {
    let foreign_workspace = [0xee; 32];
    let user_invite = UserInviteFact {
        created_at_ms: 1,
        public_key: crypto::ed25519_public_key(&USER_INVITE_PRIVATE_KEY),
        workspace_id: foreign_workspace,
        authority_event_id: foreign_workspace,
    };
    let user_invite_fact = signed_fact_with_payload(
        foreign_workspace,
        USER_INVITE_PRIVATE_KEY,
        user_invite_layout::encode_fact(&user_invite).expect("encode"),
        1,
    );
    let user = UserFact {
        created_at_ms: 2,
        workspace_id: WORKSPACE_ID,
        public_key: crypto::ed25519_public_key(&USER_PRIVATE_KEY),
        username: "alice".to_string(),
    };
    let user_fact = signed_fact_with_payload(
        user_invite_fact.id,
        USER_INVITE_PRIVATE_KEY,
        user_layout::encode_fact(&user).expect("encode user"),
        2,
    );
    let invite = DeviceInviteFact {
        created_at_ms: 11,
        workspace_id: WORKSPACE_ID,
        user_authority_event_id: user_fact.id,
        user_invite_event_id: Some(user_invite_fact.id),
        public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
    };
    let fact = signed_fact_with_payload(
        user_fact.id,
        USER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode"),
        11,
    );
    let workspace = workspace_fact(WORKSPACE_ID);
    let context = ProjectionContext::from_matches(vec![
        workspace_match(fact.id, workspace),
        user_match(fact.id, user_fact),
        user_invite_match(fact.id, user_invite_fact),
    ]);
    expect_err(p, &fact, &context, "user_invite belongs to a different workspace");
}

pub fn rejects_user_invite_key_not_matching_user<P: Projector>(p: &P) {
    let s = user_signed_scenario();
    // Build a user_invite with a public_key that does NOT match the user's
    // public_key signed by the same user_invite.
    let user_invite = UserInviteFact {
        created_at_ms: 1,
        public_key: [0x99; 32],
        workspace_id: WORKSPACE_ID,
        authority_event_id: WORKSPACE_ID,
    };
    let user_invite_fact = signed_fact_with_payload(
        WORKSPACE_ID,
        USER_INVITE_PRIVATE_KEY,
        user_invite_layout::encode_fact(&user_invite).expect("encode"),
        1,
    );
    let user = UserFact {
        created_at_ms: 2,
        workspace_id: WORKSPACE_ID,
        public_key: crypto::ed25519_public_key(&USER_PRIVATE_KEY),
        username: "alice".to_string(),
    };
    let user_fact = signed_fact_with_payload(
        user_invite_fact.id,
        USER_INVITE_PRIVATE_KEY,
        user_layout::encode_fact(&user).expect("encode user"),
        2,
    );
    let invite = DeviceInviteFact {
        created_at_ms: 11,
        workspace_id: WORKSPACE_ID,
        user_authority_event_id: user_fact.id,
        user_invite_event_id: Some(user_invite_fact.id),
        public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
    };
    let fact = signed_fact_with_payload(
        user_fact.id,
        USER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode"),
        11,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(fact.id, s.workspace_fact.clone()),
        user_match(fact.id, user_fact),
        user_invite_match(fact.id, user_invite_fact),
    ]);
    expect_err(p, &fact, &context, "user_invite key");
}

// --- endpoint-signed path validation ------------------------------------------

pub fn rejects_endpoint_shared_context_payload_id_mismatch<P: Projector>(p: &P) {
    let s = endpoint_signed_scenario();
    let mut payload = s.endpoint_fact.clone();
    payload.id = [0xfe; 32];
    let need = identity_matchers::exact_need(
        s.fact.id,
        identity_matchers::endpoint_shared_role(),
        s.endpoint_fact.id,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(s.fact.id, s.workspace_fact.clone()),
        MatchedContext {
            need,
            offer: identity_matchers::exact_offer(
                s.endpoint_fact.id,
                identity_matchers::endpoint_shared_role(),
            ),
            payload,
        },
    ]);
    expect_err(p, &s.fact, &context, "endpoint_shared context payload id mismatch");
}

pub fn rejects_endpoint_shared_payload_not_endpoint_shared<P: Projector>(p: &P) {
    let s = endpoint_signed_scenario();
    // Replace endpoint_shared payload bytes with a workspace's bytes.
    let mut payload = s.endpoint_fact.clone();
    payload.bytes = s.workspace_fact.bytes.clone();
    let context = ProjectionContext::from_matches(vec![
        workspace_match(s.fact.id, s.workspace_fact.clone()),
        MatchedContext {
            need: identity_matchers::exact_need(
                s.fact.id,
                identity_matchers::endpoint_shared_role(),
                s.endpoint_fact.id,
            ),
            offer: identity_matchers::exact_offer(
                s.endpoint_fact.id,
                identity_matchers::endpoint_shared_role(),
            ),
            payload,
        },
    ]);
    expect_err(p, &s.fact, &context, "user or endpoint_shared");
}

pub fn rejects_endpoint_shared_signer_key_mismatch<P: Projector>(p: &P) {
    let s = endpoint_signed_scenario();
    // Re-sign device_invite with a DIFFERENT private key while keeping signer_id
    // pointing at the endpoint_shared fact. The pubkey check must fail.
    let fact = signed_fact_with_payload(
        s.endpoint_fact.id,
        [0x77; 32],
        layout::encode_fact(&s.invite).expect("encode"),
        11,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(fact.id, s.workspace_fact.clone()),
        endpoint_shared_match(fact.id, s.endpoint_fact.clone()),
    ]);
    expect_err(p, &fact, &context, "endpoint_shared signing key");
}

pub fn rejects_endpoint_shared_wrong_workspace<P: Projector>(p: &P) {
    // Build endpoint_shared with a different workspace_id.
    let foreign_workspace = [0x66; 32];
    let endpoint = EndpointSharedFact {
        created_at_ms: 4,
        workspace_id: foreign_workspace,
        user_authority_event_id: [50; 32],
        endpoint_id: ENDPOINT_ID,
        signing_public_key: crypto::ed25519_public_key(&ENDPOINT_SIGNER_PRIVATE_KEY),
        endpoint_role: EndpointRole::Device,
        device_name: "laptop".to_string(),
    };
    let endpoint_fact = signed_fact_with_payload(
        [44; 32],
        [45; 32],
        endpoint_shared_layout::encode_fact(&endpoint).expect("encode"),
        4,
    );
    let invite = DeviceInviteFact {
        created_at_ms: 11,
        workspace_id: WORKSPACE_ID,
        user_authority_event_id: endpoint.user_authority_event_id,
        user_invite_event_id: None,
        public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
    };
    let fact = signed_fact_with_payload(
        endpoint_fact.id,
        ENDPOINT_SIGNER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode"),
        11,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(fact.id, workspace_fact(WORKSPACE_ID)),
        endpoint_shared_match(fact.id, endpoint_fact),
    ]);
    expect_err(p, &fact, &context, "workspace does not match");
}

pub fn rejects_endpoint_shared_wrong_user_authority<P: Projector>(p: &P) {
    let s = endpoint_signed_scenario();
    // Build a device_invite naming a DIFFERENT user_authority than the
    // endpoint_shared claims. Re-sign with the endpoint signer.
    let mut invite = s.invite;
    invite.user_authority_event_id = [0xbe; 32];
    let fact = signed_fact_with_payload(
        s.endpoint_fact.id,
        ENDPOINT_SIGNER_PRIVATE_KEY,
        layout::encode_fact(&invite).expect("encode"),
        11,
    );
    let context = ProjectionContext::from_matches(vec![
        workspace_match(fact.id, s.workspace_fact.clone()),
        endpoint_shared_match(fact.id, s.endpoint_fact.clone()),
    ]);
    expect_err(p, &fact, &context, "user authority does not match");
}

// --- master battery -----------------------------------------------------------

pub fn run_all_invariants<P: Projector>(p: &P) {
    rejects_local_scope(p);
    rejects_unsigned_fact(p);
    rejects_signed_envelope_with_wrong_inner_type(p);
    rejects_zero_workspace_id(p);
    rejects_zero_user_authority(p);
    rejects_zero_public_key(p);
    user_signed_with_no_context_declares_three_needs(p);
    endpoint_signed_with_no_context_declares_two_needs(p);
    endpoint_signed_with_only_workspace_still_parks(p);
    user_signed_materializes_on_full_context(p);
    endpoint_signed_materializes_on_full_context(p);
    materialized_row_round_trips(p);
    rejects_workspace_context_payload_id_mismatch(p);
    rejects_workspace_payload_that_is_not_workspace(p);
    rejects_user_signed_when_signer_id_is_not_user(p);
    rejects_user_payload_id_mismatch(p);
    rejects_user_payload_not_signed_user(p);
    rejects_user_signed_signer_key_mismatch(p);
    rejects_user_signed_wrong_workspace(p);
    rejects_user_signed_user_not_signed_by_named_user_invite(p);
    rejects_user_invite_payload_id_mismatch(p);
    rejects_user_invite_payload_not_user_invite(p);
    rejects_user_invite_wrong_workspace(p);
    rejects_user_invite_key_not_matching_user(p);
    rejects_endpoint_shared_context_payload_id_mismatch(p);
    rejects_endpoint_shared_payload_not_endpoint_shared(p);
    rejects_endpoint_shared_signer_key_mismatch(p);
    rejects_endpoint_shared_wrong_workspace(p);
    rejects_endpoint_shared_wrong_user_authority(p);
}
