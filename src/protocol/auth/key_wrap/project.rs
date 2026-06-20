pub mod decode {
    //! Byte decoding for key wrap facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, field order, and the
    //! structural coordinate constraints shared with encoding. Id checks live in
    //! the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{validate_key_wrap, KEY_WRAP_BYTES, TYPE_KEY_WRAP};
    use super::super::fact::{KeyWrapFact, WrappedSecretKind};

    pub fn decode_key_wrap(bytes: &[u8]) -> Result<KeyWrapFact, String> {
        wire::expect_len(bytes, KEY_WRAP_BYTES).map_err(wire_err)?;
        if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_KEY_WRAP {
            return Err("expected key wrap".to_string());
        }
        let fact = KeyWrapFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            created_at_ms: wire::take_u64be(&bytes[33..41]).map_err(wire_err)?,
            signer_endpoint_id: bytes[41..73].try_into().unwrap(),
            frontier_id: bytes[73..105].try_into().unwrap(),
            wrapped_secret_kind: WrappedSecretKind::from_u8(bytes[105])?,
            wrapped_secret_id: bytes[106..138].try_into().unwrap(),
            wrapped_source_secret_id: bytes[138..170].try_into().unwrap(),
            wrapped_tombstone_node_id: bytes[170..202].try_into().unwrap(),
            range_start: wire::take_u64be(&bytes[202..210]).map_err(wire_err)?,
            range_width: wire::take_u64be(&bytes[210..218]).map_err(wire_err)?,
            bit_depth: wire::take_u16be(&bytes[218..220]).map_err(wire_err)?,
            fact_id_prefix: bytes[220..252].try_into().unwrap(),
            recipient_key_id: bytes[252..284].try_into().unwrap(),
            sender_wrap_public_key: bytes[284..316].try_into().unwrap(),
            nonce: bytes[316..340].try_into().unwrap(),
            ciphertext: bytes[340..388].try_into().unwrap(),
        };
        validate_key_wrap(&fact)?;
        Ok(fact)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    // Ordered most-central-first: the roundtrip proves the full layout; narrower guards follow.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::core::crypto::{X25519_PUBLIC_KEY_BYTES, XCHACHA20_POLY1305_NONCE_BYTES};
        use crate::protocol::auth::key_wrap::encode::{encode_key_wrap, KEY_WRAP_BYTES};
        use crate::protocol::auth::key_wrap::fact::KEY_WRAP_CIPHERTEXT_BYTES;

        fn sample_fact() -> KeyWrapFact {
            KeyWrapFact {
                workspace_id: [1; 32],
                created_at_ms: 123,
                signer_endpoint_id: [2; 32],
                frontier_id: [3; 32],
                wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
                wrapped_secret_id: [4; 32],
                wrapped_source_secret_id: [0; 32],
                wrapped_tombstone_node_id: [0; 32],
                range_start: 0,
                range_width: 0,
                bit_depth: 0,
                fact_id_prefix: [0; 32],
                recipient_key_id: [5; 32],
                sender_wrap_public_key: [6; X25519_PUBLIC_KEY_BYTES],
                nonce: [7; XCHACHA20_POLY1305_NONCE_BYTES],
                ciphertext: [8; KEY_WRAP_CIPHERTEXT_BYTES],
            }
        }

        #[test]
        fn key_wrap_roundtrips_fixed_width() {
            let fact = sample_fact();

            let encoded = encode_key_wrap(&fact).expect("encode key wrap");

            assert_eq!(encoded.len(), KEY_WRAP_BYTES);
            assert_eq!(decode_key_wrap(&encoded).expect("decode key wrap"), fact);
        }
    }
}
pub mod authenticate {
    //! Key-wrap authenticator.
    //!
    //! POLICY. Authenticating a `key_wrap` fact proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical key-wrap fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! A key wrap is the raw exception to natural fact signing: it carries no
    //! signature field, so there is nothing to verify at the fact boundary. The
    //! signer is proven from recipient/frontier/endpoint context, and admission
    //! scope is unsigned local metadata — both are interpretation the projector
    //! owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::KeyWrapFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        wrap: KeyWrapFact,
        _context: &ProjectionContext,
    ) -> Result<KeyWrapFact, String> {
        prove_decoded_key_wrap(fact, wrap)
    }

    fn prove_decoded_key_wrap(fact: &Fact, wrap: KeyWrapFact) -> Result<KeyWrapFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(wrap)
    }

    // Tests.
    // Ordered most-central-first: canonical admit, then the id check, then layout guards.
    #[cfg(test)]
    mod tests {
        use crate::core::crypto::{X25519_PUBLIC_KEY_BYTES, XCHACHA20_POLY1305_NONCE_BYTES};
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::key_wrap::author::admit_key_wrap_fact;
        use crate::protocol::auth::key_wrap::encode;
        use crate::protocol::auth::key_wrap::fact::{
            KeyWrapFact, WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES,
        };

        fn canonical_fact() -> Fact {
            let wrap = KeyWrapFact {
                workspace_id: [1; 32],
                created_at_ms: 1_700_000_321,
                signer_endpoint_id: [2; 32],
                frontier_id: [3; 32],
                wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
                wrapped_secret_id: [4; 32],
                wrapped_source_secret_id: [0; 32],
                wrapped_tombstone_node_id: [0; 32],
                range_start: 0,
                range_width: 0,
                bit_depth: 0,
                fact_id_prefix: [0; 32],
                recipient_key_id: [5; 32],
                sender_wrap_public_key: [6; X25519_PUBLIC_KEY_BYTES],
                nonce: [7; XCHACHA20_POLY1305_NONCE_BYTES],
                ciphertext: [8; KEY_WRAP_CIPHERTEXT_BYTES],
            };
            let bytes = encode::encode_key_wrap(&wrap).expect("encode key wrap");
            admit_key_wrap_fact(bytes).expect("admit key wrap fact")
        }

        fn authenticate(fact: &Fact) -> Result<KeyWrapFact, String> {
            let decoded = super::super::decode::decode_key_wrap(fact.body())?;
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
    }
}
pub mod adapt {
    //! Key-wrap semantic adapter.
    //!
    //! The current key_wrap wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::KeyWrapFact;

    pub(crate) fn adapt(source: KeyWrapFact) -> Result<KeyWrapFact, String> {
        Ok(source)
    }
}

// Key wrap projector plus shared auth key-material wrap-source policy.
//
// POLICY. A key wrap is admitted iff signer, recipient, and frontier context
// validate; if local recipient material exists, a local recovery fact is emitted.
//
// This module also owns the wrap-source coordinate scheme and the shared
// projection helpers (scope checks, signer matching, wrap-source validation)
// that recipient-key, key-request, and local-material projection consume. The
// key-wrap family owns wrap sources, so the policy lives here.

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth;
use crate::protocol::auth::key_wrap_recovery::key_wrap_recovery_fact;
use crate::protocol::auth::local_history_node_secret;
use crate::protocol::auth::local_key_secret;
use crate::protocol::auth::recipient_key;
use crate::protocol::auth::removal_frontier;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::fact::KeyWrapFact;
pub use super::fact::WrapSourceKind;
use super::key_wrap_insert;
use super::queries::KeyWrapRow;

// ---------------------------------------------------------------------------
// Wrap-source coordinate scheme.
// ---------------------------------------------------------------------------

const WRAP_SOURCE_ROLE: &str = "wrap_source";
const PROACTIVE_DOMAIN: u8 = 1;
const REQUESTED_DOMAIN: u8 = 2;
const ENCODED_WRAP_SOURCE_DESCRIPTOR_LEN: usize = 156;

pub fn wrap_source_role() -> Role {
    Role::expect(WRAP_SOURCE_ROLE)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapSourceDescriptor {
    pub workspace_id: FactId,
    pub frontier_id: FactId,
    pub owner_endpoint_id: FactId,
    pub frontier_created_at_ms: u64,
    pub kind: WrapSourceKind,
}

pub fn proactive_wrap_source_need(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    min_frontier_created_at_ms: u64,
) -> ContextNeed {
    let start = proactive_wrap_key_prefix(workspace_id, min_frontier_created_at_ms);
    let mut end = proactive_wrap_key_prefix(workspace_id, u64::MAX);
    end.extend_from_slice(&[0xff; ENCODED_WRAP_SOURCE_DESCRIPTOR_LEN]);
    ContextNeed::range(owner, wrap_source_role(), scope, start, end)
}

pub fn requested_wrap_source_need(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
) -> ContextNeed {
    let start = requested_wrap_key_prefix(workspace_id, frontier_id);
    let mut end = start.clone();
    end.extend_from_slice(&[0xff; ENCODED_WRAP_SOURCE_DESCRIPTOR_LEN]);
    ContextNeed::range(owner, wrap_source_role(), scope, start, end)
}

pub fn frontier_root_wrap_source_offers(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
    owner_endpoint_id: FactId,
    frontier_created_at_ms: u64,
) -> Vec<ContextOffer> {
    wrap_source_offers(
        owner,
        scope,
        WrapSourceDescriptor {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            frontier_created_at_ms,
            kind: WrapSourceKind::FrontierRoot,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn history_node_wrap_source_offers(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
    owner_endpoint_id: FactId,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: FactId,
) -> Vec<ContextOffer> {
    wrap_source_offers(
        owner,
        scope,
        WrapSourceDescriptor {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            frontier_created_at_ms: 0,
            kind: WrapSourceKind::HistoryNode {
                range_start,
                range_width,
                bit_depth,
                fact_id_prefix,
            },
        },
    )
}

fn wrap_source_offers(
    owner: FactId,
    scope: FactScope,
    source: WrapSourceDescriptor,
) -> Vec<ContextOffer> {
    let metadata = encode_wrap_source_descriptor(&source).as_bytes().to_vec();
    let proactive_key = wrap_offer_key(PROACTIVE_DOMAIN, &source, &metadata);
    let proactive = ContextOffer::range(
        owner,
        wrap_source_role(),
        scope.clone(),
        proactive_key.clone(),
        proactive_key,
    );
    let requested_key = wrap_offer_key(REQUESTED_DOMAIN, &source, &metadata);
    let requested = ContextOffer::range(
        owner,
        wrap_source_role(),
        scope,
        requested_key.clone(),
        requested_key,
    );
    vec![proactive, requested]
}

fn wrap_offer_key(domain: u8, source: &WrapSourceDescriptor, metadata: &[u8]) -> Vec<u8> {
    let mut key = match domain {
        PROACTIVE_DOMAIN => {
            proactive_wrap_key_prefix(source.workspace_id, source.frontier_created_at_ms)
        }
        REQUESTED_DOMAIN => requested_wrap_key_prefix(source.workspace_id, source.frontier_id),
        _ => unreachable!("wrap source domain is internal"),
    };
    key.extend_from_slice(metadata);
    key
}

fn proactive_wrap_key_prefix(workspace_id: FactId, frontier_created_at_ms: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(41);
    key.push(PROACTIVE_DOMAIN);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&frontier_created_at_ms.to_be_bytes());
    key
}

fn requested_wrap_key_prefix(workspace_id: FactId, frontier_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(65);
    key.push(REQUESTED_DOMAIN);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&frontier_id);
    key
}

pub fn decode_wrap_source_descriptor(key: &ContextKey) -> Option<WrapSourceDescriptor> {
    decode_wrap_source_metadata(key.as_bytes())
}

fn decode_wrap_source_offer_key(key: &ContextKey) -> Option<(u8, WrapSourceDescriptor)> {
    let bytes = key.as_bytes();
    match bytes.first().copied()? {
        PROACTIVE_DOMAIN => {
            let metadata_start = 1 + 32 + 8;
            let source = decode_wrap_source_metadata(bytes.get(metadata_start..)?)?;
            Some((PROACTIVE_DOMAIN, source))
        }
        REQUESTED_DOMAIN => {
            let metadata_start = 1 + 32 + 32;
            let source = decode_wrap_source_metadata(bytes.get(metadata_start..)?)?;
            Some((REQUESTED_DOMAIN, source))
        }
        _ => None,
    }
}

fn decode_wrap_source_metadata(bytes: &[u8]) -> Option<WrapSourceDescriptor> {
    if bytes.len() != ENCODED_WRAP_SOURCE_DESCRIPTOR_LEN || bytes[0] != 3 {
        return None;
    }
    let workspace_id = bytes[1..33].try_into().ok()?;
    let frontier_id = bytes[33..65].try_into().ok()?;
    let owner_endpoint_id = bytes[65..97].try_into().ok()?;
    let frontier_created_at_ms = u64::from_be_bytes(bytes[97..105].try_into().ok()?);
    match bytes[105] {
        1 => Some(WrapSourceDescriptor {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            frontier_created_at_ms,
            kind: WrapSourceKind::FrontierRoot,
        }),
        2 => {
            let range_start = u64::from_be_bytes(bytes[106..114].try_into().ok()?);
            let range_width = u64::from_be_bytes(bytes[114..122].try_into().ok()?);
            let bit_depth = u16::from_be_bytes(bytes[122..124].try_into().ok()?);
            let fact_id_prefix = bytes[124..156].try_into().ok()?;
            if !valid_history_coordinate(range_start, range_width, bit_depth, fact_id_prefix) {
                return None;
            }
            Some(WrapSourceDescriptor {
                workspace_id,
                frontier_id,
                owner_endpoint_id,
                frontier_created_at_ms,
                kind: WrapSourceKind::HistoryNode {
                    range_start,
                    range_width,
                    bit_depth,
                    fact_id_prefix,
                },
            })
        }
        _ => None,
    }
}

pub fn encode_wrap_source_descriptor(source: &WrapSourceDescriptor) -> ContextKey {
    let mut bytes = Vec::with_capacity(ENCODED_WRAP_SOURCE_DESCRIPTOR_LEN);
    bytes.push(3);
    bytes.extend_from_slice(&source.workspace_id);
    bytes.extend_from_slice(&source.frontier_id);
    bytes.extend_from_slice(&source.owner_endpoint_id);
    bytes.extend_from_slice(&source.frontier_created_at_ms.to_be_bytes());
    match source.kind {
        WrapSourceKind::FrontierRoot => {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 50]);
        }
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            fact_id_prefix,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&range_start.to_be_bytes());
            bytes.extend_from_slice(&range_width.to_be_bytes());
            bytes.extend_from_slice(&bit_depth.to_be_bytes());
            bytes.extend_from_slice(&fact_id_prefix);
        }
    }
    ContextKey::from_bytes(bytes)
}

fn valid_history_coordinate(
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: FactId,
) -> bool {
    range_width != 0
        && range_width.is_power_of_two()
        && range_start.is_multiple_of(range_width)
        && bit_depth <= 256
        && fact_id_prefix == mask_prefix_to_depth(fact_id_prefix, bit_depth)
        && (range_width == 1 || (bit_depth == 0 && fact_id_prefix == [0; 32]))
}

fn mask_prefix_to_depth(mut prefix: FactId, bit_depth: u16) -> FactId {
    let bit_depth = bit_depth as usize;
    if bit_depth >= 256 {
        return prefix;
    }
    let byte_index = bit_depth / 8;
    let remaining_bits = bit_depth % 8;
    if remaining_bits == 0 {
        prefix[byte_index..].fill(0);
    } else {
        prefix[byte_index] &= 0xff << (8 - remaining_bits);
        prefix[byte_index + 1..].fill(0);
    }
    prefix
}

pub fn decode_proactive_wrap_need(need: &ContextNeed) -> Option<(FactId, u64)> {
    let start = need.start_key.as_bytes();
    let end = need.end_key.as_bytes();
    if start.len() != 41 || start[0] != PROACTIVE_DOMAIN {
        return None;
    }
    if end.len() != 41 + ENCODED_WRAP_SOURCE_DESCRIPTOR_LEN || end[0] != PROACTIVE_DOMAIN {
        return None;
    }
    let workspace_id: FactId = start[1..33].try_into().ok()?;
    if end[1..33] != workspace_id {
        return None;
    }
    Some((
        workspace_id,
        u64::from_be_bytes(start[33..41].try_into().ok()?),
    ))
}

pub fn decode_requested_wrap_need(need: &ContextNeed) -> Option<(FactId, FactId)> {
    let start = need.start_key.as_bytes();
    let end = need.end_key.as_bytes();
    if start.len() != 65 || start[0] != REQUESTED_DOMAIN {
        return None;
    }
    if end.len() != 65 + ENCODED_WRAP_SOURCE_DESCRIPTOR_LEN || end[0] != REQUESTED_DOMAIN {
        return None;
    }
    let workspace_id: FactId = start[1..33].try_into().ok()?;
    let frontier_id: FactId = start[33..65].try_into().ok()?;
    if end[1..33] != workspace_id || end[33..65] != frontier_id {
        return None;
    }
    Some((workspace_id, frontier_id))
}

pub fn wrap_source_offer_valid_for_need(
    need: &ContextNeed,
    offer: &ContextOffer,
) -> Option<WrapSourceDescriptor> {
    if need.role != offer.role || need.scope != offer.scope || offer.start_key != offer.end_key {
        return None;
    }
    let (domain, source) = decode_wrap_source_offer_key(&offer.start_key)?;
    match domain {
        PROACTIVE_DOMAIN => {
            let (workspace_id, min_frontier_created_at_ms) = decode_proactive_wrap_need(need)?;
            (source.workspace_id == workspace_id
                && source.frontier_created_at_ms >= min_frontier_created_at_ms)
                .then_some(source)
        }
        REQUESTED_DOMAIN => {
            let (workspace_id, frontier_id) = decode_requested_wrap_need(need)?;
            (source.workspace_id == workspace_id && source.frontier_id == frontier_id)
                .then_some(source)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Shared projection helpers consumed by the other auth key-material families.
// ---------------------------------------------------------------------------

pub(crate) fn matching_wrap_sources_with_signer(
    projection_context: &ProjectionContext,
    need: &ContextNeed,
) -> Result<Vec<(FactId, FactId, WrapSourceDescriptor)>, String> {
    projection_context
        .matched_payloads_for(need)
        .filter_map(|(offer, payload)| {
            wrap_source_offer_valid_for_need(need, offer).map(|source| (offer, payload, source))
        })
        .map(|(_, payload, source)| {
            validate_wrap_source_payload(payload, &source)?;
            Ok(local_signer_secret_fact_id(
                projection_context,
                need.owner,
                &need.scope,
                source.owner_endpoint_id,
            )
            .map(|signer_secret_fact_id| (payload.id, signer_secret_fact_id, source)))
        })
        .collect::<Result<Vec<_>, String>>()
        .map(|items| items.into_iter().flatten().collect())
}

pub(crate) fn add_signer_needs_for_matching_sources(
    mut output: ProjectionOutput,
    projection_context: &ProjectionContext,
    need: &ContextNeed,
) -> Result<ProjectionOutput, String> {
    for (offer, payload) in projection_context.matched_payloads_for(need) {
        let Some(source) = wrap_source_offer_valid_for_need(need, offer) else {
            continue;
        };
        validate_wrap_source_payload(payload, &source)?;
        output = output.need(ContextNeed::range(
            need.owner,
            "local_signer_secret",
            need.scope.clone(),
            source.owner_endpoint_id,
            source.owner_endpoint_id,
        ));
    }
    Ok(output)
}

fn local_signer_secret_fact_id(
    projection_context: &ProjectionContext,
    owner: FactId,
    scope: &FactScope,
    signer_id: FactId,
) -> Option<FactId> {
    let need = ContextNeed::range(
        owner,
        "local_signer_secret",
        scope.clone(),
        signer_id,
        signer_id,
    );
    projection_context
        .matched_payloads_for(&need)
        .map(|(_, payload)| payload.id)
        .min()
}

pub(crate) fn matched_payload_fact<'a>(
    projection_context: &'a ProjectionContext,
    need: &ContextNeed,
) -> Option<&'a Fact> {
    projection_context.payload_for(need)
}

pub(crate) fn matching_signer_public_key(
    projection_context: &ProjectionContext,
    need: &ContextNeed,
) -> Result<Option<[u8; 32]>, String> {
    for (_, payload) in projection_context.matched_payloads_for(need) {
        let Ok(endpoint) = auth::endpoint_shared::decode_fact_payload(payload.body()) else {
            continue;
        };
        if endpoint.endpoint_id.as_slice() == need.start_key.as_bytes() {
            return Ok(Some(endpoint.signing_public_key));
        }
    }
    Ok(None)
}

pub(crate) fn require_fact_scope(fact: &Fact, expected: &FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("auth fact scope does not match body workspace".to_string())
    }
}

pub(crate) fn require_local_scope(fact: &Fact) -> Result<(), String> {
    if fact.scope == FactScope::Local {
        Ok(())
    } else {
        Err("local auth fact must have local scope".to_string())
    }
}

fn validate_wrap_source_payload(
    payload: &Fact,
    source: &WrapSourceDescriptor,
) -> Result<(), String> {
    if payload.scope != FactScope::Local {
        return Err("wrap source context must be local key material".to_string());
    }
    match source.kind {
        WrapSourceKind::FrontierRoot => {
            let root = local_key_secret::decode_fact_payload(payload.body())
                .map_err(|_| "wrap source context is not a local root secret".to_string())?;
            if root.workspace_id != source.workspace_id
                || root.frontier_id != source.frontier_id
                || root.owner_endpoint_id != source.owner_endpoint_id
                || root.created_at_ms != source.frontier_created_at_ms
            {
                return Err("wrap source root payload does not match descriptor".to_string());
            }
        }
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            fact_id_prefix,
        } => {
            let node = local_history_node_secret::decode_fact_payload(payload.body())
                .map_err(|_| "wrap source context is not a local history node".to_string())?;
            if node.workspace_id != source.workspace_id
                || node.frontier_id != source.frontier_id
                || node.owner_endpoint_id != source.owner_endpoint_id
                || source.frontier_created_at_ms != 0
                || node.range_start != range_start
                || node.range_width != range_width
                || node.bit_depth != bit_depth
                || node.fact_id_prefix != fact_id_prefix
            {
                return Err("wrap source history payload does not match descriptor".to_string());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Key wrap projector.
// ---------------------------------------------------------------------------

/// Projector route metadata for the key_wrap fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::key_wrap::project::KeyWrapProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct KeyWrapProjector;

impl KeyWrapProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for KeyWrapProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_key_wrap(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl KeyWrapProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        wrap: KeyWrapFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        key_wrap(fact, context, wrap)
    }
}

fn key_wrap(
    fact: &Fact,
    projection_context: &ProjectionContext,
    wrap: KeyWrapFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = crate::protocol::auth::workspace::scope(wrap.workspace_id);
    require_fact_scope(fact, &scope)?;

    // 2. Context: signer, recipient, frontier, and local recipient.
    let signer_need = ContextNeed::range(
        fact.id,
        "content_signer",
        scope.clone(),
        wrap.signer_endpoint_id,
        wrap.signer_endpoint_id,
    );
    let recipient_need = ContextNeed::range(
        fact.id,
        "recipient_key",
        scope.clone(),
        wrap.recipient_key_id,
        wrap.recipient_key_id,
    );
    let frontier_need = ContextNeed::range(
        fact.id,
        "auth_removal_frontier",
        scope.clone(),
        wrap.frontier_id,
        wrap.frontier_id,
    );
    let local_recipient_need = ContextNeed::range(
        fact.id,
        "local_recipient_key",
        scope.clone(),
        wrap.recipient_key_id,
        wrap.recipient_key_id,
    );

    let signer_public_key = matching_signer_public_key(projection_context, &signer_need)?;
    let recipient_fact = matched_payload_fact(projection_context, &recipient_need);
    let frontier_fact = matched_payload_fact(projection_context, &frontier_need);
    let local_recipient_fact = matched_payload_fact(projection_context, &local_recipient_need);

    let mut output = ProjectionOutput::new()
        .need(signer_need.clone())
        .need(recipient_need.clone())
        .need(frontier_need.clone())
        .need(local_recipient_need.clone());

    if signer_public_key.is_none() || recipient_fact.is_none() || frontier_fact.is_none() {
        return Ok(output);
    }
    let signer_public_key = signer_public_key.expect("checked");

    let recipient_fact = recipient_fact.expect("checked");
    if recipient_fact.id != wrap.recipient_key_id {
        return Err("key wrap recipient context payload id mismatch".to_string());
    }
    let recipient = recipient_key::decode_fact_payload(&recipient_fact.bytes)?;
    if recipient.workspace_id != wrap.workspace_id {
        return Err("key wrap recipient key workspace does not match wrap".to_string());
    }
    let frontier_fact = frontier_fact.expect("checked");
    if frontier_fact.id != wrap.frontier_id {
        return Err("key wrap frontier context payload id mismatch".to_string());
    }
    let frontier = removal_frontier::decode_fact_payload(&frontier_fact.bytes)?;
    if frontier.workspace_id != wrap.workspace_id {
        return Err("key wrap removal frontier workspace does not match wrap".to_string());
    }
    if frontier.owner_endpoint_id != wrap.signer_endpoint_id {
        return Err("key wrap signer does not own removal frontier".to_string());
    }
    let context_have = context_have_from_needs(
        projection_context,
        [&signer_need, &recipient_need, &frontier_need],
    );

    // 3. Materialize: write the accepted wrap row and emit local recovery facts.
    let mut materialized_output = ProjectionOutput::new();
    if local_recipient_fact.is_none() {
        materialized_output = materialized_output.need(local_recipient_need.clone());
    }
    output = share_fact_with_sync(
        materialized_output
            .row_mutation(RowMutation::InsertValues(key_wrap_insert(KeyWrapRow {
                key_wrap_id: fact.id,
                signer_public_key,
                wrap: wrap.clone(),
            })?))
            .offer(ContextOffer::range(
                fact.id,
                "sync_exact_fact",
                scope.clone(),
                fact.id,
                fact.id,
            ))
            .offer(ContextOffer::range(
                fact.id,
                "sync_key_wrap",
                scope,
                fact.id,
                fact.id,
            )),
        wrap.workspace_id,
        fact,
        context_have,
    );

    if let Some(local_recipient_fact) = local_recipient_fact {
        if local_recipient_fact.scope != FactScope::Local {
            return Err("key wrap local recipient context is not local".to_string());
        }
        let local = crate::protocol::auth::local_recipient_key::decode_fact_payload(
            &local_recipient_fact.bytes,
        )?;
        if local.workspace_id != wrap.workspace_id {
            return Err("key wrap local recipient workspace does not match wrap".to_string());
        }
        if local.recipient_key_id != wrap.recipient_key_id {
            return Err("key wrap local recipient key id does not match wrap".to_string());
        }
        if local.recipient_key != recipient.recipient_key {
            return Err("key wrap local recipient public key does not match recipient".to_string());
        }
        output = output.fact(key_wrap_recovery_fact(
            wrap.workspace_id,
            wrap.frontier_id,
            wrap.recipient_key_id,
            fact.id,
            local_recipient_fact.id,
            fact.timestamp,
        )?);
    }

    Ok(output)
}

// ---------------------------------------------------------------------------
// Tests.
// Invariants:
// - key_wrap facts live in their workspace scope, never global or local scope;
// - projection waits on the signer endpoint, recipient key, removal frontier,
//   and local recipient key named by the wrap;
// - before required context exists, projection emits no accepted row, sync
//   offer, or local recovery fact.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::core::project_fact::Projector;
    use crate::protocol::auth::key_wrap::fact::{WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES};

    #[test]
    fn key_wrap_waits_for_exact_signer_recipient_frontier_and_local_recipient_context() {
        let wrap = sample_wrap();
        let fact = wrap_fact(
            wrap.clone(),
            crate::protocol::auth::workspace::scope(wrap.workspace_id),
        );
        let scope = crate::protocol::auth::workspace::scope(wrap.workspace_id);

        let output = KeyWrapProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project without context");

        assert_eq!(output.needs.len(), 4);
        assert!(output.needs.contains(&ContextNeed::range(
            fact.id,
            "content_signer",
            scope.clone(),
            wrap.signer_endpoint_id,
            wrap.signer_endpoint_id,
        )));
        assert!(output.needs.contains(&ContextNeed::range(
            fact.id,
            "recipient_key",
            scope.clone(),
            wrap.recipient_key_id,
            wrap.recipient_key_id,
        )));
        assert!(output.needs.contains(&ContextNeed::range(
            fact.id,
            "auth_removal_frontier",
            scope.clone(),
            wrap.frontier_id,
            wrap.frontier_id,
        )));
        assert!(output.needs.contains(&ContextNeed::range(
            fact.id,
            "local_recipient_key",
            scope,
            wrap.recipient_key_id,
            wrap.recipient_key_id,
        )));
        assert!(output.offers.is_empty());
        assert!(output.effects.row_mutations.is_empty());
        assert!(output.effects.facts.is_empty());
    }

    #[test]
    fn key_wrap_projection_rejects_scope_that_does_not_match_workspace() {
        let wrap = sample_wrap();
        let wrong_scope = crate::protocol::auth::workspace::scope([9; 32]);
        let fact = wrap_fact(wrap, wrong_scope);

        let err = KeyWrapProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("wrong scope should reject");

        assert!(err.contains("scope"), "{err}");
    }

    fn sample_wrap() -> KeyWrapFact {
        KeyWrapFact {
            workspace_id: [1; 32],
            created_at_ms: 50,
            signer_endpoint_id: [2; 32],
            frontier_id: [3; 32],
            wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
            wrapped_secret_id: [4; 32],
            wrapped_source_secret_id: [0; 32],
            wrapped_tombstone_node_id: [0; 32],
            range_start: 0,
            range_width: 0,
            bit_depth: 0,
            fact_id_prefix: [0; 32],
            recipient_key_id: [6; 32],
            sender_wrap_public_key: [7; 32],
            nonce: [8; 24],
            ciphertext: [9; KEY_WRAP_CIPHERTEXT_BYTES],
        }
    }

    fn wrap_fact(wrap: KeyWrapFact, scope: FactScope) -> Fact {
        Fact::new(
            scope,
            wrap.created_at_ms,
            crate::protocol::auth::key_wrap::encode::encode_key_wrap(&wrap).expect("encode wrap"),
        )
    }
}

// ---------------------------------------------------------------------------
// Tests. Ordered most-central-first by how much wrap-source matching each proves.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod wrap_source_tests {
    use super::*;
    use crate::protocol::auth::workspace::scope;

    #[test]
    fn wrap_source_validates_requested_frontier_only() {
        let scope = scope([1; 32]);
        let need = requested_wrap_source_need([2; 32], scope.clone(), [1; 32], [3; 32]);
        let matching =
            frontier_root_wrap_source_offers([4; 32], scope.clone(), [1; 32], [3; 32], [5; 32], 50);
        let other_frontier =
            frontier_root_wrap_source_offers([6; 32], scope, [1; 32], [7; 32], [5; 32], 50);

        assert!(matching
            .iter()
            .any(|offer| wrap_source_offer_valid_for_need(&need, offer).is_some()));
        assert!(!other_frontier
            .iter()
            .any(|offer| wrap_source_offer_valid_for_need(&need, offer).is_some()));
    }

    #[test]
    fn wrap_source_validates_proactive_minimum_creation_time() {
        let scope = scope([1; 32]);
        let need = proactive_wrap_source_need([2; 32], scope.clone(), [1; 32], 50);
        let old =
            frontier_root_wrap_source_offers([3; 32], scope.clone(), [1; 32], [4; 32], [5; 32], 49);
        let new = frontier_root_wrap_source_offers([6; 32], scope, [1; 32], [7; 32], [8; 32], 50);

        assert!(!old
            .iter()
            .any(|offer| wrap_source_offer_valid_for_need(&need, offer).is_some()));
        assert!(new
            .iter()
            .any(|offer| wrap_source_offer_valid_for_need(&need, offer).is_some()));
    }
}
