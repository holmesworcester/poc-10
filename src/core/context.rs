//! Public context vocabulary used by fact projection.
//!
//! This file intentionally contains only types and pure helpers. The SQLite
//! tables, overlap queries, pending wake rows, and commit rules live in
//! `project_fact.rs`. Projectors use these types to say "this fact still needs
//! matching payload from another fact" (`ContextNeed`) or "this fact can satisfy
//! matching needs" (`ContextOffer`) without importing SQL or queue machinery.
//!
//! `context.rs` stays separate from `project_fact.rs` because the types are the
//! public language shared by protocol projectors and the projection runner.
//! Keeping that language small and store-free lets fact modules construct and
//! test context edges without depending on the projection transaction
//! implementation. `project_fact.rs` remains responsible for querying,
//! matching, waking, and committing those edges.
//!
//! Context is the durable dependency surface between projectors; it is not a
//! hidden dependency loader or a second projection queue. A projector emits the
//! needs and offers it owns, and `project_fact.rs` records newly satisfiable
//! range overlaps. The semantic meaning of a role or byte range stays with the
//! projector that created it and with the projector that later validates the
//! matched payload.
//!
//! Every context edge has a key interval:
//!
//! ```text
//! owner, role, scope, start_key, end_key
//! ```
//!
//! `role` and `scope` partition the search space. `start_key` and `end_key` are
//! inclusive opaque byte endpoints inside that partition. Exact dependencies
//! should use `ContextNeed::for_key` and `ContextOffer::for_key`; those
//! constructors store the same key as both endpoints so the exact relationship
//! remains compatible with true range matches. Composite exact dependencies can
//! use `for_key_parts` to build one bounded canonical key. Broader dependencies
//! use `range` and choose an order-preserving byte layout in the protocol domain
//! so ordinary lexicographic range overlap is enough to find matching offers.
//!
//! Core's only matching rule is:
//!
//! ```text
//! need.role == offer.role
//! need.scope == offer.scope
//! need.start_key <= offer.end_key
//! offer.start_key <= need.end_key
//! ```
//!
//! Core never parses range bytes. It stores them, indexes them, performs the
//! overlap query, wakes affected owners, and loads the offer owner's fact as
//! matched payload. The woken projector must still decode and validate the
//! matched payload before emitting rows, offers, or intents.
//!
//! `owner` says which fact produced the row so later projection can replace
//! that fact's context without deleting anyone else's rows. For needs, `owner`
//! is the fact that should be reprojected. For offers, `owner` is also the
//! payload fact core loads when the offer overlaps a need.
//!
//! Needs and offers have different lifecycles. Needs are replacement
//! subscriptions: when a fact projects, it emits the complete current set of
//! dependencies it still wants to hear about. Offers are append-only evidence:
//! once a durable fact offers context, that offer remains until the fact is
//! purged. Core wakes only genuinely new need/offer matches and avoids
//! self-waking loops when stable unmet needs are re-emitted.

use crate::core::facts::{FactId, FactScope};
use crate::core::wire::Writer;
use std::collections::BTreeSet;

/// Maximum encoded size for a core-built canonical context key.
pub const CONTEXT_KEY_MAX_BYTES: usize = 512;
const CONTEXT_KEY_MAX_PARTS: usize = 32;
const CONTEXT_KEY_TUPLE_V1: u8 = 1;
const CONTEXT_KEY_PART_BYTES: u8 = 1;
const CONTEXT_KEY_PART_U64: u8 = 2;

// =============================================================================
// Public Vocabulary
// =============================================================================

/// Protocol-defined relationship role used for context matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Role(String);

impl Role {
    /// Roles are protocol identifiers, not free-form labels.
    ///
    /// The lowercase ASCII shape keeps persisted rows stable across languages
    /// and makes accidental UI strings or Rust type names fail early.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("context role cannot be empty".to_string());
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid context role {value:?}"));
        }
        Ok(Self(value))
    }

    pub fn expect(value: &'static str) -> Self {
        Self::new(value).expect("valid context role")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&'static str> for Role {
    fn from(value: &'static str) -> Self {
        Self::expect(value)
    }
}

impl PartialEq<&str> for Role {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<Role> for &str {
    fn eq(&self, other: &Role) -> bool {
        *self == other.as_str()
    }
}

/// Opaque byte key within a context role and scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextKey(Vec<u8>);

/// One part of a core-built canonical context key.
///
/// This is syntax only. Protocol projectors still choose which fields belong in
/// a key and validate any matched payload semantically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextKeyPart<'a> {
    Bytes(&'a [u8]),
    U64(u64),
}

impl<'a> ContextKeyPart<'a> {
    pub fn bytes(bytes: &'a [u8]) -> Self {
        Self::Bytes(bytes)
    }

    pub fn u64(value: u64) -> Self {
        Self::U64(value)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for ContextKeyPart<'a> {
    fn from(value: &'a [u8; N]) -> Self {
        Self::Bytes(value)
    }
}

impl<'a> From<&'a [u8]> for ContextKeyPart<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Bytes(value)
    }
}

impl<'a> From<u64> for ContextKeyPart<'a> {
    fn from(value: u64) -> Self {
        Self::U64(value)
    }
}

impl ContextKey {
    /// Build an opaque key or range endpoint owned by one fact module.
    ///
    /// Core stores, sorts, and compares these bytes, but never parses them.
    /// Protocol code chooses a canonical byte layout and validates the matched
    /// payload before giving the match any semantic authority.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Build a bounded canonical key from typed parts.
    ///
    /// Use this for exact or composite-key dependencies where the complete tuple
    /// is one key. Domain-specific range helpers should still build their own
    /// low/high endpoints when byte ordering matters.
    pub fn from_parts<'a, I, P>(parts: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = P>,
        P: Into<ContextKeyPart<'a>>,
    {
        let mut bytes = vec![CONTEXT_KEY_TUPLE_V1];
        let mut count = 0usize;
        for part in parts {
            count += 1;
            if count > CONTEXT_KEY_MAX_PARTS {
                return Err(format!(
                    "context key has more than {CONTEXT_KEY_MAX_PARTS} parts"
                ));
            }
            append_context_key_part(&mut bytes, part.into())?;
            if bytes.len() > CONTEXT_KEY_MAX_BYTES {
                return Err(format!("context key exceeds {CONTEXT_KEY_MAX_BYTES} bytes"));
            }
        }
        if count == 0 {
            return Err("context key must contain at least one part".to_string());
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A standing request by one fact for matching context.
///
/// The need's `owner` is the fact that should be woken when a compatible offer
/// appears. A need is not inherently blocking: the owning projector decides on
/// each run whether missing context means "wait", "project a partial result",
/// or "stop needing this context".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextNeed {
    /// Fact to wake when a compatible offer appears.
    pub owner: FactId,
    /// Matching role.
    pub role: Role,
    /// Matching scope.
    pub scope: FactScope,
    /// Inclusive start of the opaque byte range this need asks for.
    pub start_key: ContextKey,
    /// Inclusive end of the opaque byte range this need asks for.
    pub end_key: ContextKey,
}

impl ContextNeed {
    /// Build an exact-key need.
    ///
    /// Exact needs are stored with identical start/end keys. They match exact
    /// offers with the same key and true range offers that cover this key.
    pub fn for_key(
        owner: FactId,
        role: impl Into<Role>,
        scope: FactScope,
        key: impl Into<Vec<u8>>,
    ) -> Self {
        let key = ContextKey::from_bytes(key);
        Self {
            owner,
            role: role.into(),
            scope,
            start_key: key.clone(),
            end_key: key,
        }
    }

    /// Build an exact-key need from bounded canonical key parts.
    ///
    /// Use this when multiple protocol fields together form one exact lookup
    /// key. Use `range` only when the owner intentionally wants every matching
    /// offer in a byte interval.
    pub fn for_key_parts<'a, I, P>(
        owner: FactId,
        role: impl Into<Role>,
        scope: FactScope,
        parts: I,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = P>,
        P: Into<ContextKeyPart<'a>>,
    {
        let key = ContextKey::from_parts(parts)?;
        Ok(Self {
            owner,
            role: role.into(),
            scope,
            start_key: key.clone(),
            end_key: key,
        })
    }

    /// Build a true range need with inclusive byte endpoints.
    ///
    /// Ranges can match many offers. Prefer `for_key` or `for_key_parts` for
    /// ordinary fact-id or composite-key dependencies.
    pub fn range(
        owner: FactId,
        role: impl Into<Role>,
        scope: FactScope,
        start_key: impl Into<Vec<u8>>,
        end_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            owner,
            role: role.into(),
            scope,
            start_key: ContextKey::from_bytes(start_key),
            end_key: ContextKey::from_bytes(end_key),
        }
    }
}

/// A standing statement that one fact can provide context to matching needs.
///
/// The offer's `owner` is the fact that emitted this relationship and the fact
/// core should load and pass to the woken projector when this offer matches.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextOffer {
    /// Fact that emitted the offer and provides the payload.
    pub owner: FactId,
    /// Matching role.
    pub role: Role,
    /// Matching scope.
    pub scope: FactScope,
    /// Inclusive start of the opaque byte range this offer provides.
    pub start_key: ContextKey,
    /// Inclusive end of the opaque byte range this offer provides.
    pub end_key: ContextKey,
}

impl ContextOffer {
    /// Build an exact-key offer.
    ///
    /// Exact offers are stored with identical start/end keys. They satisfy exact
    /// needs for the same key and true range needs that cover this key.
    pub fn for_key(
        owner: FactId,
        role: impl Into<Role>,
        scope: FactScope,
        key: impl Into<Vec<u8>>,
    ) -> Self {
        let key = ContextKey::from_bytes(key);
        Self {
            owner,
            role: role.into(),
            scope,
            start_key: key.clone(),
            end_key: key,
        }
    }

    /// Build an exact-key offer from bounded canonical key parts.
    ///
    /// Use this when multiple protocol fields together form one exact lookup
    /// key. Use `range` only when the owner intentionally offers a byte interval.
    pub fn for_key_parts<'a, I, P>(
        owner: FactId,
        role: impl Into<Role>,
        scope: FactScope,
        parts: I,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = P>,
        P: Into<ContextKeyPart<'a>>,
    {
        let key = ContextKey::from_parts(parts)?;
        Ok(Self {
            owner,
            role: role.into(),
            scope,
            start_key: key.clone(),
            end_key: key,
        })
    }

    /// Build a true range offer with inclusive byte endpoints.
    ///
    /// Ranges can satisfy many needs. Prefer `for_key` or `for_key_parts` for
    /// ordinary fact-id or composite-key context.
    pub fn range(
        owner: FactId,
        role: impl Into<Role>,
        scope: FactScope,
        start_key: impl Into<Vec<u8>>,
        end_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            owner,
            role: role.into(),
            scope,
            start_key: ContextKey::from_bytes(start_key),
            end_key: ContextKey::from_bytes(end_key),
        }
    }
}

/// An ownerless offer emitted by a projector before core attaches the fact id.
///
/// Projectors describe the role, scope, and key range they provide. Core turns
/// the claim into a stored [`ContextOffer`] with `owner = projected_fact.id`
/// during projection preparation, so projector code cannot choose the stored
/// offer owner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextOfferClaim {
    /// Matching role.
    pub role: Role,
    /// Matching scope.
    pub scope: FactScope,
    /// Inclusive start of the opaque byte range this offer provides.
    pub start_key: ContextKey,
    /// Inclusive end of the opaque byte range this offer provides.
    pub end_key: ContextKey,
}

impl ContextOfferClaim {
    /// Build an exact-key offer claim.
    pub fn for_key(role: impl Into<Role>, scope: FactScope, key: impl Into<Vec<u8>>) -> Self {
        let key = ContextKey::from_bytes(key);
        Self {
            role: role.into(),
            scope,
            start_key: key.clone(),
            end_key: key,
        }
    }

    /// Build an exact-key offer claim from bounded canonical key parts.
    pub fn for_key_parts<'a, I, P>(
        role: impl Into<Role>,
        scope: FactScope,
        parts: I,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = P>,
        P: Into<ContextKeyPart<'a>>,
    {
        let key = ContextKey::from_parts(parts)?;
        Ok(Self {
            role: role.into(),
            scope,
            start_key: key.clone(),
            end_key: key,
        })
    }

    /// Build a true range offer claim with inclusive byte endpoints.
    pub fn range(
        role: impl Into<Role>,
        scope: FactScope,
        start_key: impl Into<Vec<u8>>,
        end_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            role: role.into(),
            scope,
            start_key: ContextKey::from_bytes(start_key),
            end_key: ContextKey::from_bytes(end_key),
        }
    }

    /// Attach the projected fact owner after core has validated projection.
    pub fn into_offer(self, owner: FactId) -> ContextOffer {
        ContextOffer {
            owner,
            role: self.role,
            scope: self.scope,
            start_key: self.start_key,
            end_key: self.end_key,
        }
    }
}

// =============================================================================
// Context Set API
// =============================================================================

/// The complete standing context emitted by a single projection owner.
///
/// Projection output replaces the previous set for that owner. This replacement
/// model is what prevents stable unmet needs from self-waking forever: only
/// added or removed relationships produce a delta for wake fanout to inspect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextSet {
    /// Standing needs owned by one fact.
    pub needs: Vec<ContextNeed>,
    /// Standing offers owned by one fact.
    pub offers: Vec<ContextOffer>,
}

impl ContextSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn need(mut self, need: ContextNeed) -> Self {
        self.needs.push(need);
        self
    }

    pub fn offer(mut self, offer: ContextOffer) -> Self {
        self.offers.push(offer);
        self
    }

    /// Sort and deduplicate needs and offers without interpreting them.
    pub fn normalized(self) -> Self {
        Self {
            needs: normalize_context_needs(self.needs),
            offers: normalize_context_offers(self.offers),
        }
    }
}

/// Relationships newly visible after replacing one owner's context set.
///
/// Wake fanout only cares about additions: new needs may match existing offers,
/// and new offers may match existing needs. Removed needs or offers never wake
/// another projection item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextSetAdditions {
    /// Needs newly visible after replacement.
    pub needs: Vec<ContextNeed>,
    /// Offers newly visible after replacement.
    pub offers: Vec<ContextOffer>,
}

impl ContextSetAdditions {
    pub fn is_empty(&self) -> bool {
        self.needs.is_empty() && self.offers.is_empty()
    }
}

// =============================================================================
// Storage-Facing Operations
// =============================================================================

/// Encode a fact scope into the stable bytes used by context match indexes.
pub(crate) fn scope_key(scope: &FactScope) -> Vec<u8> {
    let mut out = Writer::new();
    encode_scope(&mut out, scope);
    out.finish()
}

/// Return relationships in `next` that are not present in `previous`.
///
/// Projection commit uses this after every projection. Re-emitting the same need
/// or offer is a no-op; adding one exposes a new possible match to wake fanout.
pub fn context_set_additions(previous: &ContextSet, next: &ContextSet) -> ContextSetAdditions {
    ContextSetAdditions {
        needs: added_context_items(&previous.needs, &next.needs),
        offers: added_context_items(&previous.offers, &next.offers),
    }
}

// =============================================================================
// General Helpers
// =============================================================================

fn normalize_context_needs(needs: Vec<ContextNeed>) -> Vec<ContextNeed> {
    sort_and_deduplicate(needs)
}

fn normalize_context_offers(offers: Vec<ContextOffer>) -> Vec<ContextOffer> {
    sort_and_deduplicate(offers)
}

fn sort_and_deduplicate<T: Ord>(mut items: Vec<T>) -> Vec<T> {
    items.sort();
    items.dedup();
    items
}

fn added_context_items<T>(previous: &[T], next: &[T]) -> Vec<T>
where
    T: Ord + Clone,
{
    let previous = previous.iter().cloned().collect::<BTreeSet<_>>();
    let next = next.iter().cloned().collect::<BTreeSet<_>>();
    next.difference(&previous).cloned().collect()
}

fn append_context_key_part(bytes: &mut Vec<u8>, part: ContextKeyPart<'_>) -> Result<(), String> {
    match part {
        ContextKeyPart::Bytes(part) => {
            let len = u16::try_from(part.len())
                .map_err(|_| "context key byte part is too large".to_string())?;
            bytes.push(CONTEXT_KEY_PART_BYTES);
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(part);
        }
        ContextKeyPart::U64(value) => {
            bytes.push(CONTEXT_KEY_PART_U64);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    Ok(())
}

fn encode_scope(out: &mut Writer, scope: &FactScope) {
    match scope {
        FactScope::Global => out.u8(0),
        FactScope::Local => out.u8(1),
        FactScope::Scoped { kind, id } => {
            out.u8(2);
            out.string_u16be(kind.as_str())
                .expect("scope kind fits u16");
            out.fixed(id);
        }
    }
}

// =============================================================================
// Tests
// =============================================================================
// Ordered most-central-first: core context-delta proofs before narrow guards.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::FactScope;

    #[test]
    fn context_set_additions_reports_only_new_relationships() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let stable = ContextNeed {
            owner: id,
            role: role.clone(),
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([2; 32]),
            end_key: ContextKey::from_bytes([2; 32]),
        };
        let added = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([3; 32]),
            end_key: ContextKey::from_bytes([3; 32]),
        };

        let previous = ContextSet::new().need(stable.clone()).need(stable.clone());
        let next = ContextSet::new()
            .need(stable)
            .need(added.clone())
            .need(added.clone());
        let additions = context_set_additions(&previous, &next);

        assert_eq!(additions.needs, vec![added]);
        assert!(additions.offers.is_empty());
    }

    #[test]
    fn identical_context_sets_have_no_additions() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([2; 32]);
        let set = ContextSet::new()
            .need(ContextNeed {
                owner: id,
                role: role.clone(),
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key,
            })
            .normalized();

        assert!(context_set_additions(&set, &set).is_empty());
    }

    #[test]
    fn context_key_parts_encode_canonical_bounded_bytes() {
        let id = [1; 32];
        let key = ContextKey::from_parts([
            ContextKeyPart::from(&id),
            ContextKeyPart::u64(42),
            ContextKeyPart::bytes(b"constant".as_slice()),
        ])
        .expect("canonical key");
        let same = ContextKey::from_parts([
            ContextKeyPart::from(&id),
            ContextKeyPart::from(42u64),
            ContextKeyPart::from(b"constant".as_slice()),
        ])
        .expect("canonical key");

        assert_eq!(key, same);
        assert!(key.as_bytes().len() <= CONTEXT_KEY_MAX_BYTES);
        assert_eq!(key.as_bytes()[0], CONTEXT_KEY_TUPLE_V1);
    }

    #[test]
    fn key_part_need_and_offer_use_identical_endpoints() {
        let owner = [1; 32];
        let scope = FactScope::Global;
        let first = [2; 32];
        let second = [3; 32];
        let need = ContextNeed::for_key_parts(owner, "composite", scope.clone(), [&first, &second])
            .expect("need");
        let offer = ContextOffer::for_key_parts(owner, "composite", scope, [&first, &second])
            .expect("offer");

        assert_eq!(need.start_key, need.end_key);
        assert_eq!(offer.start_key, offer.end_key);
        assert_eq!(need.start_key, offer.start_key);
    }

    #[test]
    fn exact_key_need_and_offer_use_identical_endpoints() {
        let owner = [1; 32];
        let scope = FactScope::Global;
        let key = [2; 32];
        let need = ContextNeed::for_key(owner, "exact", scope.clone(), key);
        let offer = ContextOffer::for_key(owner, "exact", scope, key);

        assert_eq!(need.start_key, ContextKey::from_bytes(key));
        assert_eq!(need.start_key, need.end_key);
        assert_eq!(offer.start_key, offer.end_key);
        assert_eq!(need.start_key, offer.start_key);
    }

    #[test]
    fn normalized_context_set_sorts_and_deduplicates() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([2; 32]),
            end_key: ContextKey::from_bytes([2; 32]),
        };

        let set = ContextSet::new()
            .need(need.clone())
            .need(need.clone())
            .normalized();

        assert_eq!(set.needs, vec![need]);
    }

    #[test]
    fn context_set_builder_keeps_needs_and_offers_explicit() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([2; 32]);
        let set = ContextSet::new()
            .need(ContextNeed {
                owner: id,
                role: role.clone(),
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key,
            });

        assert_eq!(set.needs.len(), 1);
        assert_eq!(set.offers.len(), 1);
    }

    #[test]
    fn context_key_parts_reject_empty_oversized_and_too_many_parts() {
        assert!(ContextKey::from_parts(Vec::<ContextKeyPart<'_>>::new()).is_err());
        let oversized = vec![0; CONTEXT_KEY_MAX_BYTES];
        assert!(ContextKey::from_parts([ContextKeyPart::bytes(&oversized)]).is_err());
        let parts = [[0u8; 1]; CONTEXT_KEY_MAX_PARTS + 1];
        assert!(ContextKey::from_parts(parts.iter()).is_err());
    }

    #[test]
    fn role_rejects_broad_free_text() {
        assert!(Role::new("exact_fact").is_ok());
        assert!(Role::new("ExactFact").is_err());
        assert!(Role::new("exact-fact").is_err());
    }
}
