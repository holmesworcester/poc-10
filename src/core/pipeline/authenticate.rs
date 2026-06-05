//! Authentication contracts for fact pipeline stages.

use super::context::ProjectionContext;
use super::decode::FactCodec;
use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};

// ----- Fact authentication: the pre-projection layer -----
//
// An authenticator turns one fact's primary bytes into an `AuthenticatedFact`:
// it proves the bytes are canonical for the family and cryptographically
// authentic at the fact boundary, nothing more. It is not a validity check.
// Authority, relationships, deletion, retention, and materialization stay in
// the projector, which begins where the authenticator leaves off. See
// `docs/research/fact-validators.md`.

/// A decoded fact whose primary bytes are proven canonical and authentic.
///
/// Only a family `DecodedAuthenticator` constructs this value, so holding one is
/// the proof: the content id matches `hash(bytes)`, and any fact-boundary signature
/// or container envelope verified. It is an in-memory view — not a new signed
/// fact — that borrows the source fact and owns its decoded payload. A projector
/// reads the payload and the source fact through it and never touches raw bytes.
pub struct AuthenticatedFact<'a, T> {
    fact: &'a Fact,
    payload: T,
}

impl<'a, T> AuthenticatedFact<'a, T> {
    /// Wrap a decoded payload as authenticated.
    ///
    /// Call this only after the family authenticator has proven canonical bytes
    /// and fact-boundary authenticity; constructing it asserts that proof.
    pub fn new(fact: &'a Fact, payload: T) -> Self {
        Self { fact, payload }
    }

    /// Content id of the authenticated fact.
    pub fn id(&self) -> FactId {
        self.fact.id
    }

    /// Admission scope of the source fact.
    pub fn scope(&self) -> &FactScope {
        &self.fact.scope
    }

    /// The source fact, for sync sharing and id-owned context.
    pub fn fact(&self) -> &Fact {
        self.fact
    }

    /// The decoded, authenticated payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Split into the borrowed source fact and the owned payload.
    ///
    /// The fact reference keeps the original borrow, so a projector can bind
    /// `let (fact, payload) = authenticated.into_parts();` and read both.
    pub fn into_parts(self) -> (&'a Fact, T) {
        (self.fact, self.payload)
    }
}

/// Outcome of authenticating one fact's primary bytes.
///
/// `NeedsAuthentication` carries the narrow cryptographic context the
/// authenticator is waiting on — a verifier key, or a connection/endpoint
/// secret needed to prove or open this fact boundary. It is not an authority
/// proof and is a distinct concern from the projector's normal context needs,
/// even though core schedules both through the same standing-need machinery.
pub enum Authentication<'a, T> {
    Authenticated(AuthenticatedFact<'a, T>),
    NeedsAuthentication(Vec<ContextNeed>),
    Invalid(String),
}

impl<'a, T> Authentication<'a, T> {
    /// Map a context-free authentication result into an outcome.
    ///
    /// The common case: an authenticator that needs no external key can run its
    /// numbered checks with `?` and hand the `Result` here — `Ok` authenticates,
    /// `Err` rejects. Authenticators that park on a verifier key build the
    /// `NeedsAuthentication` arm directly instead.
    pub fn from_result(fact: &'a Fact, result: Result<T, String>) -> Self {
        match result {
            Ok(payload) => Authentication::Authenticated(AuthenticatedFact::new(fact, payload)),
            Err(error) => Authentication::Invalid(error),
        }
    }

    /// Park authentication on one context need.
    pub fn need(need: ContextNeed) -> Self {
        Authentication::NeedsAuthentication(vec![need])
    }

    /// Park authentication on several alternate or cumulative context needs.
    pub fn needs(needs: impl IntoIterator<Item = ContextNeed>) -> Self {
        Authentication::NeedsAuthentication(needs.into_iter().collect())
    }
}

/// Family authenticator for the first-class staged read pipeline.
///
/// The fact's owning codec decodes raw bytes first. The authenticator receives
/// that decoded source value and owns id checks, fact-boundary cryptographic
/// proof, verifier-key parking, and intrinsic single-fact rules. It does not
/// materialize rows or inspect semantic context.
pub trait DecodedAuthenticator<C: FactCodec> {
    type Authenticated;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        decoded: C::Payload,
        context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated>;
}
/// Self-check a freshly authored fact against its own staged authenticator.
///
/// The write pipeline's exit gate mirrors the read pipeline's entry gate:
/// authored bytes must decode through the family `Codec` and be acceptable to
/// the family `DecodedAuthenticator` before they are admitted.
/// `NeedsAuthentication` is accepted because some valid facts require verifier
/// context that is not available at authoring time; `Invalid` means the
/// author/encode/signing drifted and must not be submitted.
pub fn authenticate_authored<C, A>(fact: &Fact) -> Result<(), String>
where
    C: FactCodec,
    A: DecodedAuthenticator<C>,
{
    let decoded = C::decode_fact(fact)?;
    match A::authenticate_decoded(fact, decoded, &ProjectionContext::default()) {
        Authentication::Authenticated(_) | Authentication::NeedsAuthentication(_) => Ok(()),
        Authentication::Invalid(error) => Err(error),
    }
}

/// Check a fact's content id against its own bytes.
///
/// Core constructs every `Fact` with `id = fact_id(bytes)`, so this normally
/// holds. An authenticator re-checks it anyway so authentication is a
/// self-contained proof over raw bytes — the property fuzzing relies on.
pub fn verify_fact_id(fact: &Fact) -> Result<(), String> {
    if fact.id == crate::core::facts::fact_id(&fact.bytes) {
        Ok(())
    } else {
        Err("fact id does not match fact bytes".to_string())
    }
}
