//! Project stage contracts and staged runners.

use super::adapt::Adapter;
use super::authenticate::{AuthenticatedFact, Authentication, Authenticator, DecodedAuthenticator};
use super::context::ProjectionContext;
use super::decode::FactCodec;
use super::effects::ProjectionOutput;
use crate::core::facts::Fact;

/// Projector implementation after core has authenticated the input fact.
///
/// The body begins at the CONTEXT section: authority and relationship proofs,
/// deletion, retention, and materialization. Primary decoding and authentication
/// already happened in the family authenticator, so the projector never parses
/// or verifies its own primary bytes.
pub trait AuthenticatedProjector<A: Authenticator> {
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, A::Authenticated>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String>;
}

/// Projector body for the first-class staged read pipeline.
///
/// Implementations receive the semantic value after decode, authentication, and
/// adaptation. They own scope/context proof, authority, rows, needs/offers,
/// time wakes, intents, emitted facts, and purge.
pub trait SemanticProjector<T> {
    fn project_semantic(
        &self,
        fact: &Fact,
        semantic: T,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String>;
}

/// Authenticate a fact through `A`, then project it.
///
/// `NeedsAuthentication` becomes a standing context need so core re-runs this
/// path once the crypto context appears; the projector does not run until the
/// fact authenticates. `Invalid` rejects the fact through the same error path a
/// failed `verify_signature` takes today.
pub fn project_authenticated<A, P>(
    projector: &P,
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String>
where
    A: Authenticator,
    P: AuthenticatedProjector<A>,
{
    match A::authenticate(fact, context) {
        Authentication::Authenticated(authenticated) => {
            projector.project_authenticated(authenticated, context)
        }
        Authentication::NeedsAuthentication(need) => Ok(ProjectionOutput::new().need(need)),
        Authentication::Invalid(error) => Err(error),
    }
}

/// Decode, authenticate, adapt, then project through first-class stages.
///
/// Converted route functions should call this helper. It preserves the legacy
/// parking/rejection behavior while making every stage explicit in
/// `FactRoute.pipeline`.
pub fn project_staged<C, A, Ad, P>(
    projector: &P,
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String>
where
    C: FactCodec,
    A: DecodedAuthenticator<C>,
    Ad: Adapter<Source = A::Authenticated>,
    P: SemanticProjector<Ad::Semantic>,
{
    let decoded = C::decode_fact(fact)?;
    match A::authenticate_decoded(fact, decoded, context) {
        Authentication::Authenticated(authenticated) => {
            let (fact_ref, source) = authenticated.into_parts();
            let semantic = Ad::adapt(source)?;
            projector.project_semantic(fact_ref, semantic, context)
        }
        Authentication::NeedsAuthentication(need) => Ok(ProjectionOutput::new().need(need)),
        Authentication::Invalid(error) => Err(error),
    }
}
