//! Project stage contracts and staged runners.

use super::adapt::Adapter;
use super::authenticate::{Authentication, DecodedAuthenticator};
use super::context::ProjectionContext;
use super::decode::FactCodec;
use super::effects::ProjectionOutput;
use crate::core::facts::Fact;

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

/// Decode, authenticate, adapt, then project through first-class stages.
///
/// Every converted route function calls this helper, making each stage explicit
/// in `FactRoute.pipeline`. `NeedsAuthentication` becomes a standing context
/// need so core re-runs the route once the crypto context appears; `Invalid`
/// rejects the fact.
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
        Authentication::NeedsAuthentication(needs) => {
            let mut output = ProjectionOutput::new();
            for need in needs {
                output = output.need(need);
            }
            Ok(output)
        }
        Authentication::Invalid(error) => Err(error),
    }
}
