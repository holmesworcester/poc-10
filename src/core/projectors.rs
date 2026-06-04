//! Transitional re-export facade for the fact-processing pipeline.
//!
//! New code should import these contracts from `core::pipeline`. This module
//! remains during fact-by-fact cutover for existing protocol imports.

pub use crate::core::pipeline::{
    authenticate_authored, project_authenticated, project_staged, verify_fact_id, Adapter,
    AuthenticatedFact, AuthenticatedProjector, Authentication, Authenticator, DecodedAuthenticator,
    EffectiveTagFn, EnvelopeRoute, FactCodec, FactPipeline, FactRoute, MatchedContext,
    ProjectionContext, ProjectionOutput, Projector, ProjectorFn, RouterProjector,
    SemanticProjector, TimeRange, TimeWake, Timeline,
};
