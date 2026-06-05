//! Fact route selection for the read pipeline.

use super::context::ProjectionContext;
use super::effects::ProjectionOutput;
use crate::core::facts::Fact;

/// Function pointer used by static projector route tables.
pub type ProjectorFn = fn(&Fact, &ProjectionContext) -> Result<ProjectionOutput, String>;
/// Optional protocol-owned admission check for facts core is about to store.
pub type FactAdmissionFn = fn(&Fact) -> Result<(), String>;
/// Function that maps an envelope fact to its semantic fact tag.
pub type EffectiveTagFn = fn(&Fact) -> Result<u8, String>;

/// Human-readable stage declaration for a fact route.
///
/// Every route is staged: the registered route function calls core's first-class
/// decode, authenticate, adapt, and project runner, and records the role-file
/// labels a reviewer can open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactPipeline {
    /// Staged route: the registered route function calls core's first-class
    /// decode, authenticate, adapt, and project runner.
    Staged {
        decode: &'static str,
        authenticate: &'static str,
        adapt: &'static str,
        project: &'static str,
    },
}

impl FactPipeline {
    pub const fn is_staged(self) -> bool {
        matches!(self, Self::Staged { .. })
    }
}

/// Route from a fact tag to the projector that owns that tag.
#[derive(Debug, Clone, Copy)]
pub struct FactRoute {
    /// Effective fact tag routed to this projector function.
    pub tag: u8,
    pub projector: ProjectorFn,
    /// First-class stage labels for this route's read pipeline.
    pub pipeline: FactPipeline,
    /// Whether a from-scratch replay re-projects this fact type. `true` for
    /// durable protocol truth (membership, content, keys, learned addresses)
    /// that must rebuild deterministically. `false` for durable facts whose
    /// projection materializes live session state — connection requests and the
    /// connection itself — which a rebuild must not resurrect: the fact is kept
    /// on disk but replay skips it, so its session rows are wiped and not
    /// rebuilt. This is the projector-route analog of a handler route's
    /// `runs_during_replay`.
    pub replayed: bool,
}

/// The protocol-facing projection entry point.
///
/// Every family declares `FactPipeline::Staged` in its route and implements
/// `project` through `project_staged`, so route metadata and direct projector
/// calls expose the same decode/authenticate/adapt/project stages.
pub trait Projector {
    fn project(&self, fact: &Fact, context: &ProjectionContext)
        -> Result<ProjectionOutput, String>;
}

/// Route for envelope facts whose outer tag is not the semantic fact tag.
#[derive(Debug, Clone, Copy)]
pub struct EnvelopeRoute {
    /// Outer fact tag identifying the envelope layout.
    pub outer_tag: u8,
    /// Function that reads the envelope enough to choose the semantic route.
    pub effective_tag: EffectiveTagFn,
}

/// Tag router used by protocol registries.
///
/// Core reads only the first byte and any protocol-supplied envelope tag
/// function. It does not know what a tag means beyond selecting the registered
/// projector function.
#[derive(Debug, Clone, Copy)]
pub struct RouterProjector {
    routes: &'static [FactRoute],
    envelopes: &'static [EnvelopeRoute],
}

impl RouterProjector {
    pub const fn new(routes: &'static [FactRoute], envelopes: &'static [EnvelopeRoute]) -> Self {
        Self { routes, envelopes }
    }

    fn effective_tag(&self, fact: &Fact) -> Result<u8, String> {
        let Some(tag) = fact.bytes.first().copied() else {
            return Err("cannot project empty fact bytes".to_string());
        };
        if let Some(envelope) = self
            .envelopes
            .iter()
            .find(|envelope| envelope.outer_tag == tag)
        {
            return (envelope.effective_tag)(fact);
        }
        Ok(tag)
    }
}

impl Projector for RouterProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let tag = self.effective_tag(fact)?;
        let Some(route) = self.routes.iter().find(|route| route.tag == tag) else {
            return Err(format!("no target projector registered for fact tag {tag}"));
        };
        (route.projector)(fact, context)
    }
}
