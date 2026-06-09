use crate::core::context::{ContextKeyPart, ContextNeed, ContextOffer};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::content;
use crate::protocol::sync::shared_fact::project::share_fact_with_sync;

use super::fact::{RootFact, RootRef};

pub const ROOT_ENVELOPE_ROLE: &str = "root_envelope";
pub const ROOT_REF_ROLE: &str = "root_ref";

pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "root::decode::Codec",
    authenticate: "root::authenticate::RootAuthenticator",
    adapt: "root::adapt::RootAdapter",
    project: "root::project::RootProjector",
};

#[derive(Debug, Clone, Default)]
pub struct RootProjector;

impl RootProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for RootProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::RootAuthenticator,
            super::adapt::RootAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<RootFact> for RootProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        root: RootFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let mut output = root_context_output(fact, &root)?;

        if let Some(workspace_id) = root.workspace_id() {
            let workspace_scope = crate::protocol::auth::workspace::scope(workspace_id);
            if fact.scope != workspace_scope {
                return Err("root fact scope does not match workspace ref".to_string());
            }
        }

        if root.family == content::message::ROOT_FAMILY_CONTENT_MESSAGE {
            return content::message::project::project_root_message(fact, &root, context, output);
        }

        if let Some(workspace_id) = root.workspace_id() {
            let context_have = root
                .refs
                .iter()
                .map(|edge| edge.target_fact_id)
                .collect::<Vec<_>>();
            output = share_fact_with_sync(output, workspace_id, fact, context_have);
        }

        Ok(output)
    }
}

fn root_context_output(fact: &Fact, root: &RootFact) -> Result<ProjectionOutput, String> {
    let mut output = ProjectionOutput::new().offer(root_envelope_offer(
        fact.id,
        fact.scope.clone(),
        fact.id,
        root.family,
        root.version,
    )?);

    for edge in &root.refs {
        output = output.offer(root_ref_offer(fact.id, fact.scope.clone(), fact.id, *edge)?);
    }

    Ok(output)
}

pub fn root_envelope_need(
    owner: FactId,
    scope: FactScope,
    root_id: FactId,
    family: u32,
    version: u32,
) -> Result<ContextNeed, String> {
    ContextNeed::for_key_parts(
        owner,
        ROOT_ENVELOPE_ROLE,
        scope,
        [
            ContextKeyPart::bytes(&root_id),
            ContextKeyPart::u64(u64::from(family)),
            ContextKeyPart::u64(u64::from(version)),
        ],
    )
}

pub fn root_envelope_offer(
    owner: FactId,
    scope: FactScope,
    root_id: FactId,
    family: u32,
    version: u32,
) -> Result<ContextOffer, String> {
    ContextOffer::for_key_parts(
        owner,
        ROOT_ENVELOPE_ROLE,
        scope,
        [
            ContextKeyPart::bytes(&root_id),
            ContextKeyPart::u64(u64::from(family)),
            ContextKeyPart::u64(u64::from(version)),
        ],
    )
}

pub fn root_ref_offer(
    owner: FactId,
    scope: FactScope,
    root_id: FactId,
    edge: RootRef,
) -> Result<ContextOffer, String> {
    ContextOffer::for_key_parts(
        owner,
        ROOT_REF_ROLE,
        scope,
        [
            ContextKeyPart::bytes(&root_id),
            ContextKeyPart::u64(u64::from(edge.role)),
            ContextKeyPart::u64(u64::from(edge.index)),
            ContextKeyPart::bytes(&edge.target_fact_id),
        ],
    )
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::{ProjectionContext, Projector};

    use super::*;

    #[test]
    fn root_projects_envelope_and_ref_offers() {
        let root = RootFact {
            family: 99,
            version: 1,
            created_at_ms: 0,
            refs: vec![
                RootRef::new(crate::protocol::root::roles::WORKSPACE, 0, [1; 32]).unwrap(),
                RootRef::new(crate::protocol::root::roles::CONTENT, 0, [2; 32]).unwrap(),
            ],
        };
        let fact = Fact::new(
            crate::protocol::auth::workspace::scope([1; 32]),
            0,
            crate::protocol::root::encode::encode_fact(&root).expect("encode root"),
        );

        let output = RootProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project root");

        assert!(output.needs.is_empty());
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == ROOT_ENVELOPE_ROLE));
        assert_eq!(
            output
                .offers
                .iter()
                .filter(|offer| offer.role == ROOT_REF_ROLE)
                .count(),
            2
        );
        assert_eq!(output.effects.intents.len(), 1);
    }

    #[test]
    fn root_rejects_scope_that_disagrees_with_workspace_ref() {
        let root = RootFact {
            family: 1,
            version: 1,
            created_at_ms: 0,
            refs: vec![RootRef::new(crate::protocol::root::roles::WORKSPACE, 0, [1; 32]).unwrap()],
        };
        let fact = Fact::new(
            FactScope::Global,
            0,
            crate::protocol::root::encode::encode_fact(&root).expect("encode root"),
        );

        assert!(RootProjector::new()
            .project(&fact, &ProjectionContext::default())
            .is_err());
    }
}
