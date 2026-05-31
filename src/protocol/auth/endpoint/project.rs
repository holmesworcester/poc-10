//! Poc-10 local endpoint projector.
//!
//! POLICY. A local endpoint fact is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and endpoint layout re-derives both
//!      public keys from the stored private keys.
//!   2. CONTEXT. No remote context is accepted; this is local identity secret
//!      material.
//!   3. MATERIALIZE. Write the four local endpoint rows for public/secret and
//!      signing public/secret material, and publish local endpoint context keyed
//!      by the endpoint id for bootstrap receive projection.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use super::rows::endpoint_rows;

const DAEMON_ENDPOINT_ROLE: &str = "auth_daemon_endpoint";
const DAEMON_ENDPOINT_KEY: &[u8] = b"daemon_endpoint";

pub fn daemon_endpoint_need(
    owner: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        DAEMON_ENDPOINT_ROLE,
        crate::core::facts::FactScope::Local,
        DAEMON_ENDPOINT_KEY,
        DAEMON_ENDPOINT_KEY,
    )
}

pub fn daemon_endpoint_offer(
    owner: crate::core::facts::FactId,
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        DAEMON_ENDPOINT_ROLE,
        crate::core::facts::FactScope::Local,
        DAEMON_ENDPOINT_KEY,
        DAEMON_ENDPOINT_KEY,
    )
}

#[derive(Debug, Clone, Default)]
pub struct EndpointProjector;

impl EndpointProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EndpointProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for EndpointProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        endpoint: super::fact::EndpointFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("local endpoint fact must have local scope".to_string());
        }

        // 3. Materialize.
        let mut output = ProjectionOutput::new();
        output = output.offer(crate::core::context::ContextOffer::range(
            fact.id,
            "auth_local_endpoint",
            crate::core::facts::FactScope::Local,
            endpoint.endpoint,
            endpoint.endpoint,
        ));
        output = output.offer(daemon_endpoint_offer(fact.id));
        for row in endpoint_rows(&endpoint) {
            output = output.row_mutation(RowMutation::PutRow(row));
        }
        Ok(output)
    }
}
