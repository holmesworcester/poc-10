//! User-facing command for local endpoint identity.
//!
//! Endpoint commands are local identity work. They return a local endpoint
//! fact when no complete local keypair exists yet, reusing the constructors and
//! capability access in `author.rs`.

use crate::core::command_context::CommandOutput;
use crate::core::store::Store;

use super::author::{create_local_endpoint, endpoint_fact, local_endpoint};
use super::fact::EndpointFact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEndpointOutput {
    pub endpoint: EndpointFact,
    pub created: bool,
}

pub fn local_or_create(
    store: &Store,
    created_at_ms: u64,
) -> Result<CommandOutput<LocalEndpointOutput>, String> {
    match local_endpoint(store)? {
        Some(endpoint) => Ok(CommandOutput::new(LocalEndpointOutput {
            endpoint,
            created: false,
        })),
        None => {
            let endpoint = create_local_endpoint();
            let fact = endpoint_fact(created_at_ms, endpoint)?;
            Ok(CommandOutput::new(LocalEndpointOutput {
                endpoint,
                created: true,
            })
            .with_facts(vec![fact]))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::core::facts::FactScope;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::auth::endpoint::project::decode;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    use super::super::author::create_local_endpoint;
    use super::*;

    #[test]
    fn local_or_create_returns_local_endpoint_fact_when_missing() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open store");

        let output = local_or_create(&store, 10).expect("create endpoint");

        assert!(output.receipt.created);
        assert_eq!(output.facts.len(), 1);
        assert_eq!(output.facts[0].scope, FactScope::Local);
        assert_eq!(output.facts[0].timestamp, 10);
        assert_eq!(
            decode::decode_fact(&output.facts[0].bytes).expect("decode"),
            output.receipt.endpoint
        );
    }

    #[test]
    fn local_or_create_reuses_unprojected_local_endpoint_fact() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open store");
        let endpoint = create_local_endpoint();
        let fact = super::super::author::endpoint_fact(10, endpoint).expect("endpoint fact");
        crate::core::pipeline::submit_fact_to_store(&store, fact).expect("submit fact");

        let output = local_or_create(&store, 20).expect("reuse endpoint");

        assert!(!output.receipt.created);
        assert!(output.facts.is_empty());
        assert_eq!(output.receipt.endpoint, endpoint);
    }
}
