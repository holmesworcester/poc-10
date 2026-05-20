//! Command constructors for local endpoint identity facts.
//!
//! Endpoint commands are local identity work. They read only the endpoint rows
//! owned by this module, and they return a local endpoint fact when no complete
//! local keypair exists yet.

use crate::core::command_context::CommandOutput;
use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::store::Store;

use super::fact::EndpointFact;
use super::{layout, local_endpoint};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEndpointOutput {
    pub endpoint: EndpointFact,
    pub created: bool,
}

pub fn local_or_create(
    store: &Store,
    created_at_ms: u64,
) -> Result<CommandOutput<LocalEndpointOutput>, String> {
    match local_endpoint::local_endpoint(store)? {
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

fn create_local_endpoint() -> EndpointFact {
    let secret = crypto::random_x25519_private_key();
    let signing_secret = crypto::random_ed25519_private_key();
    EndpointFact {
        endpoint: crypto::x25519_public_key(&secret),
        secret,
        signing_public_key: crypto::ed25519_public_key(&signing_secret),
        signing_secret,
    }
}

pub fn endpoint_fact(created_at_ms: u64, endpoint: EndpointFact) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Local,
        created_at_ms,
        layout::encode_fact(&endpoint)?,
    ))
}

#[cfg(test)]
mod tests {
    use crate::core::schema_dsl::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

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
            layout::decode_fact(&output.facts[0].bytes).expect("decode"),
            output.receipt.endpoint
        );
    }

    #[test]
    fn local_or_create_reuses_unprojected_local_endpoint_fact() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open store");
        let endpoint = create_local_endpoint();
        let fact = endpoint_fact(10, endpoint.clone()).expect("endpoint fact");
        crate::core::pipeline::submit_fact_to_store(&store, fact).expect("submit fact");

        let output = local_or_create(&store, 20).expect("reuse endpoint");

        assert!(!output.receipt.created);
        assert!(output.facts.is_empty());
        assert_eq!(output.receipt.endpoint, endpoint);
    }
}
