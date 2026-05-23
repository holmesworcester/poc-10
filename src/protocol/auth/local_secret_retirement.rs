//! Local secret-retirement fact family.
//!
//! A retirement fact is local context saying one local secret-source fact should
//! stop offering key material. The retirement fact does not purge the target by
//! itself; target secret projectors keep a standing retirement need and emit
//! self-purge after this context arrives.
//!
//! Change this family for retirement fact bytes or retirement-context
//! coordinates. Change the target secret projectors for target-specific cleanup
//! and validation.

pub mod fact;
pub mod layout;
pub mod project;

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use crate::core::facts::{FactId, FactScope};

const LOCAL_SECRET_RETIRED_ROLE: &str = "local_secret_source_retired";

pub const TYPE_LOCAL_SECRET_RETIREMENT: u8 = layout::TYPE_LOCAL_SECRET_RETIREMENT;

pub fn secret_retired_need(owner: FactId, target_secret_id: FactId) -> ContextNeed {
    exact_local_need(owner, LOCAL_SECRET_RETIRED_ROLE, target_secret_id)
}

pub fn secret_retired_offer(owner: FactId, target_secret_id: FactId) -> ContextOffer {
    exact_local_offer(owner, LOCAL_SECRET_RETIRED_ROLE, target_secret_id)
}

fn exact_local_need(owner: FactId, role: &'static str, key: FactId) -> ContextNeed {
    let key = ContextKey::from_bytes(key);
    ContextNeed {
        owner,
        role: Role::expect(role),
        scope: FactScope::Local,
        start_key: key.clone(),
        end_key: key,
    }
}

fn exact_local_offer(owner: FactId, role: &'static str, key: FactId) -> ContextOffer {
    let key = ContextKey::from_bytes(key);
    ContextOffer {
        owner,
        role: Role::expect(role),
        scope: FactScope::Local,
        start_key: key.clone(),
        end_key: key,
    }
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalSecretRetirementFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::LocalSecretRetirementFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
