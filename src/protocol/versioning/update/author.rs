//! Pure local protocol update fact construction.

use crate::core::facts::{Fact, FactScope};

use super::encode::encode_update_fact;
use super::fact::UpdateFact;

pub fn update_fact(update: UpdateFact) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Local,
        update.applied_at_ms,
        encode_update_fact(update)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::versioning::update::decode_update_fact;

    #[test]
    fn update_fact_creates_local_fact() {
        let fact = update_fact(UpdateFact {
            protocol_version: 7,
            applied_at_ms: 44,
        })
        .expect("update fact");
        assert_eq!(fact.scope, FactScope::Local);
        assert_eq!(
            decode_update_fact(fact.body())
                .expect("decode")
                .protocol_version,
            7
        );
    }
}
