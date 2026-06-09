use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::LocalSecretPayloadFact;

pub(crate) struct LocalSecretPayloadAuthenticator;

impl DecodedAuthenticator<super::decode::Codec> for LocalSecretPayloadAuthenticator {
    type Authenticated = LocalSecretPayloadFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        secret: LocalSecretPayloadFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, verify_fact_id(fact).map(|()| secret))
    }
}
