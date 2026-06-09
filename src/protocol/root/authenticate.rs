use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::RootFact;

pub(crate) struct RootAuthenticator;

impl DecodedAuthenticator<super::decode::Codec> for RootAuthenticator {
    type Authenticated = RootFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        root: RootFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, verify_fact_id(fact).map(|()| root))
    }
}
