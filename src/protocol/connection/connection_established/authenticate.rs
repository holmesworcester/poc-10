use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionEstablishedFact;

pub(crate) struct ConnectionEstablishedAuthenticator;

impl Authenticator for ConnectionEstablishedAuthenticator {
    type Authenticated = ConnectionEstablishedFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_established(fact))
    }
}

fn authenticate_established(fact: &Fact) -> Result<ConnectionEstablishedFact, String> {
    let established = super::Codec::decode_fact(fact)?;
    verify_fact_id(fact)?;
    if established.connection_id == [0; 32]
        || established.request_id == [0; 32]
        || established.initiator_ephemeral_secret_fact_id == [0; 32]
        || established.responder_ephemeral_secret_fact_id == [0; 32]
        || established.connection_secret == [0; 32]
    {
        return Err("connection_established selectors cannot be empty".to_string());
    }
    if established.from_endpoint == established.to_endpoint {
        return Err("connection_established endpoints must differ".to_string());
    }
    Ok(established)
}
