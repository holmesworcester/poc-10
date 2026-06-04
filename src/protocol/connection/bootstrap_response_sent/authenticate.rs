use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::BootstrapResponseSentFact;

pub(crate) struct BootstrapResponseSentAuthenticator;

impl Authenticator for BootstrapResponseSentAuthenticator {
    type Authenticated = BootstrapResponseSentFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_response_sent(fact))
    }
}

fn authenticate_response_sent(fact: &Fact) -> Result<BootstrapResponseSentFact, String> {
    let sent = super::Codec::decode_fact(fact)?;
    verify_fact_id(fact)?;
    if sent.response_id
        != crate::core::facts::fact_id(
            &crate::protocol::connection::bootstrap_response::layout::encode_fact(&sent.response)?,
        )
    {
        return Err("bootstrap_response_sent response_id does not match response".to_string());
    }
    if sent.request_id != sent.response.request_id {
        return Err("bootstrap_response_sent request_id does not match response".to_string());
    }
    if sent.responder_ephemeral_secret_fact_id != sent.response.responder_ephemeral_secret_fact_id {
        return Err("bootstrap_response_sent ephemeral id does not match response".to_string());
    }
    Ok(sent)
}
