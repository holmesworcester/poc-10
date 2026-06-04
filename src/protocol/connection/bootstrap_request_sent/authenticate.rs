use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::BootstrapRequestSentFact;

pub(crate) struct BootstrapRequestSentAuthenticator;

impl Authenticator for BootstrapRequestSentAuthenticator {
    type Authenticated = BootstrapRequestSentFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_request_sent(fact))
    }
}

fn authenticate_request_sent(fact: &Fact) -> Result<BootstrapRequestSentFact, String> {
    let sent = super::Codec::decode_fact(fact)?;
    verify_fact_id(fact)?;
    if sent.request_id
        != crate::core::facts::fact_id(
            &crate::protocol::connection::bootstrap_request::layout::encode_fact(&sent.request)?,
        )
    {
        return Err("bootstrap_request_sent request_id does not match request".to_string());
    }
    if sent.initiator_ephemeral_secret_fact_id != sent.request.initiator_ephemeral_secret_fact_id {
        return Err("bootstrap_request_sent ephemeral id does not match request".to_string());
    }
    Ok(sent)
}
