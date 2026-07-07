//! Membership connection-response version adapter.
//!
//! The response family is unsuffixed (a single version), so its adapter is the
//! identity: the authenticated `ConnectionResponseFact` is already the active
//! semantic value the projector consumes. A future incompatible version adds a
//! non-identity adapter in a `_vN/` sibling without touching this family's
//! authenticator or projector.

use crate::core::projectors::IdentityAdapter;

use super::fact::ConnectionResponseFact;

pub(crate) type ConnectionResponseAdapter = IdentityAdapter<ConnectionResponseFact>;
