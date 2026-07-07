//! Membership connection-request version adapter.
//!
//! The request family is unsuffixed (a single version), so its adapter is the
//! identity: the authenticated `ConnectionRequestFact` is already the active
//! semantic value the projector consumes. A future incompatible version adds a
//! non-identity adapter in a `_vN/` sibling without touching this family's
//! authenticator or projector.

use crate::core::projectors::IdentityAdapter;

use super::fact::ConnectionRequestFact;

pub(crate) type ConnectionRequestAdapter = IdentityAdapter<ConnectionRequestFact>;
