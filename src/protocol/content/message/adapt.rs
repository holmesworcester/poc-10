//! Content-message version adapter.
//!
//! The message family is unsuffixed (a single version), so its adapter is the
//! identity: the authenticated `ContentMessageFact` is already the active
//! semantic value the projector consumes. A future incompatible version adds a
//! non-identity adapter in a `_vN/` sibling without touching this family's
//! authenticator or projector.

use crate::core::projectors::IdentityAdapter;

use super::fact::ContentMessageFact;

pub(crate) type ContentMessageAdapter = IdentityAdapter<ContentMessageFact>;
