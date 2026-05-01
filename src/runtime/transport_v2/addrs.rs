//! Pluggable address resolver.
//!
//! Phase 1 stub: just a `HashMap<EndpointId, SocketAddr>`. Real resolver
//! will be backed by invites, `observed_address` events, and learned-from-
//! incoming hints.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use super::super::control_loop::work_item::EndpointId;

/// Anything that can map a remote `endpoint_id` to a `SocketAddr`.
pub trait AddressResolver: Send + Sync {
    fn resolve(&self, endpoint_id: &EndpointId) -> Option<SocketAddr>;

    /// Record a freshly-learned address (e.g. from incoming connection,
    /// `observed_address` event, invite metadata). Default no-op for
    /// resolvers that are read-only.
    fn record(&self, _endpoint_id: EndpointId, _addr: SocketAddr) {}
}

/// In-memory, mutex-guarded `HashMap`-based resolver. Good enough for tests
/// and Phase 1 wiring.
#[derive(Default, Clone)]
pub struct AddressBook {
    inner: Arc<RwLock<HashMap<EndpointId, SocketAddr>>>,
}

impl AddressBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_initial(map: HashMap<EndpointId, SocketAddr>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(map)),
        }
    }

    pub fn insert(&self, endpoint_id: EndpointId, addr: SocketAddr) {
        if let Ok(mut g) = self.inner.write() {
            g.insert(endpoint_id, addr);
        }
    }

    pub fn get(&self, endpoint_id: &EndpointId) -> Option<SocketAddr> {
        self.inner.read().ok()?.get(endpoint_id).copied()
    }
}

impl AddressResolver for AddressBook {
    fn resolve(&self, endpoint_id: &EndpointId) -> Option<SocketAddr> {
        self.get(endpoint_id)
    }

    fn record(&self, endpoint_id: EndpointId, addr: SocketAddr) {
        self.insert(endpoint_id, addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn address_book_round_trip() {
        let book = AddressBook::new();
        let id: EndpointId = [7u8; 32];
        let addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        book.insert(id, addr);
        assert_eq!(book.resolve(&id), Some(addr));
        assert_eq!(book.resolve(&[0u8; 32]), None);
    }
}
