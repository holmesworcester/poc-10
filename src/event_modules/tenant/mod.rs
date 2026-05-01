//! `tenant` event module — local tenant identity event.
//!
//! Per-file layout (plan.md per-file rule): `codec.rs` owns encode/parse +
//! registry meta; `projector.rs` owns `ensure_schema` + the pure projector.
//!
//! TODO(plan.md Wave 2): tenant module is a Wave-1 deferred drop, retained
//! as a helper for the `tenants` projection table relied on by
//! transport/discovery. Migrated to per-file layout per the plan
//! anyway since the event still exists.

pub mod projector;
pub mod codec;

pub use projector::{ensure_schema, project_pure};
pub use codec::{
    encode_tenant, parse_tenant, TenantEvent, TENANT_FIELDS, TENANT_META, TENANT_WIRE_SIZE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event, ParsedEvent};

    #[test]
    fn test_roundtrip_tenant() {
        let e = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: 987,
            public_key: [9u8; 32],
        });
        let blob = encode_event(&e).unwrap();
        assert_eq!(blob.len(), TENANT_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, e);
    }
}
