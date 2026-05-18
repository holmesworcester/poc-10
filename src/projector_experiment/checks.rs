//! Reusable micro-primitives for projector readability variants.
//!
//! Each item is small enough that a reader of a calling projector does not need
//! to study this file to understand what a call does — the name is the spec.
//!
//! Helpers placed here MUST satisfy two rules:
//!   1. Pure structural mechanics (decode, collect, format) — never a domain
//!      cross-field check.
//!   2. The body fits on one screen.
//!
//! If you need a cross-field check (e.g., "endpoint workspace matches invite
//! workspace"), keep it in the projector's own file so the policy stays visible
//! where it's enforced.

#![cfg(test)]

use crate::core::context::ContextNeed;
use crate::core::projection::ProjectionOutput;
use crate::event_modules::signed_fact;
use crate::event_modules::signed_fact::fact::SignedFactEnvelope;

/// Turn one boolean invariant into a `?`-friendly call. Reads like a spec line:
///   `require(invite.workspace_id == workspace.id, "workspace mismatch")?;`
pub fn require(condition: bool, error: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(error.to_string())
    }
}

/// True if every byte of a 32-byte selector field is zero (the canonical
/// "unset" sentinel for FactId / public-key fields in this codebase).
pub fn is_zero32(field: &[u8; 32]) -> bool {
    field == &[0; 32]
}

/// Open a signed envelope, confirm its inner type tag, and decode the inner
/// payload. Captures the four-line "decode envelope / check inner_type /
/// decode payload" recipe that appears in every authority projector.
///
/// - `envelope_err` is returned for either a malformed envelope or an
///   unexpected inner type (both mean "wrong kind of fact here").
/// - `payload_err` is returned only for a malformed inner body.
pub fn open_signed<T>(
    bytes: &[u8],
    expected_type: u8,
    decode: fn(&[u8]) -> Result<T, String>,
    envelope_err: &str,
    payload_err: &str,
) -> Result<(SignedFactEnvelope, T), String> {
    let envelope = signed_fact::layout::decode_signed_fact(bytes)
        .map_err(|_| envelope_err.to_string())?;
    if envelope.inner_type != expected_type {
        return Err(envelope_err.to_string());
    }
    let inner = decode(&envelope.payload).map_err(|_| payload_err.to_string())?;
    Ok((envelope, inner))
}

/// Accumulates the needs a projector publishes as it discovers them. `park()`
/// drains the set into a `ProjectionOutput` whose only contribution is the
/// recorded needs — exactly what the wake loop expects to see when validation
/// can't yet proceed.
///
/// Usage:
/// ```ignore
/// let mut needs = NeedSet::new();
/// let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
/// needs.add(invite_need.clone());
/// let Some(invite) = ctx.payload_for(&invite_need) else { return Ok(needs.park()); };
/// ```
///
/// The pattern is "declare → look up → park-on-miss" in three lines per
/// dependency. The state is visible (each `add` is explicit), so no
/// auto-tracking magic is hidden inside.
#[derive(Default)]
pub struct NeedSet {
    needs: Vec<ContextNeed>,
}

impl NeedSet {
    pub fn new() -> Self {
        Self {
            needs: Vec::new(),
        }
    }

    pub fn add(&mut self, need: ContextNeed) {
        self.needs.push(need);
    }

    pub fn park(self) -> ProjectionOutput {
        let mut out = ProjectionOutput::new();
        for need in self.needs {
            out = out.need(need);
        }
        out
    }
}
