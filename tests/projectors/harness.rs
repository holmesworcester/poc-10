//! Shared test harness for pure projector conformance tests.
//!
//! Provides assertion helpers for ProjectorResult inspection. Per plan.md
//! (Forking plan, "no scaffolding"), every projector's ContextSnapshot is
//! `{event, deps, labels}` (+ sync extension). Test fixtures construct
//! that minimal shape directly.

#[cfg(test)]
pub mod fixtures {
    use std::collections::BTreeMap;
    use topo::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, WriteOp};
    use topo::projection::decision::ProjectionDecision;

    /// Default ContextSnapshot with empty deps + empty labels.
    pub fn empty_ctx() -> ContextSnapshot {
        ContextSnapshot::default()
    }

    /// ContextSnapshot with a single label entry.
    pub fn ctx_with_label(event_id_b64: &str, label: &str) -> ContextSnapshot {
        let mut labels: BTreeMap<String, Vec<String>> = BTreeMap::new();
        labels.insert(event_id_b64.to_string(), vec![label.to_string()]);
        ContextSnapshot {
            labels,
            ..ContextSnapshot::default()
        }
    }

    /// ContextSnapshot with a single dep entry.
    pub fn ctx_with_dep(dep_id_b64: &str, bytes: Vec<u8>) -> ContextSnapshot {
        let mut deps: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        deps.insert(dep_id_b64.to_string(), bytes);
        ContextSnapshot {
            deps,
            ..ContextSnapshot::default()
        }
    }

    /// Base64-encode a 32-byte ID (matches crypto::event_id_to_base64).
    pub fn b64(id: &[u8; 32]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(id)
    }

    // ── Assertion helpers ──

    pub fn assert_valid(result: &ProjectorResult) {
        assert!(
            matches!(result.decision, ProjectionDecision::Valid),
            "expected Valid, got {:?}",
            result.decision
        );
    }

    #[allow(dead_code)]
    pub fn assert_block(result: &ProjectorResult) {
        assert!(
            matches!(result.decision, ProjectionDecision::Block { .. }),
            "expected Block, got {:?}",
            result.decision
        );
    }

    pub fn assert_reject(result: &ProjectorResult) {
        assert!(
            matches!(result.decision, ProjectionDecision::Reject { .. }),
            "expected Reject, got {:?}",
            result.decision
        );
    }

    pub fn assert_reject_contains(result: &ProjectorResult, substring: &str) {
        match &result.decision {
            ProjectionDecision::Reject { reason } => {
                assert!(
                    reason.contains(substring),
                    "expected rejection containing '{}', got '{}'",
                    substring,
                    reason
                );
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    /// Assert that write_ops contain an InsertOrIgnore to the given table.
    pub fn assert_writes_to_table(result: &ProjectorResult, table: &str) {
        assert!(
            result.write_ops.iter().any(|op| matches!(
                op, WriteOp::InsertOrIgnore { table: t, .. } if *t == table
            )),
            "expected InsertOrIgnore to table '{}', ops: {:?}",
            table,
            result.write_ops
        );
    }

    /// Assert that no write_ops target the given table.
    pub fn assert_no_write_to_table(result: &ProjectorResult, table: &str) {
        assert!(
            !result.write_ops.iter().any(|op| match op {
                WriteOp::InsertOrIgnore { table: t, .. } => *t == table,
                WriteOp::Delete { table: t, .. } => *t == table,
            }),
            "expected no write to table '{}', but found one",
            table
        );
    }

    /// Assert that emit_commands contains a specific command variant.
    pub fn assert_emits_command<F: Fn(&EmitCommand) -> bool>(
        result: &ProjectorResult,
        name: &str,
        predicate: F,
    ) {
        assert!(
            result.emit_commands.iter().any(&predicate),
            "expected emit command '{}', commands: {:?}",
            name,
            result.emit_commands
        );
    }

    /// Assert that emit_commands does not contain a command matching predicate.
    #[allow(dead_code)]
    pub fn assert_no_command<F: Fn(&EmitCommand) -> bool>(result: &ProjectorResult, predicate: F) {
        assert!(
            !result.emit_commands.iter().any(&predicate),
            "expected no matching command, got: {:?}",
            result.emit_commands
        );
    }

    /// Assert that emit_commands is empty.
    pub fn assert_no_commands(result: &ProjectorResult) {
        assert!(
            result.emit_commands.is_empty(),
            "expected no emit commands, got: {:?}",
            result.emit_commands
        );
    }
}
