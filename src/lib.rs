pub mod event_modules;
pub mod runtime;
pub mod shared;
pub mod state;

pub use runtime::control::{api, assert, rpc, service};
pub use runtime::control_loop;
pub use runtime::transport_v2;
pub use shared::{contracts, crypto, protocol, tuning};
pub use state::db;
pub use state::projection;

#[cfg(test)]
mod boundary_tests {
    // Wave 1 cleanup: `test_boundary_imports_enforced` and
    // `test_projector_tla_conformance_enforced` were deleted because they
    // ground out on now-deleted modules (peering/, sync_engine/) and stale
    // legacy projector test ids (admin/file_slice/attachment/bench_dep).
    // Boundary enforcement should be re-introduced as part of the multi-daemon
    // convergence rebuild; in the meantime, the bijection check remains as a
    // forward-compat sanity gate for projector ↔ TLA mapping.

    fn assert_python_script_passes(script: &str) {
        let result = std::process::Command::new("python3")
            .arg(script)
            .output()
            .unwrap_or_else(|err| panic!("failed to run {} via python3: {}", script, err));
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let stdout = String::from_utf8_lossy(&result.stdout);
            panic!("{} failed:\n{}\n{}", script, stdout, stderr);
        }
    }

    #[test]
    fn test_projector_tla_bijection_enforced() {
        assert_python_script_passes("scripts/check_projector_tla_bijection.py");
    }
}
