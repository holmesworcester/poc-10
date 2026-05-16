//! End-to-end demo of the target architecture.
//!
//! This example is a thin wrapper that defers to `topo::demo::run`,
//! the same function the `match` binary invokes via `match demo`. Both
//! paths drive a workspace + sealed-message walkthrough through the target
//! `WakeLoop`, target projectors, and target row tables only, without
//! touching `src/legacy/protocol/` or `src/legacy/workers/`.
//!
//! Run via either:
//!   cargo run --example match_demo
//!   cargo run --bin match -- demo

fn main() -> Result<(), String> {
    topo::demo::run()
}
