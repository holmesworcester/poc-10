//! End-to-end demo of the poc-10 target architecture.
//!
//! This example is a thin wrapper that defers to `topo::poc10_demo::run`,
//! the same function the `topo` binary invokes via `topo poc10-demo`. Both
//! paths drive a workspace + sealed-message walkthrough through the target
//! `EventBus`, target projectors, and target row tables only, without
//! touching `src/protocol/` or `src/workers/`.
//!
//! Run via either:
//!   cargo run --example poc10_demo
//!   cargo run --bin topo -- poc10-demo

fn main() -> Result<(), String> {
    topo::poc10_demo::run()
}
