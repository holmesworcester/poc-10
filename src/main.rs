//! Binary entry point for the `match` protocol.
//!
//! The binary should stay boring. It selects the concrete protocol description
//! from `match_app`, passes process arguments into the generic core runner, and
//! turns returned errors into process output. Protocol behavior belongs in
//! `protocol`; reusable CLI, daemon, and runtime hosting belongs in `core`.

use std::env;

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    if let Err(err) = topo::match_app::run(argv) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
