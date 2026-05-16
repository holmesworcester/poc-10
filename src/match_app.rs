//! Product-facing `match` binary entrypoint.
//!
//! `main.rs` stays intentionally tiny: it collects argv and delegates here.
//! This module chooses the current Topo protocol implementation behind the
//! product-facing `match` binary name. It should not grow protocol logic,
//! projection code, handler dispatch, or fact construction.

pub fn run(argv: Vec<String>) -> Result<(), String> {
    if matches!(argv.first().map(String::as_str), Some("demo")) {
        return crate::demo::run();
    }
    crate::legacy::app::run::<crate::legacy::protocol::Protocol>(argv)
}
