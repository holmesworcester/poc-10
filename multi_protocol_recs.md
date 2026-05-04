# Multi-Protocol Recommendations

## Goal

`poc-8` should support multiple protocols without mixing their command
surfaces, event registries, test definitions, or daemon instances. Each
protocol should be able to build as its own CLI and run separately or
concurrently, the same way independent `poc-7` daemon instances can run today.

## Directory Shape

Use named peer protocols under `src/protocol`:

```text
src/
  core/
  protocol/
    mod.rs
    topo/
      mod.rs
      cli.rs
      app/
      event_modules/
      network.rs
      wire.rs
    twopo/
      mod.rs
      cli.rs
      app/
      event_modules/
      network.rs
      wire.rs
  bin/
    topo.rs
    twopo.rs
```

Do not nest one protocol under another, such as `protocol/topo/twopo`. `topo`
and `twopo` are separate protocol peers. Each owns its protocol composition
object, event-module registry, app shell, wire tags, URI prefix, CLI surface,
network framing, and protocol-specific tests.

Shared code should move to `core/` only when it is genuinely
protocol-agnostic. Avoid creating a vague shared protocol layer for behavior
that actually belongs to one protocol's semantics.

## CLI Binaries

Cargo should declare one binary per protocol:

```toml
[[bin]]
name = "topo"
path = "src/bin/topo.rs"

[[bin]]
name = "twopo"
path = "src/bin/twopo.rs"
```

Each bin should be a tiny wrapper around the owning protocol CLI:

```rust
fn main() {
    topo::protocol::topo::cli::main()
}
```

and:

```rust
fn main() {
    topo::protocol::twopo::cli::main()
}
```

Plain `cargo build` should build all protocol CLIs. Targeted commands can still
use `cargo build --bin topo` or `cargo build --bin twopo`.

## Test Placement

Protocol tests should be defined inside the owning protocol or event-module
scope, not gathered into root-level integration-test files. Root `tests/`
should not become a mixed pile of protocol behavior.

Preferred shape:

```text
src/protocol/topo/
  cli_test.rs
  event_modules/
    connection/
      cli_test.rs
      worker_test.rs
    content/
      cli_test.rs
    sync/
      cli_test.rs
      worker_test.rs

src/protocol/twopo/
  cli_test.rs
  event_modules/
    ...
```

Wire these through local `#[cfg(test)]` module declarations:

```rust
// src/protocol/topo/mod.rs
pub mod cli;
pub mod event_modules;

#[cfg(test)]
mod cli_test;
```

and:

```rust
// src/protocol/topo/event_modules/sync/mod.rs
pub mod worker;

#[cfg(test)]
mod cli_test;

#[cfg(test)]
mod worker_test;
```

Module-local `cli_test.rs` files may still be black-box tests that build and
spawn the real protocol binary. The point is ownership: the test definition
lives beside the protocol or event module whose behavior it proves.

Generic reusable harness helpers can live in a neutral test-support module,
but actual protocol assertions should stay in the owning protocol tree.

## Boundary Rules

Static boundary tests should become protocol-aware. Checks that currently
hard-code paths such as `src/protocol/event_modules` should scan
`src/protocol/*/event_modules`.

Each protocol should keep its own:

- event type tags and canonical wire layout,
- URI scheme or prefix, such as `topo://...` versus `twopo://...`,
- event-module registry,
- table names or table namespace,
- CLI command names and output formatting,
- app/effect vocabulary,
- network framing if it is protocol-specific.

Cross-protocol use should fail explicitly. For example, a `twopo` CLI should
not silently accept a `topo://invite/...` link.

## Build And Runtime Expectations

`cargo build` builds every protocol CLI. Each CLI can be launched independently
with its own database, socket, listener port, and daemon lifecycle.

Black-box coverage should include:

- each protocol's CLI builds and handles its own basic command surface,
- each protocol rejects another protocol's invite or URI prefix,
- two different protocol CLIs can run concurrently with separate DBs and ports,
- protocol-local event-module scenarios remain defined beside their owning
  event modules.

## Rollout Notes

1. Move the current `src/protocol/*` implementation into
   `src/protocol/topo/*`.
2. Add tiny `src/bin/topo.rs` and update `Cargo.toml` so the existing CLI name
   remains stable.
3. Convert path-based rules and tests to iterate named protocol directories.
4. Move protocol behavior tests from root `tests/` into protocol-local
   `cli_test.rs` or module-local test files.
5. Add `twopo` as a second peer protocol with its own CLI binary and scoped
   tests.
6. Prove concurrent operation with a black-box test that runs both protocol
   CLIs independently.
7. Commit the completed work on the same worktree branch before handoff or
   review.
