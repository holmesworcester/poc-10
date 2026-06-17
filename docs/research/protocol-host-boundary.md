# Protocol Host Boundary Plan

This plan simplifies the single-protocol program shape while preserving the
strict boundary between protocol-neutral core mechanics and concrete protocol
policy. Core should keep hosting typed protocol functions without importing the
protocol module. The protocol should export one typed definition that names its
commands, daemon callbacks, schema, routes, handlers, and admission policy.

The result should make the entry path read directly:

```rust
topo::core::protocol_host::run(&topo::protocol::definition::PROTOCOL, argv)
```

## Target Model

`main.rs` remains the process edge. It collects process arguments, calls the
core protocol host with the concrete protocol definition, prints errors, and
exits. It should not parse protocol commands, open runtimes, or start daemon
loops directly.

`core::protocol_host` owns the program-level hosting flow for one protocol
definition. It parses `--db`, handles help and daemon lifecycle commands, opens
the runtime, constructs command context, dispatches protocol commands, and
connects daemon mode to the runtime and daemon modules. It consumes protocol
function pointers and tables through core-defined types only.

`core::runtime` remains the state engine. It opens schema, admits facts, drains
projection, dispatches intents, and runs replay. It should not know argv,
process exit behavior, lock files, TCP listener lifetime, or command names.

`core::daemon` remains the long-running process mechanics. It owns lock files,
stop/reset coordination, listener lifetime, recurring schedules, tick ordering,
network intake pumping, time-wake admission, and outgoing network pumping. It
feeds work into `Runtime`; it should not own protocol command dispatch.

`protocol::definition` exports the concrete protocol definition. It names the
runtime declarations, daemon declarations, command table, schema sources, row
mutation allowlist, fact routes, fact admission hook, and handler routes for the
single concrete protocol.

`protocol::registry` may remain as a route-table module if `definition.rs` gets
too large, but it should no longer be the primary executable protocol entrypoint
unless it exports the whole `PROTOCOL` definition. A registry is a table; a
definition is the whole runnable protocol contract.

`protocol::commands` owns the top-level command adapter functions. These
functions bridge command argv and command context into domain modules. They
should stay thin and should not be folded into the protocol definition.

## Names

Use `ProtocolDefinition` for the consumed type. The value defines the executable
protocol, not merely a lookup table.

Use `core::protocol_host` for the module that consumes a `ProtocolDefinition`
and hosts it as short-lived CLI commands or long-lived daemon mode.

Use `protocol::definition::PROTOCOL` for the single concrete protocol value.
The protocol may still carry an internal protocol name such as `toy_fs`, while
the product-facing CLI remains `con` and the display name remains `Context`.
The term `context` stays available for the core context-matching feature.

Use `protocol::commands` instead of `protocol::cli` when renaming is practical.
The file owns command adapters, not generic CLI infrastructure.

Consider renaming `core::cli` to `core::command_dispatch` if the refactor
already touches that surface. That file owns `CliCommand`, `CliArgs`,
`CliOutput`, duplicate-name validation, and command function dispatch.

## Boundary Rules

Core may define hosting, runtime, daemon, command-dispatch, projection, handler,
schema, and store types. Core may consume function pointers and factories from a
protocol definition. Core must not import `crate::protocol`.

Protocol may import core types and implement concrete command adapters,
admission functions, projectors, handlers, schema declarations, row helpers,
queries, and network intake conversion.

`main.rs` is the only place that wires the concrete protocol definition into
core hosting. This preserves a strict dependency direction:

```text
main -> core::protocol_host + protocol::definition
protocol -> core types
core -> no protocol imports
```

## Proposed File Shape

```text
src/
  main.rs
  lib.rs
  core.rs
  protocol.rs
  core/
    protocol_host.rs
    runtime.rs
    daemon.rs
    command_dispatch.rs
    ...
  protocol/
    definition.rs
    commands.rs
    registry.rs
    auth/
    content/
    connection/
    sync/
```

`core.rs` and `protocol.rs` stay as module maps. They should remain
declaration-only.

## Migration Steps

1. Add `core::protocol_host`.
   Move the current generic program-hosting behavior out of `core::app` or
   rename `core::app` to `core::protocol_host`. Keep argv parsing, usage,
   daemon lifecycle commands, `assert eventually`, runtime opening, turn lock
   acquisition, and command dispatch in this module.

2. Introduce `ProtocolDefinition`.
   Replace `ProtocolDescription` as the externally consumed protocol contract.
   The initial version may keep the existing generic command context if that
   reduces churn. A later cleanup can make the command context concrete.

3. Add `protocol::definition`.
   Collapse the current `protocol::app` assembly into `protocol::definition`.
   Export `pub const PROTOCOL: ProtocolDefinition`.

4. Keep route tables declarative.
   Keep fact routes, handler routes, schema sources, row mutation tables, and
   admission routing in `protocol::registry` if that keeps `definition.rs`
   readable. `definition.rs` should assemble those pieces into `PROTOCOL`.

5. Rename command adapters when practical.
   Rename `protocol::cli` to `protocol::commands` and update command route
   registration to point at that module. Keep command implementations out of
   `definition.rs`.

6. Remove the thin product wrapper.
   Delete `context_app.rs`. Update `main.rs` to call
   `core::protocol_host::run(&protocol::definition::PROTOCOL, argv)`. Remove
   `pub mod context_app` from `lib.rs`.

7. Update tests and guardrails.
   Point registry tests at `protocol::definition::PROTOCOL` or the route tables
   it contains. Add a focused test that opens an in-memory runtime from the
   protocol definition. Keep existing CLI, daemon, projection, handler, and
   replay tests passing.

8. Update current architecture docs after the refactor lands.
   Once the code moves, revise `docs/RULES.md` so the current-code rules name
   `protocol_host` and `protocol::definition` instead of `context_app` and
   `protocol::app`.

9. Commit the completed work on the same worktree branch before handoff or
   review.

## Non-Goals

Do not introduce a config file for projector routes, handler factories,
admission hooks, daemon callbacks, or command functions. Those values are typed
Rust functions and factories; putting them behind strings would add a second
lookup layer and lose compiler checks.

Do not move daemon lifecycle into `Runtime`. Runtime should remain the
store-backed state engine. Daemon startup, listener lifetime, lock files, and
sleep loops belong above it.

Do not move protocol hosting into `main.rs`. The hosting flow should remain
library code so tests can call it with synthetic argv without spawning the
binary.

Do not add multi-protocol selection unless there is a concrete need. The strict
boundary does not require named protocol lists.
