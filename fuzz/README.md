# Fuzz Targets

This package uses `cargo-fuzz`/libFuzzer for byte-level and projector-level
stress testing.

Install the runner once:

```sh
cargo install cargo-fuzz
```

Run a target:

```sh
cargo fuzz run decode_any_fact_bytes
cargo fuzz run connection_frame_header
cargo fuzz run receive_network_frame
cargo fuzz run project_connection_request
cargo fuzz run project_pending_facts
```

Build-check every target without installing `cargo-fuzz`:

```sh
RUSTFLAGS="--cfg fuzzing" cargo check --manifest-path fuzz/Cargo.toml --bins
```

The first targets are intentionally split by failure surface:

- `decode_any_fact_bytes`: all registered fact layout decoders must return
  `Ok` or `Err`, never panic.
- `connection_frame_header`: arbitrary bytes through established-frame header
  peek, shape decode, and fixed-size frame decoders.
- `receive_network_frame`: arbitrary network bytes through receive-intent
  encoding/decoding and established-frame classification.
- `project_connection_request`: arbitrary request bytes and generated context
  snapshots through the real request projector.
- `project_pending_facts`: generated projector behavior through the runtime
  projection loop, including fixed-point context and ephemeral transient-need
  guards.
