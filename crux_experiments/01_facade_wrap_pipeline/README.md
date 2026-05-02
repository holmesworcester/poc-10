# Facade Wrap Pipeline

Tiny Crux prototype for wrapping the current store/admit plus ready-drain path
as an incremental facade.

The Crux `App` owns only the intent and model update. It emits effects for a
shell to execute:

1. `StoreRecords`
2. `DrainReady`
3. `PrintReport`

Run it with:

```sh
cargo run
```

Test it with:

```sh
cargo test
```
