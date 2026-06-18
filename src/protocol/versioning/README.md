# Versioning

`versioning` is a protocol scope. It is not itself a fact family.

This scope owns one release constant, `CURRENT_PROTOCOL_VERSION`, and the
protocol logic that compares the schema-declared protocol marker with that constant. The
normal repair loop is:

1. `check_version` is a recurring intent.
2. If the schema-declared protocol marker is missing or stale, it authors a local
   `local_update` fact.
3. The `local_update` fact records protocol-visible update history, requests a
   rebuild of derived state, and advances the schema-declared protocol marker through a
   normal projection commit.
4. Normal projection and intent draining replay retained facts into the current
   materialized table shape.

The actual fact family is `versioning/local_update/`. Its role files (`fact.rs`,
`encode.rs`, `author.rs`, `project.rs`, `api.rs`, `cli.rs`) stay under that
directory. State-summary diagnostics live with that family because `state-summary`
is the versioning/update diagnostic command.

`state-summary` is a diagnostic command owned by the local-update family. It
hashes schema-declared summary tables so rebuild output can be compared without
adding protocol meaning to core.

Queries are direct SQL readers, so core does not gate them automatically the way
it gates projection and intent commits. A query that touches materialized tables
must explicitly choose its storage-version behavior: require current storage,
support a documented old table shape, or be a maintenance/diagnostic read that
is allowed to inspect stale state.
