# Versioning

`versioning` is a protocol scope. It is not itself a fact family.

This scope owns one release constant, `CURRENT_PROTOCOL_VERSION`, and the code
that compares projected release-marker state with that constant. The normal
repair loop is:

1. `check_version` is a recurring intent.
2. If the projected marker is missing or stale, it authors a local
   `update` fact.
3. The `update` fact projects the current marker row and requests a rebuild of
   derived state.
4. Normal projection and intent draining replay retained facts into the current
   materialized table shape.

The actual fact family is `versioning/update/`. Its role files (`fact.rs`,
`encode.rs`, `author.rs`, `project.rs`, `api.rs`, `cli.rs`) stay under that
directory. Scope-level files such as `queries.rs`, `cli.rs`, and
`check_version.rs` own versioning-wide reads, diagnostics, and lifecycle work
that are not themselves fact-family roles.

`state-summary` is a diagnostic command for the versioning scope. It hashes
schema-declared summary tables so rebuild output can be compared without adding
protocol meaning to core.
