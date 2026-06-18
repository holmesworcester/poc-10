# Message Search Index Plan

This note describes a search index design for opened message contents in
poc-10. The goal is local search without scanning message rows, while keeping
purge semantics strong enough that deleted or purged content does not remain
searchable through hits or completion.

The recommended direction is to use SQLite FTS5 as the local query engine, but
to keep index maintenance inside poc-10's projection, intent, replay, and
effect-commit model. SQLite triggers are a useful reference point, but they
should not be the primary correctness boundary for this runtime.

## Current Boundary

poc-10 treats retained facts as durable truth and projected rows as derived
state. Projectors and handlers return explicit effects, and core commits those
effects atomically with queue progress. Replay clears schema-declared derived
state and rebuilds it by running the ordinary projection and handler paths in
replay mode.

Search indexes should follow the same rule. An index over opened message text
is derived local state. It should be declared, reset, rebuilt, and purged by the
same machinery that owns other derived rows. Query code may use SQLite
efficiently, but index maintenance should be visible as an effect that can be
reviewed with the fact family that creates or removes message content.

## Threat Model Requirement

Search index deletion is security-sensitive. After a message, channel, or
workspace is purged, local search must not expose stale state through:

- ordinary search results;
- prefix search-as-you-type;
- completion vocabulary;
- snippets;
- stale FTS rowids that can be joined back later;
- FTS shadow tables, if the database remains locally inspectable.

Filtering query results against live message rows is necessary but not
sufficient if completion reads index vocabulary, or if the threat model treats
stale local index tokens as sensitive. Purge must remove or retire the index
state itself, not merely hide query rows.

## Signal Reference

Signal validates SQLite FTS5 as a practical local search engine, but also shows
why FTS needs explicit lifecycle management.

Signal Android uses an FTS5 external-content table named `message_fts` over the
main `message` table. The FTS rowid is the message `_id`. SQLite triggers insert
on message creation, delete from FTS on message deletion, and delete-then-insert
on message update. Query text is split into tokens, quotes inside each token
are escaped, and `*` is appended to each token so FTS performs prefix matching
for search-as-you-type. Android also has rebuild, optimize, corruption recovery,
and trigger-fix paths. It tried FTS5 `secure-delete`, then disabled it because
the overhead was too high; the comments say their manual approach preserves the
safety guarantee while making bulk deletes cheaper.

Signal Desktop also uses FTS5. Current Desktop schema has a generated
`searchableText` column on messages, derived from body or poll question, and an
FTS table `messages_fts(body, tokenize = 'signal_tokenizer')`. Triggers keep
the FTS table current on insert, update, delete, and view-once changes. Desktop
normalizes query text with the same tokenizer, quotes tokens, appends `*`, and
uses `MATCH`. It first materializes FTS rowids into temporary tables, then joins
and sorts against ordinary message indexes. On full local data removal, Desktop
drops the message delete trigger for performance, deletes `messages_fts`
directly, deletes messages, optimizes FTS, and recreates the trigger. Desktop
currently enables FTS5 `secure-delete`.

The useful lessons are:

- FTS5 is the right local primitive for text search and prefix matching.
- The rowid/docid should be deterministic and tied to the source message row.
- Search query normalization should match index tokenization.
- Bulk delete and rebuild paths must be explicit and tested.
- FTS optimize, rebuild, and integrity handling are part of the feature.
- Triggers work in a conventional app database, but they hide maintenance work
  from poc-10's projection and replay model.

## Options Considered

### Scan Opened Message Rows

Scanning opened message rows is simple, but it does not support fast
search-as-you-type or large workspaces. It also creates pressure to load broad
plaintext rows into Rust and filter there, which conflicts with the runtime's
SQL query rules.

### SQLite FTS5 With Triggers

SQLite triggers provide transactionally automatic maintenance. Insert, update,
and delete on the source table can update FTS in the same SQLite transaction.
This is the Signal model.

For poc-10, triggers have the wrong ownership shape. They create hidden derived
state outside `ProjectionOutput` and `RuntimeEffects`, make replay ordering more
implicit, and make purge auditing depend on SQLite side effects rather than on
visible fact-family output. They also make protocol customization harder:
projectors cannot easily declare which field, scope, or token policy they are
using except by creating bespoke trigger SQL.

### Intent-Only Indexing

An index intent can work if it is source-derived and convergent. The durable
intent should not carry plaintext to add to the index. It should name the
source:

```text
reindex_message_text(workspace_id, message_id)
```

The handler reads current opened-message state. If the message row exists, it
upserts the current text into the index. If the row is gone, it deletes the doc
from the index. This makes add/remove races converge.

The risk is query fencing. If purge only queues a later reindex intent, search
must not run against stale index state before that intent applies. That can be
handled by draining relevant index intents before search, by joining and
filtering against live rows, or by maintaining a pending-purge overlay. However,
completion vocabulary is still difficult if stale FTS terms remain until the
intent runs.

Intent-only indexing is a good repair and background-rebuild mechanism. Purge
should still have a synchronous index removal effect.

### Core-Owned Index Effects

The preferred shape is a core-owned low-level index effect with
protocol-declared semantics. Core should know how to apply index mutations
atomically, reset them during replay, and enforce purge ordering. Protocol
should define what text is indexed, what scope owns it, and how search results
are loaded.

This keeps search common enough to have core plumbing, while still leaving
protocol modules free to define domain-specific indexes.

## Recommended Ownership

Core owns:

- index registration and stable index names;
- schema lifecycle for index tables and shadow tables;
- atomic commit of index mutations with projection or handler output;
- replay reset and replay-mode rebuild ordering;
- validation that an index mutation targets a declared index;
- query fencing rules for pending purge or pending index work;
- FTS optimize, rebuild, integrity-check, and reset hooks.

Core does not own:

- message-text semantics;
- which message states are searchable;
- token policy beyond invoking the registered index implementation;
- result hydration or authorization filters;
- shared encrypted index fact formats.

Protocol owns:

- source rows and fact-family projection rules;
- index specs for messages, facts, or future attachment text;
- doc ids, scope ids, and sort keys;
- field extraction, such as message body versus poll question;
- deletion and purge policy per scope;
- result query modules and user-visible search behavior.

## Index Effect Shape

The low-level effect should be explicit and scope-aware:

```rust
enum IndexMutation {
    UpsertDoc {
        index: SearchIndexId,
        scope: SearchScopeId,
        doc: SearchDocId,
        fields: SearchFields,
        sort_key: SearchSortKey,
    },
    DeleteDoc {
        index: SearchIndexId,
        scope: SearchScopeId,
        doc: SearchDocId,
    },
    DeleteScope {
        index: SearchIndexId,
        scope: SearchScopeId,
    },
    RetireScopeGeneration {
        index: SearchIndexId,
        scope: SearchScopeId,
        generation: SearchGeneration,
    },
}
```

`UpsertDoc` is idempotent for the same `(index, scope, doc)`. `DeleteDoc` is
idempotent if the doc is already absent. `DeleteScope` is idempotent if the
scope is already empty or retired. These properties matter because replay,
repair, and convergent reindex intents may repeat work.

The initial message index can use:

- index: `messages`;
- scope: workspace id, or workspace plus channel if channel purge needs a
  cheap synchronous boundary;
- doc: opened message id;
- fields: body text;
- sort key: received or authored message order already used by message queries.

## SQLite Storage Shape

The local implementation should use SQLite FTS5. Two table modes are plausible.

External-content FTS:

- stores FTS postings while source text remains in `opened_message_rows`;
- supports snippets through the live source table;
- requires careful manual insert/delete sequencing;
- should not use triggers;
- search should join candidates back to live source rows.

Contentless FTS with `contentless_delete=1`:

- avoids a second retrievable plaintext body copy in the FTS table;
- still stores token/posting data, so purge must delete postings;
- makes snippets harder because FTS cannot retrieve original text;
- is attractive if minimizing duplicate plaintext matters more than snippets.

The first implementation should choose based on user-visible needs. If snippets
are required immediately, external-content FTS is easier. If snippets can wait,
contentless FTS is the cleaner local-minimization default.

In both cases, the FTS rowid should be derived from the stable message doc id.
That makes upsert/delete exact and makes replay deterministic.

## Projection And Handler Flow

Message creation or opening:

1. The message projector materializes or updates the opened-message row.
2. The same projection output emits `IndexMutation::UpsertDoc`.
3. Core commits the row mutation and index mutation in one SQLite transaction.

Message edit or completion:

1. The owning projector updates the opened-message row.
2. The same output emits `UpsertDoc` for the current text.
3. The index implementation replaces the prior doc contents.

Message purge:

1. The owning projector or handler deletes the opened-message row.
2. The same output emits `DeleteDoc`.
3. Core commits both in one transaction.

Channel or workspace purge:

1. The purge owner emits source-row deletes for that scope.
2. The same output emits `DeleteScope`.
3. Core removes or retires the whole scope before the purge is observable to
   search.

Background repair:

1. A `reindex_message_text` intent may be queued for non-critical rebuild work.
2. The handler reads current source state and converges the index to that state.
3. If source state is absent, the handler deletes the doc.

Purge must not depend only on background repair. Repair can fix drift; purge
must synchronously remove or retire searchable state.

## Query Flow

Search-as-you-type should use FTS prefix matching:

1. Normalize the query with the same tokenizer policy as the index.
2. Escape double quotes inside each token.
3. Wrap each token in quotes.
4. Append `*` to each token.
5. Join tokens with spaces and use `MATCH`.

The search query should:

1. Ask FTS for candidate doc ids.
2. Join candidates against live opened-message rows.
3. Apply workspace, channel, or thread filters.
4. Sort by the protocol sort key.
5. Limit results.
6. Hydrate only the bounded result set.

If direct virtual-table joins become slow, use the Signal Desktop pattern:
materialize matching rowids into a temporary table, sort and limit through
ordinary message indexes, then join back to FTS only for snippets.

## Completion

Prefix search over messages and completion suggestions are separate features.
FTS `MATCH 'term*'` supports prefix search. Completion suggestions usually read
index vocabulary, for example through `fts5vocab`.

Completion is more sensitive to purge bugs because stale terms can leak even if
search results are filtered against live messages. Completion should ship only
after one of these is true:

- the underlying index deletion is synchronous and scope-safe;
- vocabulary reads can be filtered to live, non-purged scopes;
- completion is backed by a separate scope-generation index whose generations
  can be retired atomically.

The first release should implement search-as-you-type results before exposing
completion suggestions.

## Bulk Delete Cost

Deleting one FTS doc is proportional to the indexed tokens for that doc plus FTS
maintenance overhead. This is acceptable for individual message purge.

Deleting a whole channel by deleting each doc is proportional to all indexed
tokens in the channel. That can be expensive and must still complete before the
purge is considered complete if stale local index terms are in scope for the
threat model.

The scalable shape is a scope-aware index:

- each doc records its purge scope;
- whole-scope purge uses `DeleteScope` or scope generation retirement;
- queries ignore retired scopes immediately;
- physical FTS row deletion and optimize can run after the scope is retired if
  retired postings are no longer queryable or decryptable.

For plaintext local FTS, tombstoning a scope is not enough if local shadow-table
tokens are considered sensitive. In that stricter model, the purge path must
physically delete the scope's FTS rows, or the implementation must use
per-scope encrypted/HMAC token material that can be retired by dropping a key.

## Replay And Versioning

Index tables are derived state and should be schema-declared reset tables.
Replay should clear them with other derived state, queue retained facts in
replay mode, and rebuild search rows through ordinary projection and replayable
handler output.

Index version changes should be explicit. A protocol index spec should carry a
version or generation. If tokenization, indexed fields, or scope boundaries
change, replay should reset and rebuild the affected index. If a live database
detects an old index version, it should request rebuild rather than attempting
ad hoc migration through hidden trigger behavior.

Tests should cover:

- retained facts replay into equivalent index rows;
- old facts replay correctly into a newer index spec;
- replay suppresses live-only indexing work;
- purged facts do not recreate searchable docs;
- index reset order does not depend on SQLite trigger side effects.

## Future Shared Encrypted Index Facts

Local FTS is not the right shape for shared encrypted search facts. Shared
search should use a protocol-level postings format.

A future encrypted index can publish facts like:

- scope id and index generation;
- normalized token or prefix transformed with a keyed HMAC;
- encrypted posting lists or encrypted doc references;
- range metadata for lazy sync;
- generation retirement facts.

A peer that has the search key for a scope can compute HMAC query tokens,
download postings before downloading all messages, identify matching ranges,
then sync only the message ranges needed to hydrate results. Peers without the
key see opaque tokens and encrypted postings.

Purge is handled by generation or key retirement. Once a scope generation is
retired, old postings are no longer queryable or decryptable even if physical
garbage collection has not completed. This model fits shared search better than
SQLite FTS because it makes token visibility, access control, and lazy sync part
of the protocol.

## Implementation Phases

1. Add search index registration and `IndexMutation` effect types.
2. Add a local SQLite FTS5 implementation behind the registered index.
3. Declare index tables in schema reset/replay lifecycle.
4. Add message index spec for opened message contents.
5. Emit `UpsertDoc`, `DeleteDoc`, and `DeleteScope` from message projection and
   purge paths.
6. Add bounded search query API using FTS instead of scans.
7. Add replay, purge, edit, and channel-purge tests.
8. Add optimize, integrity-check, and rebuild maintenance.
9. Add completion only after scope-safe vocabulary behavior is designed.
10. Design encrypted shared index facts separately from local FTS.

## Open Decisions

- Whether the first local index should be external-content FTS or contentless
  FTS.
- Whether the initial purge scope is workspace, channel, thread, or message.
- Whether snippets are required in the first search UI.
- Whether search queries should drain pending index intents or rely only on
  synchronous purge effects.
- Whether core should expose only `IndexMutation` or a more general
  protocol-owned SQL effect for specialized indexes.
- How strict the local database inspection threat model is for stale FTS shadow
  table tokens after scope tombstoning.
