# TODO: CLI Command Ownership

This document tracks cleanup of protocol `cli.rs` files so each user-facing
command is owned by the most relevant fact family.

## Goal

The target shape is:

```text
root CLI host -> protocol command host -> family cli.rs -> commands/queries -> author/encode
```

`src/protocol/cli.rs` stays a runtime host. It may open the runtime, build the
right `CommandContext`, provide vaults, submit `CommandOutput`, settle
command-visible work, and call core file helpers. It should not own protocol
argument parsing, selector policy, receipt formatting, or command-specific
business decisions.

A family `cli.rs` owns the human-facing surface for commands whose primary
object is that family: usage strings, argv parsing, selector resolution through
typed query helpers, calls to that family's command/query API, and terminal
formatting. It should not construct facts, call sibling `create.rs`/`encode.rs`
directly, drain the runtime, dispatch handlers, or persist state.

## Ownership Rule

Use the most relevant fact type:

1. If a CLI command authors one protocol fact family, that fact family owns the
   command's `cli.rs` surface.
2. If a command authors several facts, the owner is the primary user-visible
   object or policy fact. Other families expose narrow author/query helpers.
3. If a command is read-only, the owner is the family that owns the displayed
   rows. A multi-family view stays with the primary list/detail surface unless
   there is no honest primary fact family.
4. Selector resolution lives with the selected object. For example, file
   selectors should be resolved by file-owned helpers, not copied into message
   CLI code.
5. Core/runtime diagnostics with no protocol fact owner, such as replay and
   intent-registry inspection, may stay in the protocol/core host surface.

## Current Problems

- `src/protocol/content/message/cli.rs` is a bundle. It imports file,
  file-slice, reaction, and message-deletion modules and owns `react`,
  `send-file`, `files`, `save-file`, and `delete-message` even though those are
  better owned by the relevant reaction, file, or deletion fact families.
- `src/protocol/cli.rs` parses and constructs `connect` inline. The
  connection-request family should own the CLI parser/usage/receipt surface; the
  protocol host should only supply runtime context and submit the output.
- `src/protocol/auth/key_wrap/cli.rs` is a key-material bundle. Some commands
  are true key-wrap queries, but others are recipient-key, removal-frontier,
  local-history-node, or local-secret-retirement operations.
- Cross-family content display is not yet cleanly separated. `messages`,
  `view`, and `content-count` can stay message-owned while message rows are the
  primary display surface, but they should call narrow reaction/file helpers
  instead of importing broad sibling implementation modules.

## Target Moves

| Command | Target owner | Notes |
| --- | --- | --- |
| `send` | `content/message/cli.rs` | Already message-owned. |
| `generate` | `content/message/cli.rs` | Test/bulk version of message authoring. |
| `messages` | `content/message/cli.rs` | Message timeline is the primary displayed object. |
| `view` | `content/message/cli.rs` | Keep as message detail/timeline view; use narrow helpers for attached files and reactions. |
| `content-count` | `content/message/cli.rs` for now | Revisit if content count becomes a scope-level aggregate instead of message-row derived. |
| `react` | `content/reaction/cli.rs` | Message selector lookup should be a message query helper. |
| `delete-message` | `content/message_deletion/cli.rs` | The command authors a message-deletion fact. |
| `send-file` | `content/file/cli.rs` | File metadata/slices are the primary user-visible object; message authoring is a helper. |
| `files` | `content/file/cli.rs` | File rows own the displayed list. |
| `save-file` | `content/file/cli.rs` | File selector and payload IO are file-owned; file bytes still use core helpers. |
| `delete-file` | `content/file_deletion/cli.rs` | Already close to target; selector helpers should come from file. |
| `connect` | `connection/connection_request/cli.rs` | Move usage, parsing, and receipt formatting out of `src/protocol/cli.rs`. |
| `key-recipient` | `auth/recipient_key/cli.rs` or `auth/local_recipient_key/cli.rs` | Decide based on whether the user-visible result is the shared recipient key or the retained local key material. |
| `key-rotate-recipient` | `auth/recipient_key/cli.rs` or `auth/local_recipient_key/cli.rs` | Same owner as `key-recipient`. |
| `key-frontier` | `auth/removal_frontier/cli.rs` | The frontier is the visible object; local secrets are helpers. |
| `key-node` | `auth/local_history_node_secret/cli.rs` | The command authors retained local history-node secret material. |
| `key-wrap` | `auth/key_wrap/cli.rs` | True key-wrap lookup/query. |
| `key-access` | `auth/key_wrap/cli.rs` for now | Revisit once access status helpers are split by frontier/key owner. |
| `key-derive` | `auth/key_wrap/cli.rs` for now | This is a handler-settlement surface; split after key-material command ownership is clearer. |
| `keys` | `auth/key_wrap/cli.rs` for now | Status is a cross-key-material aggregate; may need a dedicated owner once broad key-material files are split. |
| `chop-now` | `auth/local_secret_retirement/cli.rs` | The command retires local secret material and may rotate recipient keys as helper work. |

## Work Plan

1. Inventory `MATCH_COMMANDS` and annotate the intended family owner for every
   command.
2. Add narrow selector/query helpers where a command needs another family's
   object, such as resolving a message selector for `react` or a file selector
   for `delete-file`.
3. Move content commands out of `content/message/cli.rs` first. They are the
   clearest mismatch and will prove the pattern for cross-family helpers.
4. Move `connect` into `connection/connection_request/cli.rs`.
5. Split key-material CLI ownership after the key-material role files are less
   bundled. Do not move parse/format code into another broad dumping ground.
6. Update `src/protocol/registry.rs` usage paths and `src/protocol/cli.rs`
   host functions as each command moves.
7. Add guardrails that fail when a family `cli.rs` imports broad sibling
   implementation modules instead of narrow helper APIs, and when
   `src/protocol/cli.rs` grows command-specific parsing or formatting.
8. Keep black-box `con` CLI tests green for each moved command.

## Definition Of Done

- Each command's usage string and parser live with the most relevant fact
  family.
- `src/protocol/cli.rs` contains only runtime hosting, context/vault setup,
  command submission, settlement, and delegation to family CLI functions.
- `content/message/cli.rs` no longer owns reaction, file, file-deletion, or
  message-deletion commands.
- File IO still goes through core CLI file helpers.
- Existing black-box CLI behavior and output remain stable unless a command is
  intentionally renamed or redesigned.
