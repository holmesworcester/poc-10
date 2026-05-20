//! Command registry for the concrete `match` protocol.
//!
//! This file is intentionally just the table: command names, usage strings,
//! and the app-level entry point that core should call. Parsing and output
//! formatting stay in the fact-scope `cli.rs` modules. Runtime opening and
//! final printing are core app responsibilities.

use crate::core::cli::CliCommand;
use crate::protocol::command_handlers as command;
use crate::protocol::facts::sync;
use crate::protocol::facts::{content, encryption, identity};

pub use crate::protocol::command_handlers::MatchCliContext;

pub const MATCH_COMMANDS: &[CliCommand<MatchCliContext>] = &[
    CliCommand {
        name: "create-workspace",
        usage: identity::workspace::cli::CREATE_WORKSPACE_USAGE,
        help: "",
        run: command::create_workspace,
    },
    CliCommand {
        name: "invite",
        usage: identity::invite::cli::INVITE_USAGE,
        help: "",
        run: command::invite,
    },
    CliCommand {
        name: "invite-server",
        usage: identity::invite::cli::INVITE_SERVER_USAGE,
        help: "",
        run: command::invite_server,
    },
    CliCommand {
        name: "accept",
        usage: identity::invite::cli::ACCEPT_USAGE,
        help: "",
        run: command::accept,
    },
    CliCommand {
        name: "accept-invite-server",
        usage: identity::invite::cli::ACCEPT_INVITE_SERVER_USAGE,
        help: "",
        run: command::accept_invite_server,
    },
    CliCommand {
        name: "link",
        usage: identity::invite::cli::LINK_USAGE,
        help: "",
        run: command::link,
    },
    CliCommand {
        name: "accept-link",
        usage: identity::invite::cli::ACCEPT_LINK_USAGE,
        help: "",
        run: command::accept_link,
    },
    CliCommand {
        name: "identity",
        usage: identity::endpoint_shared::cli::IDENTITY_USAGE,
        help: "",
        run: command::identity,
    },
    CliCommand {
        name: "peers",
        usage: identity::endpoint_shared::cli::PEERS_USAGE,
        help: "",
        run: command::peers,
    },
    CliCommand {
        name: "workspaces",
        usage: identity::workspace::cli::WORKSPACES_USAGE,
        help: "",
        run: command::workspaces,
    },
    CliCommand {
        name: "users",
        usage: identity::user::cli::USERS_USAGE,
        help: "",
        run: command::users,
    },
    CliCommand {
        name: "key-recipient",
        usage: encryption::cli::KEY_RECIPIENT_USAGE,
        help: "",
        run: command::key_recipient,
    },
    CliCommand {
        name: "key-rotate-recipient",
        usage: encryption::cli::KEY_ROTATE_RECIPIENT_USAGE,
        help: "",
        run: command::key_recipient_rotation,
    },
    CliCommand {
        name: "key-frontier",
        usage: encryption::cli::KEY_FRONTIER_USAGE,
        help: "",
        run: command::key_frontier,
    },
    CliCommand {
        name: "key-wrap",
        usage: encryption::cli::KEY_WRAP_USAGE,
        help: "",
        run: command::key_wrap,
    },
    CliCommand {
        name: "key-access",
        usage: encryption::cli::KEY_ACCESS_USAGE,
        help: "",
        run: command::key_access,
    },
    CliCommand {
        name: "key-derive",
        usage: command::KEY_DERIVE_USAGE,
        help: "",
        run: command::key_derive,
    },
    CliCommand {
        name: "key-node",
        usage: command::KEY_NODE_USAGE,
        help: "",
        run: command::key_node,
    },
    CliCommand {
        name: "keys",
        usage: command::KEYS_USAGE,
        help: "",
        run: command::keys,
    },
    CliCommand {
        name: "chop-now",
        usage: command::CHOP_NOW_USAGE,
        help: "",
        run: command::chop_now,
    },
    CliCommand {
        name: "disappearing-set",
        usage: command::DISAPPEARING_SET_USAGE,
        help: "",
        run: command::disappearing_set,
    },
    CliCommand {
        name: "disappearing-status",
        usage: command::DISAPPEARING_STATUS_USAGE,
        help: "",
        run: command::disappearing_status,
    },
    CliCommand {
        name: "disappearing-tighten",
        usage: command::DISAPPEARING_TIGHTEN_USAGE,
        help: "",
        run: command::disappearing_tighten,
    },
    CliCommand {
        name: "disappearing-compact",
        usage: command::DISAPPEARING_COMPACT_USAGE,
        help: "",
        run: command::disappearing_compact,
    },
    CliCommand {
        name: "send",
        usage: content::message::cli::SEND_USAGE,
        help: "",
        run: command::send,
    },
    CliCommand {
        name: "react",
        usage: content::message::cli::REACT_USAGE,
        help: "",
        run: command::react,
    },
    CliCommand {
        name: "send-file",
        usage: content::message::cli::SEND_FILE_USAGE,
        help: "",
        run: command::send_file,
    },
    CliCommand {
        name: "files",
        usage: content::message::cli::FILES_USAGE,
        help: "",
        run: command::files,
    },
    CliCommand {
        name: "save-file",
        usage: content::message::cli::SAVE_FILE_USAGE,
        help: "",
        run: command::save_file,
    },
    CliCommand {
        name: "delete-file",
        usage: command::DELETE_FILE_USAGE,
        help: "",
        run: command::delete_file,
    },
    CliCommand {
        name: "delete-message",
        usage: content::message::cli::DELETE_MESSAGE_USAGE,
        help: "",
        run: command::delete_message,
    },
    CliCommand {
        name: "messages",
        usage: content::message::cli::MESSAGES_USAGE,
        help: "",
        run: command::messages,
    },
    CliCommand {
        name: "view",
        usage: content::message::cli::VIEW_USAGE,
        help: "",
        run: command::view,
    },
    CliCommand {
        name: "grant-admin",
        usage: identity::admin::cli::GRANT_ADMIN_USAGE,
        help: "",
        run: command::grant_admin,
    },
    CliCommand {
        name: "generate",
        usage: content::event::cli::GENERATE_USAGE,
        help: "",
        run: command::generate,
    },
    CliCommand {
        name: "generate-deps",
        usage: sync::cascade_fact::cli::GENERATE_DEPS_USAGE,
        help: "",
        run: command::generate_deps,
    },
    CliCommand {
        name: "replay-deps-reverse",
        usage: sync::cascade_fact::cli::REPLAY_DEPS_REVERSE_USAGE,
        help: "",
        run: command::replay_deps_reverse,
    },
    CliCommand {
        name: "sync-status",
        usage: command::SYNC_STATUS_USAGE,
        help: "",
        run: command::sync_status,
    },
    CliCommand {
        name: "negentropy-drain",
        usage: command::NEGENTROPY_DRAIN_USAGE,
        help: "",
        run: command::negentropy_drain,
    },
    CliCommand {
        name: "content-count",
        usage: content::event::cli::CONTENT_COUNT_USAGE,
        help: "",
        run: command::content_count,
    },
    CliCommand {
        name: "clock",
        usage: command::CLOCK_USAGE,
        help: "",
        run: command::clock,
    },
    CliCommand {
        name: "count",
        usage: identity::workspace::cli::COUNT_USAGE,
        help: "",
        run: command::count,
    },
];
