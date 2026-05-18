//! Hybrid-polish attempt: typed `InviteAuthority` classifies the signer up
//! front, then dispatches to one of two path functions, each preceded by an
//! English "Required facts" + "Rules" docstring. The invariant battery is
//! wired up inside the `tests` submodule of `project.rs`.

pub mod project;
