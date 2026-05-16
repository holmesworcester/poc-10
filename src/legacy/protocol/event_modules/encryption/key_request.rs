//! Event module for targeted key-healing requests.
//!
//! A key request is a shared event owned by the encryption domain. It depends
//! on the requester endpoint, responder endpoint, removal frontier, and
//! recipient key, but it does not perform cryptographic wrapping itself.
//! Projection only queues bounded worker work; the encryption worker owns
//! deciding whether local key material can answer the request.

pub mod commands;
pub mod layout;
pub mod projector;
pub mod queries;
pub mod rows;
pub mod types;
