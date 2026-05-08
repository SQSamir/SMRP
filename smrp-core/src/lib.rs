#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_possible_truncation)]

//! `smrp-core` — shared types, crypto, transport, and handshake logic for the
//! Secure Minimal Reliable Protocol.

pub mod conn;
pub mod constants;
pub mod crypto;
pub mod error;
pub mod handshake;
pub mod packet;
pub mod replay;
pub mod session;
pub mod transport;
