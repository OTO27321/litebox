//! # LiteBox
//!
//! > A security-focused library OS.
//!
//! LiteBox exposes a [`nix`](https://docs.rs/nix)/[`rustix`](https://docs.rs/rustix)-like interface
//! "above" when it is provided a `Platform` interface "below".
//!
//! To use LiteBox, you must provide a type that implements the [`platform::Provider`] trait; then,
//! one obtains a Rust-friendly POSIX-like interface (i.e., "nix-like" interface) via the rest of
//! the modules in this crate.

/// The underlying platform upon which LiteBox resides.
pub mod platform {
    /// A provider of a platform upon which LiteBox can execute.
    pub trait Provider {}
}

/// File-system related functionality
pub mod fs {}

/// Network-related functionality
pub mod net {}
