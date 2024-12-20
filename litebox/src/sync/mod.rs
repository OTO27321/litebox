//! Higher-level synchronization primitives

mod condvar;
mod mutex;
mod rwlock;

#[cfg(feature = "lock_tracing")]
mod lock_tracing;
