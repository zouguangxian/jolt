//! Jolt zkVM guest platform (ZeroOS)
//!
//! Layout mirrors `ZeroOS/platforms/spike-platform/src/`:
//! - `boot.rs`: `__platform_bootstrap()`
//! - `trap.rs`: `trap_handler(..)`
//! - `lib.rs`: platform ABI (`platform_exit`, `__debug_write`, optional syscall shim)

mod boot;
mod trap;
pub mod ecall;
pub(crate) mod lib;

pub use lib::{exit, platform_exit};
