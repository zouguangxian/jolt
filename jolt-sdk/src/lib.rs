#![cfg_attr(not(any(feature = "host", feature = "guest-std")), no_std)]

extern crate jolt_sdk_macros;

// For no-std guest builds that pull in `alloc` (e.g., via postcard/serde),
// we must provide a global allocator and a panic handler somewhere in the final binary.
// Putting them in `jolt-sdk` keeps guest crates minimal.
#[cfg(all(feature = "guest-nostd", not(feature = "host"), target_os = "none"))]
#[global_allocator]
static JOLT_ALLOCATOR: ::zeroos::alloc::System = ::zeroos::alloc::System;

#[cfg(all(feature = "guest-nostd", not(feature = "host"), target_os = "none"))]
#[panic_handler]
fn __jolt_panic_handler(_info: &core::panic::PanicInfo) -> ! {
    // Best-effort termination for the emulator.
    crate::platform::platform_exit(1)
}

// Standard ZeroOS architecture and runtimes for guest builds
#[cfg(all(not(feature = "host"), target_arch = "riscv64"))]
pub mod platform;

#[cfg(any(feature = "host", feature = "guest-verifier"))]
pub mod host_utils;
#[cfg(any(feature = "host", feature = "guest-verifier"))]
pub use host_utils::*;





pub use jolt_platform::*;
pub use jolt_sdk_macros::provable;
pub use postcard;

use serde::{Deserialize, Serialize};

/// A wrapper type to mark guest program inputs as trusted_advice.
#[derive(Debug, Serialize, Deserialize)]
#[repr(transparent)]
pub struct TrustedAdvice<T> {
    value: T,
}

impl<T> TrustedAdvice<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T> From<T> for TrustedAdvice<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T> core::ops::Deref for TrustedAdvice<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// A wrapper type to mark guest program inputs as untrusted_advice.
#[derive(Debug, Serialize, Deserialize)]
#[repr(transparent)]
pub struct UntrustedAdvice<T> {
    value: T,
}

impl<T> UntrustedAdvice<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T> From<T> for UntrustedAdvice<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T> core::ops::Deref for UntrustedAdvice<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

// This is a dummy _HEAP_PTR to keep the compiler happy.
// It should never be used when compiled as a guest or with
// our custom allocator
#[no_mangle]
#[cfg(feature = "host")]
pub static mut _HEAP_PTR: u8 = 0;


// Re-export common types for the provable macro
#[cfg(feature = "host")]
pub use common::jolt_device::{JoltDevice, MemoryConfig, MemoryLayout};

#[cfg(feature = "host")]
pub use jolt_core::{
    field::JoltField,
    host::analyze,
    zkvm::JoltProverPreprocessing,
    zkvm::JoltVerifierPreprocessing,
    zkvm::JoltRV64IMAC,
    zkvm::RV64IMACJoltProof,
    zkvm::Jolt,
};
#[cfg(feature = "host")]
pub type F = jolt_core::ark_bn254::Fr;
#[cfg(feature = "host")]
pub type PCS = jolt_core::poly::commitment::dory::DoryCommitmentScheme;

// Note: `jolt_print!` / `jolt_println!` are `#[macro_export]` macros defined in
// `platform/ecall.rs`, so they are exported at the crate root automatically.
