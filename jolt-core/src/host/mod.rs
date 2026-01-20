#![allow(clippy::type_complexity)]

use std::path::PathBuf;

#[cfg(feature = "host")]
pub mod analyze;
#[cfg(feature = "host")]
pub mod program;
#[cfg(all(feature = "host", not(target_arch = "wasm32")))]
pub mod toolchain;

pub const TOOLCHAIN_VERSION: &str = "1.89.0";

#[derive(Clone)]
pub struct Program {
    guest: String,
    func: Option<String>,
    /// Total linked RAM size (i.e., linker `MEMORY_SIZE`), if discoverable from ELF symbols.
    ///
    /// For our linker templates, `__stack_top` is placed at the top of RAM, so:
    ///   ram_size = __stack_top - RAM_START_ADDRESS.
    ram_size: Option<u64>,
    memory_size: u64,
    stack_size: u64,
    heap_size: u64,
    max_input_size: u64,
    max_untrusted_advice_size: u64,
    max_trusted_advice_size: u64,
    max_output_size: u64,
    std: bool,
    pub elf: Option<PathBuf>,
}

pub const DEFAULT_TARGET_DIR: &str = "/tmp/jolt-guest-targets";
