use crate::field::JoltField;
use crate::guest;
use crate::host::analyze::ProgramSummary;
#[cfg(not(target_arch = "wasm32"))]


use crate::host::{Program, DEFAULT_TARGET_DIR, };
use common::constants::{
    DEFAULT_MAX_INPUT_SIZE, DEFAULT_MAX_OUTPUT_SIZE, DEFAULT_MAX_TRUSTED_ADVICE_SIZE,
    DEFAULT_MAX_UNTRUSTED_ADVICE_SIZE, DEFAULT_MEMORY_SIZE, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE,
    JOLT_ABI_VERSION,
    RAM_START_ADDRESS,
    
};
use common::jolt_device::{JoltDevice, MemoryConfig};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use object::{Object, ObjectSymbol};

use std::io;
use tracer::emulator::memory::Memory;
use tracer::instruction::{Cycle, Instruction};
use tracer::LazyTraceIterator;
use tracing::info;

impl Program {
    pub fn new(guest: &str) -> Self {
        Self {
            guest: guest.to_string(),
            func: None,
            ram_size: None,
            memory_size: DEFAULT_MEMORY_SIZE,
            stack_size: DEFAULT_STACK_SIZE,
            heap_size: DEFAULT_HEAP_SIZE,
            max_input_size: DEFAULT_MAX_INPUT_SIZE,
            max_untrusted_advice_size: DEFAULT_MAX_UNTRUSTED_ADVICE_SIZE,
            max_trusted_advice_size: DEFAULT_MAX_TRUSTED_ADVICE_SIZE,
            max_output_size: DEFAULT_MAX_OUTPUT_SIZE,
            std: false,
            elf: None,
        }
    }

    pub fn set_std(&mut self, std: bool) {
        self.std = std;
    }

    pub fn set_func(&mut self, func: &str) {
        self.func = Some(func.to_string())
    }

    pub fn set_memory_config(&mut self, memory_config: MemoryConfig) {
        self.set_memory_size(memory_config.memory_size);
        self.set_stack_size(memory_config.stack_size);
        self.set_max_input_size(memory_config.max_input_size);
        self.set_max_trusted_advice_size(memory_config.max_trusted_advice_size);
        self.set_max_untrusted_advice_size(memory_config.max_untrusted_advice_size);
        self.set_max_output_size(memory_config.max_output_size);
    }

    pub fn set_memory_size(&mut self, len: u64) {
        self.memory_size = len;
    }

    pub fn set_stack_size(&mut self, len: u64) {
        self.stack_size = len;
    }

    pub fn set_heap_size(&mut self, len: u64) {
        self.heap_size = len;
    }

    pub fn set_max_input_size(&mut self, size: u64) {
        self.max_input_size = size;
    }

    pub fn set_max_trusted_advice_size(&mut self, size: u64) {
        self.max_trusted_advice_size = size;
    }

    pub fn set_max_untrusted_advice_size(&mut self, size: u64) {
        self.max_untrusted_advice_size = size;
    }

    pub fn set_max_output_size(&mut self, size: u64) {
        self.max_output_size = size;
    }

    /// Build a `MemoryConfig` using the sizes currently stored on this `Program`.
    ///
    /// After `Program::build*`, these sizes are expected to have been updated from ELF symbols
    /// (e.g., `__jolt_max_*`, `__heap_*`, `__stack_*`), making the ELF the source of truth.
    pub fn discovered_memory_config(&self, program_size: u64) -> MemoryConfig {
        let memory_size = if let Some(ram_size) = self.ram_size {
            ram_size
                .saturating_sub(program_size)
                .saturating_sub(self.stack_size)
        } else {
            self.memory_size
        };
        MemoryConfig {
            memory_size,
            stack_size: self.stack_size,
            max_input_size: self.max_input_size,
            max_untrusted_advice_size: self.max_untrusted_advice_size,
            max_trusted_advice_size: self.max_trusted_advice_size,
            max_output_size: self.max_output_size,
            program_size: Some(program_size),
        }
    }

    pub fn build(&mut self, target_dir: &str) {
        self.build_with_channel(target_dir, "stable");
    }

    #[tracing::instrument(skip_all, name = "Program::build")]
    
    fn discover_memory_sizes(&mut self, elf_contents: &[u8]) {
        if let Ok(elf) = object::File::parse(elf_contents) {
            let mut heap_start = None;
            let mut heap_end = None;
            let mut stack_top = None;
            let mut stack_bottom = None;
            let mut max_input = None;
            let mut max_output = None;
            let mut max_trusted = None;
            let mut max_untrusted = None;
            let mut abi_version = None;

            for symbol in elf.symbols() {
                if let Ok(name) = symbol.name() {
                    match name {
                        "__heap_start" => heap_start = Some(symbol.address()),
                        "__heap_end" => heap_end = Some(symbol.address()),
                        "__stack_top" => stack_top = Some(symbol.address()),
                        "__stack_bottom" => stack_bottom = Some(symbol.address()),
                        "__jolt_max_input_size" => max_input = Some(symbol.address()),
                        "__jolt_max_output_size" => max_output = Some(symbol.address()),
                        "__jolt_max_trusted_advice_size" => max_trusted = Some(symbol.address()),
                        "__jolt_max_untrusted_advice_size" => max_untrusted = Some(symbol.address()),
                        "__jolt_abi_version" => abi_version = Some(symbol.address()),
                        _ => {}
                    }
                }
            }

            if let Some(v) = abi_version {
                if v != 0 && v != JOLT_ABI_VERSION {
                    panic!(
                        "Unsupported Jolt guest ABI version: ELF has {}, host supports {}",
                        v, JOLT_ABI_VERSION
                    );
                }
            }

            if let (Some(start), Some(end)) = (heap_start, heap_end) {
                let size = end.saturating_sub(start);
                info!("Discovered heap size from ELF: {} bytes", size);
                self.heap_size = size;
            }

            if let (Some(bottom), Some(top)) = (stack_bottom, stack_top) {
                let size = top.saturating_sub(bottom);
                info!("Discovered stack size from ELF: {} bytes", size);
                self.stack_size = size;
            }
            if let Some(top) = stack_top {
                // In our linker templates, `__stack_top` is placed at the top of RAM.
                self.ram_size = Some(top.saturating_sub(RAM_START_ADDRESS));
            }

            if let Some(size) = max_input {
                if size != 0 {
                    info!("Discovered max input size from ELF: {} bytes", size);
                    self.max_input_size = size;
                }
            }
            if let Some(size) = max_output {
                if size != 0 {
                    info!("Discovered max output size from ELF: {} bytes", size);
                    self.max_output_size = size;
                }
            }
            if let Some(size) = max_trusted {
                if size != 0 {
                    info!("Discovered max trusted advice size from ELF: {} bytes", size);
                    self.max_trusted_advice_size = size;
                }
            }
            if let Some(size) = max_untrusted {
                if size != 0 {
                    info!("Discovered max untrusted advice size from ELF: {} bytes", size);
                    self.max_untrusted_advice_size = size;
                }
            }
            
            // Note: `memory_size` is used by the emulator as the heap capacity above the
            // (program + stack) region. If `ram_size` is available, callers should derive
            // the effective heap size from it (see `discovered_memory_config`).
        }
    }

    pub fn build_with_channel(&mut self, target_dir: &str, _channel: &str) {
        if self.elf.is_none() {
            // Use cargo-jolt to build the guest program.
            //
            // IMPORTANT: don't assume the user's PATH `cargo-jolt` is the same version as this
            // workspace (it might be an older installed binary with different CLI flags).
            //
            // - If `CARGO_JOLT_PATH` is set: run that binary directly (fast path).
            // - Otherwise: run the workspace cargo-jolt via `cargo run -p cargo-jolt --release -- ...`
            //   so the CLI flags always match this checkout.
            // Optional fast-path: allow users to point to an external `cargo-jolt` binary.
            //
            // However, we must not assume it matches this workspace's CLI flags. In particular,
            // older binaries may not understand `--mode`, and could accidentally forward it to
            // `cargo build`, producing confusing errors like:
            //   "error: unexpected argument '--mode' found"
            //
            // So we probe for `--mode` support and fall back to the workspace `cargo run -p cargo-jolt`
            // if the external binary looks incompatible.
            let cargo_jolt_path = std::env::var("CARGO_JOLT_PATH").ok().filter(|path| {
                Self::cargo_jolt_supports_mode_flag(path).unwrap_or(false)
            });

            // Build base arguments for cargo-jolt.
            //
            // Important: cargo profile flags like `--release` must be passed to *cargo* (after `--`),
            // not to cargo-jolt itself.
            let mut args = vec![
                "jolt".to_string(),
                "build".to_string(),
                "-p".to_string(),
                self.guest.clone(),
            ];

            // Select build mode explicitly.
            args.push("--mode".to_string());
            args.push(if self.std {
                "std".to_string()
            } else {
                "no-std".to_string()
            });

            // Do NOT pass memory sizing flags here.
            // `cargo-jolt` owns the linker template, and sizing should come from the guest
            // crate's `[package.metadata.jolt]` (or explicit `cargo jolt build` CLI overrides).


            // Create per-guest target directory (isolates builds)
            let guest_target_dir = format!(
                "{}/{}-{}",
                target_dir,
                self.guest,
                self.func.as_ref().unwrap_or(&"".to_string())
            );

            // Add separator for cargo passthrough args
            args.push("--".to_string());

            // Always build release guests (Program expects `.../release/<guest>` output).
            args.push("--release".to_string());

            // Pass --target-dir to cargo (not cargo-jolt)
            args.push("--target-dir".to_string());
            args.push(guest_target_dir.clone());

            // Always pass --features guest to enable the guest feature on the example package
            // (this is separate from the jolt-sdk features specified in the example's Cargo.toml)
            args.push("--features".to_string());
            args.push("guest".to_string());

            let (cmd_prog, cmd_prefix_args): (String, Vec<String>) = if let Some(path) = cargo_jolt_path {
                (path, vec![])
            } else {
                (
                    "cargo".to_string(),
                    vec![
                        "run".to_string(),
                        "-p".to_string(),
                        "cargo-jolt".to_string(),
                        "--release".to_string(),
                        "--".to_string(),
                    ],
                )
            };

            let mut full_args: Vec<String> = Vec::new();
            full_args.extend(cmd_prefix_args.clone());
            full_args.extend(args.clone());

            let cmd_line = compose_command_line(
                &cmd_prog,
                &[],
                &full_args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            );
            info!("\n{cmd_line}");

            let mut cmd = Command::new(&cmd_prog);
            if cmd_prog == "cargo" {
                let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .expect("jolt-core manifest dir should have a parent");
                cmd.current_dir(workspace_root);
            }
            cmd.args(&full_args);

            // Pass JOLT_FUNC_NAME if a specific function is set (for guest packages with multiple provable functions)
            if let Some(func) = &self.func {
                cmd.env("JOLT_FUNC_NAME", func);
            }

            let output = cmd.output().expect(
                "failed to run cargo-jolt (set CARGO_JOLT_PATH or ensure workspace builds cargo-jolt)",
            );

            if !output.status.success() {
                io::stderr().write_all(&output.stderr).unwrap();
                let output_msg = format!("::build command: \n{cmd_line}\n");
                io::stderr().write_all(output_msg.as_bytes()).unwrap();
                panic!("failed to compile guest with cargo-jolt");
            }

            // Determine the ELF path based on std mode
            let target_triple = if self.std {
                "riscv64imac-zero-linux-musl"
            } else {
                "riscv64imac-unknown-none-elf"
            };

            // ELF is built to guest_target_dir with standard cargo layout
            let elf_path = PathBuf::from(&guest_target_dir)
                .join(target_triple)
                .join("release")
                .join(&self.guest);

            // Verify the ELF exists
            if !elf_path.exists() {
                panic!("Built ELF not found at expected location: {}", elf_path.display());
            }

            // Store the main ELF path
            self.elf = Some(elf_path.clone());
            if let Some(contents) = self.get_elf_contents() {
                self.discover_memory_sizes(&contents);
            }

            info!("Built guest binary with cargo-jolt: {}", elf_path.display());
        }
    }

    fn cargo_jolt_supports_mode_flag(path: &str) -> Option<bool> {
        let output = Command::new(path)
            .args(["jolt", "build", "--help"])
            .output()
            .ok()?;

        // Some clap versions print help to stdout, others to stderr depending on exit status.
        let mut combined = String::new();
        combined.push_str(&String::from_utf8_lossy(&output.stdout));
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        Some(combined.contains("--mode"))
    }

    pub fn get_elf_contents(&self) -> Option<Vec<u8>> {
        if let Some(elf) = &self.elf {
            let mut elf_file =
                File::open(elf).unwrap_or_else(|_| panic!("could not open elf file: {elf:?}"));
            let mut elf_contents = Vec::new();
            elf_file.read_to_end(&mut elf_contents).unwrap();
            Some(elf_contents)
        } else {
            None
        }
    }

    pub fn decode(&mut self) -> (Vec<Instruction>, Vec<(u64, u8)>, u64) {
        self.build(DEFAULT_TARGET_DIR);
        let elf = self.elf.as_ref().unwrap();
        let mut elf_file =
            File::open(elf).unwrap_or_else(|_| panic!("could not open elf file: {elf:?}"));
        let mut elf_contents = Vec::new();
        elf_file.read_to_end(&mut elf_contents).unwrap();
        guest::program::decode(&elf_contents)
    }

    // TODO(moodlezoup): Make this generic over InstructionSet
    #[tracing::instrument(skip_all, name = "Program::trace")]
    pub fn trace(
        &mut self,
        inputs: &[u8],
        untrusted_advice: &[u8],
        trusted_advice: &[u8],
    ) -> (LazyTraceIterator, Vec<Cycle>, Memory, JoltDevice) {
        self.build(DEFAULT_TARGET_DIR);
        let elf = self.elf.as_ref().unwrap();
        let mut elf_file =
            File::open(elf).unwrap_or_else(|_| panic!("could not open elf file: {elf:?}"));
        let mut elf_contents = Vec::new();
        elf_file.read_to_end(&mut elf_contents).unwrap();
        let (_, _, program_end, _) = tracer::decode(&elf_contents);
        let program_size = program_end - RAM_START_ADDRESS;

        let memory_config = MemoryConfig {
            memory_size: self.memory_size,
            stack_size: self.stack_size,
            max_input_size: self.max_input_size,
            max_untrusted_advice_size: self.max_untrusted_advice_size,
            max_trusted_advice_size: self.max_trusted_advice_size,
            max_output_size: self.max_output_size,
            program_size: Some(program_size),
        };

        guest::program::trace(
            &elf_contents,
            self.elf.as_ref(),
            inputs,
            untrusted_advice,
            trusted_advice,
            &memory_config,
        )
    }

    #[tracing::instrument(skip_all, name = "Program::trace_to_file")]
    pub fn trace_to_file(
        &mut self,
        inputs: &[u8],
        untrusted_advice: &[u8],
        trusted_advice: &[u8],
        trace_file: &PathBuf,
    ) -> (Memory, JoltDevice) {
        self.build(DEFAULT_TARGET_DIR);
        let elf = self.elf.as_ref().unwrap();
        let mut elf_file =
            File::open(elf).unwrap_or_else(|_| panic!("could not open elf file: {elf:?}"));
        let mut elf_contents = Vec::new();
        elf_file.read_to_end(&mut elf_contents).unwrap();
        let (_, _, program_end, _) = tracer::decode(&elf_contents);
        let program_size = program_end - RAM_START_ADDRESS;
        let memory_config = MemoryConfig {
            memory_size: self.memory_size,
            stack_size: self.stack_size,
            max_input_size: self.max_input_size,
            max_untrusted_advice_size: self.max_untrusted_advice_size,
            max_trusted_advice_size: self.max_trusted_advice_size,
            max_output_size: self.max_output_size,
            program_size: Some(program_size),
        };

        tracer::trace_to_file(
            &elf_contents,
            self.elf.as_ref(),
            inputs,
            untrusted_advice,
            trusted_advice,
            &memory_config,
            trace_file,
        )
    }

    pub fn trace_analyze<F: JoltField>(
        mut self,
        inputs: &[u8],
        untrusted_advice: &[u8],
        trusted_advice: &[u8],
    ) -> ProgramSummary {
        let (bytecode, init_memory_state, _) = self.decode();
        let (_, trace, _, io_device) = self.trace(inputs, untrusted_advice, trusted_advice);

        ProgramSummary {
            trace,
            bytecode,
            memory_init: init_memory_state,
            io_device,
        }
    }

    // save_linker and linker_path are no longer needed when using cargo-jolt
    // cargo-jolt handles linker script generation
    // Keeping these methods for backward compatibility but they're unused



}

fn compose_command_line(program: &str, envs: &[(&str, String)], args: &[&str]) -> String {
    fn has_ctrl(s: &str) -> bool {
        s.chars()
            .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    }

    // ANSI-C ($'...') quoting for when control chars are present.
    fn quote_ansi_c(s: &str) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(s.len() + 3);
        out.push_str("$'");
        for c in s.chars() {
            match c {
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\\' => out.push_str("\\\\"),
                '\'' => out.push_str("\\'"),
                c if c.is_control() => {
                    let _ = write!(out, "\\x{:02x}", c as u32);
                }
                _ => out.push(c),
            }
        }
        out.push('\'');
        out
    }

    // Safe POSIX-style single-quote quoting (no expansions).
    fn sh_quote(s: &str) -> String {
        const SAFE: &str =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-";
        if !s.is_empty() && s.chars().all(|c| SAFE.contains(c)) {
            s.to_string()
        } else {
            let mut out = String::with_capacity(s.len() + 2);
            out.push('\'');
            for ch in s.chars() {
                if ch == '\'' {
                    out.push_str("'\\''");
                } else {
                    out.push(ch);
                }
            }
            out.push('\'');
            out
        }
    }

    let mut parts = Vec::new();

    if !envs.is_empty() {
        parts.push("env".to_string());
        for &(k, ref v) in envs {
            let v = v.as_str();
            let q = if has_ctrl(v) {
                quote_ansi_c(v)
            } else {
                sh_quote(v)
            };
            parts.push(format!("{k}={q}"));
        }
    }

    parts.push(sh_quote(program));
    parts.extend(args.iter().map(|&a| {
        if has_ctrl(a) {
            quote_ansi_c(a)
        } else {
            sh_quote(a)
        }
    }));

    parts.join(" ")
}
