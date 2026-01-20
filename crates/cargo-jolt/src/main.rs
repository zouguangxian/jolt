use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, info};
use std::fs;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{exit, Command};

use build::cmds::{BuildArgs, StdMode};

/// Linker script template embedded at compile time.
/// This avoids the need to discover it via cargo metadata, which can find the wrong
/// jolt-platform package when running in a different workspace (e.g., the jolt repo).
static LINKER_TEMPLATE: &str = include_str!("../../../common/linker.ld.template");

#[derive(serde::Deserialize, Debug, Default)]
struct JoltMetadata {
    #[serde(rename = "heap_size")]
    heap_size: Option<String>,
    #[serde(rename = "stack_size")]
    stack_size: Option<String>,
    #[serde(rename = "isa")]
    isa: Option<String>,
    #[serde(rename = "io")]
    io: Option<JoltIoMetadata>,
}

#[derive(serde::Deserialize, Debug, Default, Clone)]
struct JoltIoMetadata {
    #[serde(rename = "max_input_size")]
    max_input_size: Option<u64>,
    #[serde(rename = "max_output_size")]
    max_output_size: Option<u64>,
    #[serde(rename = "max_trusted_advice_size")]
    max_trusted_advice_size: Option<u64>,
    #[serde(rename = "max_untrusted_advice_size")]
    max_untrusted_advice_size: Option<u64>,
}

#[derive(Parser)]
#[command(name = "cargo-jolt")]
#[command(bin_name = "cargo")]
#[command(about = "Build for Jolt zkVM", version, long_about = None)]



enum Cli {
    #[command(name = "jolt", subcommand)]
    Jolt(JoltCmd),
}

#[derive(clap::Subcommand, Debug)]
enum JoltCmd {
    Build(JoltBuildArgs),

    Run(RunArgs),

    #[command(subcommand)]
    Generate(GenerateCmd),
}

#[derive(clap::Subcommand, Debug)]
enum GenerateCmd {
    Target(JoltGenerateTargetArgs),

    Linker(JoltGenerateLinkerArgs),
}

#[derive(clap::Args, Debug)]
struct JoltBuildArgs {
    #[command(flatten)]
    base: BuildArgs,

    /// Override max input size (bytes or with suffixes like 4Ki/64Mi).
    ///
    /// If provided, this overrides `[package.metadata.jolt.io.max_input_size]`.
    #[arg(long)]
    max_input_size: Option<String>,

    /// Override max output size (bytes or with suffixes like 4Ki/64Mi).
    ///
    /// If provided, this overrides `[package.metadata.jolt.io.max_output_size]`.
    #[arg(long)]
    max_output_size: Option<String>,

    /// Override max trusted advice size (bytes or with suffixes like 4Ki/64Mi).
    ///
    /// If provided, this overrides `[package.metadata.jolt.io.max_trusted_advice_size]`.
    #[arg(long)]
    max_trusted_advice_size: Option<String>,

    /// Override max untrusted advice size (bytes or with suffixes like 4Ki/64Mi).
    ///
    /// If provided, this overrides `[package.metadata.jolt.io.max_untrusted_advice_size]`.
    #[arg(long)]
    max_untrusted_advice_size: Option<String>,
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// Path to the ELF binary to run
    #[arg(value_name = "BINARY")]
    binary: PathBuf,

    /// Path to jolt-emu binary (defaults to searching PATH, then common locations)
    #[arg(long, env = "JOLT_EMU_PATH")]
    jolt_emu: Option<PathBuf>,

    /// Additional arguments to pass to jolt-emu
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub emu_args: Vec<String>,
}

#[derive(clap::Args, Debug)]
struct JoltGenerateTargetArgs {
    #[command(flatten)]
    base: build::cmds::GenerateTargetArgs,

    #[arg(long, short = 'o')]
    output: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct JoltGenerateLinkerArgs {
    #[command(flatten)]
    base: build::cmds::GenerateLinkerArgs,

    #[arg(long, short = 'o', default_value = "linker.ld")]
    output: PathBuf,
}

fn main() {
    env_logger::Builder::from_default_env()
        .format_timestamp(None)
        .format_module_path(false)
        .init();

    debug!("cargo-jolt starting");

    if let Err(e) = run() {
        eprintln!("Error: {:#}", e);
        exit(1);
    }
}

fn run() -> Result<()> {
    let Cli::Jolt(cmd) = Cli::parse();

    match cmd {
        JoltCmd::Build(args) => build_command(args),
        JoltCmd::Run(args) => run_command(args),
        JoltCmd::Generate(gen_cmd) => match gen_cmd {
            GenerateCmd::Target(args) => generate_target_command(args),
            GenerateCmd::Linker(args) => generate_linker_command(args),
        },
    }
}

// Use ZeroOS's std guest target by default (this is the same target spike uses).
// zeroos-build knows how to provision the target spec/toolchain for this triple.
const TARGET_JOLT_STD: &str = "riscv64imac-zero-linux-musl";

/// Jolt-specific rustflags for zkVM environment
const JOLT_RUSTFLAGS: &[&str] = &[
    // lower-atomic: Jolt prover doesn't support LR/SC atomic instructions
    "-Cpasses=lower-atomic",
    // panic=abort: Required for zkVM
    "-Cpanic=abort",
    // Optimize for size (helps with register allocation for inline asm)
    "-Copt-level=z",
    // Use jolt-platform's custom getrandom implementation
    "--cfg=getrandom_backend=\"custom\"",
];

// Defaults used when the target package omits `[package.metadata.jolt.io]`.
// These should match `common::constants::{DEFAULT_MAX_*}` in the Jolt workspace.
const DEFAULT_MAX_INPUT_SIZE: usize = 4096;
const DEFAULT_MAX_OUTPUT_SIZE: usize = 4096;
const DEFAULT_MAX_TRUSTED_ADVICE_SIZE: usize = 4096;
const DEFAULT_MAX_UNTRUSTED_ADVICE_SIZE: usize = 4096;

fn arg_present(flag: &str) -> bool {
    // Support both `--flag value` and `--flag=value`.
    std::env::args().any(|a| a == flag || a.starts_with(&format!("{flag}=")))
}

fn build_command(args: JoltBuildArgs) -> Result<()> {
    let mut args = args;
    debug!("build_command: {:?}", args);

    // This tool is intended to be the *supported* way to build the Jolt std guest target.
    // We don't try to make `cargo build --target riscv64imac-jolt-linux-musl` work without
    // configuration; instead, `cargo jolt build` owns the necessary env/rustflags setup.
    if args.base.target.is_none() && args.base.mode == StdMode::Std {
        args.base.target = Some(TARGET_JOLT_STD.to_string());
    }

    let workspace_root = build::cmds::find_workspace_root()?;
    debug!("workspace_root: {}", workspace_root.display());

    let metadata =
        parse_jolt_metadata(&workspace_root, &args.base.package, args.base.mode).unwrap_or_default();
    // CLI should override metadata. Since `BuildArgs` carries defaults, detect whether the user
    // explicitly set these flags.
    if !arg_present("--heap-size") {
        if let Some(heap) = metadata.heap_size {
            args.base.heap_size = heap;
        }
    }
    if !arg_present("--stack-size") {
        if let Some(stack) = metadata.stack_size {
            args.base.stack_size = stack;
        }
    }

    // Always provide I/O sizing symbols in the linker script so the ELF is self-describing.
    let mut max_input = DEFAULT_MAX_INPUT_SIZE;
    let mut max_output = DEFAULT_MAX_OUTPUT_SIZE;
    let mut max_trusted = DEFAULT_MAX_TRUSTED_ADVICE_SIZE;
    let mut max_untrusted = DEFAULT_MAX_UNTRUSTED_ADVICE_SIZE;

    if let Some(io) = metadata.io {
        max_input = io
            .max_input_size
            .unwrap_or(DEFAULT_MAX_INPUT_SIZE as u64) as usize;
        max_output = io
            .max_output_size
            .unwrap_or(DEFAULT_MAX_OUTPUT_SIZE as u64) as usize;
        max_trusted = io
            .max_trusted_advice_size
            .unwrap_or(DEFAULT_MAX_TRUSTED_ADVICE_SIZE as u64) as usize;
        max_untrusted = io
            .max_untrusted_advice_size
            .unwrap_or(DEFAULT_MAX_UNTRUSTED_ADVICE_SIZE as u64) as usize;
    }

    if let Some(s) = &args.max_input_size {
        max_input = parse_size::parse_size(s)? as usize;
    }
    if let Some(s) = &args.max_output_size {
        max_output = parse_size::parse_size(s)? as usize;
    }
    if let Some(s) = &args.max_trusted_advice_size {
        max_trusted = parse_size::parse_size(s)? as usize;
    }
    if let Some(s) = &args.max_untrusted_advice_size {
        max_untrusted = parse_size::parse_size(s)? as usize;
    }

    let mut linker_defines = BTreeMap::new();
    linker_defines.insert("JOLT_MAX_INPUT_SIZE".to_string(), format!("{:#x}", max_input));
    linker_defines.insert("JOLT_MAX_OUTPUT_SIZE".to_string(), format!("{:#x}", max_output));
    linker_defines.insert(
        "JOLT_MAX_TRUSTED_ADVICE_SIZE".to_string(),
        format!("{:#x}", max_trusted),
    );
    linker_defines.insert(
        "JOLT_MAX_UNTRUSTED_ADVICE_SIZE".to_string(),
        format!("{:#x}", max_untrusted),
    );
    // ABI version for host-side compatibility checks.
    linker_defines.insert("JOLT_ABI_VERSION".to_string(), "1".to_string());

    // Export effective sizing parameters for proc-macros (e.g., `#[jolt::provable]`) so codegen
    // matches the linker script and ELF symbols, even when CLI overrides are used.
    // Use bytes to keep parsing trivial.
    let heap_bytes = parse_size::parse_size(&args.base.heap_size)? as u64;
    let stack_bytes = parse_size::parse_size(&args.base.stack_size)? as u64;
    std::env::set_var("JOLT_MEMORY_SIZE", heap_bytes.to_string());
    std::env::set_var("JOLT_STACK_SIZE", stack_bytes.to_string());
    std::env::set_var("JOLT_MAX_INPUT_SIZE", max_input.to_string());
    std::env::set_var("JOLT_MAX_OUTPUT_SIZE", max_output.to_string());
    std::env::set_var("JOLT_MAX_TRUSTED_ADVICE_SIZE", max_trusted.to_string());
    std::env::set_var("JOLT_MAX_UNTRUSTED_ADVICE_SIZE", max_untrusted.to_string());

    // TODO: ISA metadata could map to a target triple / linker config.

    // Use the embedded linker template (compiled into the binary)
    let linker_tpl = LINKER_TEMPLATE.to_string();

    let fully = args.base.mode == StdMode::Std || args.base.fully;

    let toolchain_paths = if args.base.mode == StdMode::Std || fully {
        Some(build::cmds::get_or_build_toolchain(
            args.base.musl_lib_path.clone(),
            args.base.gcc_lib_path.clone(),
            fully,
        )?)
    } else {
        None
    };

    // Add Jolt-specific rustflags
    let mut rustflags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    for flag in JOLT_RUSTFLAGS {
        if !rustflags.is_empty() {
            rustflags.push('');
        }
        rustflags.push_str(flag);
    }
    std::env::set_var("CARGO_ENCODED_RUSTFLAGS", rustflags);

    build::cmds::build_binary(
        &workspace_root,
        &args.base,
        toolchain_paths,
        Some(linker_tpl),
        Some(linker_defines),
    )?;

    Ok(())
}

fn find_jolt_emu() -> Option<PathBuf> {
    // First check if jolt-emu is in PATH
    if let Ok(output) = Command::new("which").arg("jolt-emu").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }

    // Check common locations relative to the jolt repository
    let common_paths = [
        // Relative to current working directory (if in jolt repo)
        "target/release/jolt-emu",
        "target/debug/jolt-emu",
        // Common sibling directory layout
        "../jolt/target/release/jolt-emu",
        "../jolt/target/debug/jolt-emu",
    ];

    for path in &common_paths {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p.canonicalize().unwrap_or(p));
        }
    }

    None
}

fn run_command(args: RunArgs) -> Result<()> {
    if !args.binary.exists() {
        anyhow::bail!("Binary not found: {}", args.binary.display());
    }

    let jolt_emu = args.jolt_emu.or_else(find_jolt_emu).ok_or_else(|| {
        anyhow::anyhow!(
            "jolt-emu not found. Please specify --jolt-emu or set JOLT_EMU_PATH environment variable"
        )
    })?;

    debug!("Running binary: {}", args.binary.display());
    debug!("Using jolt-emu: {}", jolt_emu.display());

    println!("Running on Jolt emulator...\n");

    let mut cmd = Command::new(&jolt_emu);
    cmd.arg(&args.binary);
    cmd.args(&args.emu_args);

    let args_vec: Vec<String> = cmd
        .get_args()
        .map(|s| s.to_string_lossy().to_string())
        .collect();
    let cmd_str = format!("{} {}", jolt_emu.display(), args_vec.join(" "));
    debug!("Command: {}", cmd_str);

    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute jolt-emu at {}", jolt_emu.display()))?;

    if !status.success() {
        exit(status.code().unwrap_or(1));
    }

    Ok(())
}

fn generate_target_command(cli_args: JoltGenerateTargetArgs) -> Result<()> {
    use build::cmds::generate_target_spec;
    use build::spec::{load_target_profile, parse_target_triple};

    let target_triple = if let Some(profile_name) = &cli_args.base.profile {
        load_target_profile(profile_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown profile: {}", profile_name))?
            .config
            .target_triple()
    } else if let Some(target) = &cli_args.base.target {
        parse_target_triple(target)
            .ok_or_else(|| anyhow::anyhow!("Cannot parse target triple: {}", target))?
            .target_triple()
    } else {
        return Err(anyhow::anyhow!("Either --profile or --target is required"));
    };

    let json_content =
        generate_target_spec(&cli_args.base, build::spec::TargetRenderOptions::default()).map_err(|e| anyhow::anyhow!("{}", e))?;

    let output_path = cli_args
        .output
        .unwrap_or_else(|| PathBuf::from(format!("{}.json", target_triple)));

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create output directory: {}", parent.display()))?;
    }

    fs::write(&output_path, &json_content)
        .with_context(|| format!("Failed to write target spec to {}", output_path.display()))?;

    info!("Generated target spec: {}", output_path.display());
    info!("Target triple: {}", target_triple);

    Ok(())
}

fn generate_linker_command(cli_args: JoltGenerateLinkerArgs) -> Result<()> {
    use build::cmds::generate_linker_script;

    let result = generate_linker_script(&cli_args.base)?;

    if let Some(parent) = cli_args.output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create output directory: {}", parent.display()))?;
    }

    fs::write(&cli_args.output, &result.script_content).with_context(|| {
        format!(
            "Failed to write linker script to {}",
            cli_args.output.display()
        )
    })?;

    info!("Generated linker script: {}", cli_args.output.display());

    Ok(())
}


fn parse_jolt_metadata(workspace_root: &PathBuf, package: &str, mode: StdMode) -> Result<JoltMetadata> {
    #[derive(serde::Deserialize)]
    struct CargoMetadata {
        packages: Vec<CargoPackage>,
    }
    #[derive(serde::Deserialize)]
    struct CargoPackage {
        name: String,
        manifest_path: String,
    }

    // Discover the package's Cargo.toml via `cargo metadata` so this works no matter where
    // `cargo-jolt` is invoked from (host example, workspace root, etc).
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--no-deps")
        .arg("--format-version=1")
        .current_dir(workspace_root)
        .output()
        .with_context(|| "failed to run `cargo metadata`")?;
    if !output.status.success() {
        return Ok(JoltMetadata::default());
    }
    let meta: CargoMetadata = serde_json::from_slice(&output.stdout)?;
    let manifest_path = meta
        .packages
        .into_iter()
        .find(|p| p.name == package)
        .map(|p| PathBuf::from(p.manifest_path))
        .unwrap_or_else(|| workspace_root.join("Cargo.toml"));

    if !manifest_path.exists() {
        return Ok(JoltMetadata::default());
    }

    let content = fs::read_to_string(&manifest_path)?;
    let toml_value: toml::Value = toml::from_str(&content)?;

    let jolt_val = toml_value
        .get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("jolt"));

    let mut metadata: JoltMetadata = if let Some(v) = jolt_val {
        v.clone().try_into().unwrap_or_default()
    } else {
        JoltMetadata::default()
    };

    let mode_key = match mode {
        StdMode::Std => "std",
        StdMode::NoStd => "no-std",
    };

    if let Some(mode_val) = jolt_val.and_then(|j| j.get(mode_key)) {
        let mode_metadata: JoltMetadata = mode_val.clone().try_into().unwrap_or_default();
        if mode_metadata.heap_size.is_some() {
            metadata.heap_size = mode_metadata.heap_size;
        }
        if mode_metadata.stack_size.is_some() {
            metadata.stack_size = mode_metadata.stack_size;
        }
        if mode_metadata.isa.is_some() {
            metadata.isa = mode_metadata.isa;
        }
        if mode_metadata.io.is_some() {
            metadata.io = mode_metadata.io;
        }
    }

    Ok(metadata)
}
