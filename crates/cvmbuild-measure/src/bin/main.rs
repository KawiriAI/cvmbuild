//! cvmbuild-measure — standalone CLI for SNP/TDX measurement computation.
//!
//! Wraps the same measurement code that `cvmbuild build`/`cvmbuild measure`
//! uses, but takes raw paths and parameters instead of reading cvm.toml.
//! Useful for ops/audit pipelines that want to re-derive measurements from
//! known-good kernel + initrd + OVMF + cmdline inputs without pulling in
//! the full cvmbuild config schema.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use cvmbuild_measure::snp::guest::{calc_launch_digest, LaunchDigestOptions};
use cvmbuild_measure::snp::types::{SevMode, VmmType};
use cvmbuild_measure::tdx::{
    rtmr::{calc_rtmr0, calc_rtmr1, calc_rtmr2, calc_rtmr3},
    tdvf::calculate_mrtd,
    types::GpuModel,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "cvmbuild-measure",
    about = "Compute SNP launch digests / TDX MRTD+RTMRs from raw inputs",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbose logging.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute the AMD SEV-SNP LAUNCH_DIGEST for one or more vCPU signatures.
    /// Output is a JSON object keyed by signature name.
    Snp {
        /// OVMF firmware blob.
        #[arg(long)]
        ovmf: PathBuf,
        /// Linux kernel (vmlinuz).
        #[arg(long)]
        kernel: PathBuf,
        /// Initial ramdisk.
        #[arg(long)]
        initrd: PathBuf,
        /// Kernel command line (the full final cmdline including verity bits).
        #[arg(long)]
        cmdline: String,
        /// Number of vCPUs.
        #[arg(long, default_value = "1")]
        vcpus: u32,
        /// SEV_FEATURES value baked into VMSA (0x1 = SnpActive, 0x21 adds RestrictedInjection).
        #[arg(long, default_value = "1")]
        guest_features: u64,
        /// Comma-separated list of NAME=HEXSIG pairs. Defaults to the four
        /// EPYC generations cvmbuild ships by default.
        #[arg(
            long,
            default_value = "EPYC-v4=0x800F12,EPYC-Rome=0x830F10,EPYC-Milan=0xA00F11,EPYC-Genoa=0xA10F11"
        )]
        cpu_sigs: String,
    },
    /// Compute Intel TDX MRTD + RTMR0..3.
    Tdx {
        /// OVMF/TDVF firmware blob.
        #[arg(long)]
        ovmf: PathBuf,
        /// Linux kernel (vmlinuz).
        #[arg(long)]
        kernel: PathBuf,
        /// Initial ramdisk.
        #[arg(long)]
        initrd: PathBuf,
        /// Kernel command line.
        #[arg(long)]
        cmdline: String,
        /// Path to the CvmDsdt.aml that the patched OVMF installs.
        #[arg(long)]
        dsdt: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Snp {
            ovmf,
            kernel,
            initrd,
            cmdline,
            vcpus,
            guest_features,
            cpu_sigs,
        } => {
            let kernel_data =
                std::fs::read(&kernel).with_context(|| format!("reading {}", kernel.display()))?;
            let initrd_data =
                std::fs::read(&initrd).with_context(|| format!("reading {}", initrd.display()))?;

            let mut out = serde_json::Map::new();
            for entry in cpu_sigs.split(',').filter(|s| !s.is_empty()) {
                let (name, sig_str) = entry
                    .split_once('=')
                    .with_context(|| format!("--cpu-sigs entry '{entry}' must be NAME=0xHEX"))?;
                let sig_str = sig_str.trim_start_matches("0x");
                let vcpu_sig = u32::from_str_radix(sig_str, 16)
                    .with_context(|| format!("parsing vcpu_sig hex from '{entry}'"))?;

                let ld = calc_launch_digest(&LaunchDigestOptions {
                    mode: SevMode::SevSnp,
                    vcpus,
                    vcpu_sig,
                    ovmf_file: &ovmf,
                    kernel: Some(&kernel_data),
                    initrd: Some(&initrd_data),
                    append: Some(&cmdline),
                    guest_features,
                    vmm_type: VmmType::Qemu,
                    ..Default::default()
                })?;
                out.insert(
                    format!("SNP_{name}"),
                    serde_json::Value::String(hex::encode(&ld)),
                );
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(out))?
            );
        }
        Commands::Tdx {
            ovmf,
            kernel,
            initrd,
            cmdline,
            dsdt,
        } => {
            let firmware =
                std::fs::read(&ovmf).with_context(|| format!("reading {}", ovmf.display()))?;
            let kernel_data =
                std::fs::read(&kernel).with_context(|| format!("reading {}", kernel.display()))?;
            let initrd_data =
                std::fs::read(&initrd).with_context(|| format!("reading {}", initrd.display()))?;
            let dsdt_data =
                std::fs::read(&dsdt).with_context(|| format!("reading {}", dsdt.display()))?;

            let mrtd = calculate_mrtd(&firmware)?;
            let rtmr0 = calc_rtmr0(&firmware, &dsdt_data, GpuModel::None)?;
            let rtmr1 = calc_rtmr1(&kernel_data)?;
            let rtmr2 = calc_rtmr2(&cmdline, &initrd_data)?;
            let rtmr3 = calc_rtmr3();

            let out = serde_json::json!({
                "MRTD": hex::encode(&mrtd),
                "RTMR0": hex::encode(&rtmr0),
                "RTMR1": hex::encode(&rtmr1),
                "RTMR2": hex::encode(&rtmr2),
                "RTMR3": hex::encode(&rtmr3),
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}
