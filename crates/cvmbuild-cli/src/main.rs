mod cache;
mod kawiri_cache;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "cvmbuild",
    about = "Fast, declarative CVM image builder",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Image definition directory (must contain cvm.toml), or path to a .toml file
    #[arg(default_value = ".")]
    image_dir: PathBuf,

    /// OVMF firmware directory (resolves ovmf_file in cvm.toml)
    #[arg(long, env = "OVMF_DIR")]
    ovmf_dir: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Download models specified in [[models]] from HuggingFace
    DownloadModels,

    /// Validate the config against security assertions
    Validate,

    /// List all available assertion checks
    Checks,

    /// Build the CVM image (docker buildx + seal)
    Build {
        /// Skip the container build, use existing image
        #[arg(long)]
        skip_container: bool,

        /// Output directory for artifacts
        #[arg(short, long, default_value = "build")]
        output: PathBuf,

        /// Dry run — show what would be built without building
        #[arg(long)]
        dry_run: bool,

        /// Skip downloading models (fail if missing)
        #[arg(long)]
        no_download: bool,
    },

    /// Extract rootfs from an OCI container image
    Extract {
        /// Container image reference (e.g., localhost/my-cvm:latest)
        #[arg(long)]
        base: String,

        /// Output directory for rootfs
        #[arg(short, long, default_value = "work")]
        output: PathBuf,
    },

    /// Seal a rootfs into a CVM disk image (squashfs → verity → GPT + kernel + initrd)
    Seal {
        /// Path to extracted rootfs
        #[arg(long)]
        rootfs: PathBuf,

        /// Output directory for image artifacts
        #[arg(short, long, default_value = "output")]
        output: PathBuf,
    },

    /// Create an ext4+verity disk image from a directory
    VerityDisk {
        /// Source directory to include in the disk
        #[arg(long)]
        source: PathBuf,

        /// Output image path
        #[arg(short, long)]
        output: PathBuf,

        /// Disk label
        #[arg(long, default_value = "data")]
        label: String,

        /// Filesystem UUID (for reproducibility)
        #[arg(long, default_value = "cb9faa28-968e-4601-a47e-f1dc67ebaddc")]
        uuid: String,
    },

    /// Compute TEE measurements from built artifacts
    Measure {
        /// Build output directory
        #[arg(short, long, default_value = "build")]
        output: PathBuf,
    },

    /// Print QEMU boot command from built artifacts
    BootCmd {
        /// Build output directory
        #[arg(short, long, default_value = "build")]
        output: PathBuf,

        /// TEE mode: snp, tdx, or none (default: none)
        #[arg(long, default_value = "none")]
        tee: String,

        /// Path to QEMU binary
        #[arg(long, default_value = "qemu-system-x86_64")]
        qemu: String,

        /// Path to OVMF firmware (required for --tee snp/tdx)
        #[arg(long)]
        ovmf: Option<PathBuf>,

        /// Memory size
        #[arg(long, default_value = "16G")]
        mem: String,

        /// Number of vCPUs
        #[arg(long, default_value = "4")]
        smp: String,

        /// Host port for forwarding to guest 8443
        #[arg(long, default_value = "18443")]
        port: String,

        /// Use absolute paths in the generated command
        #[arg(long)]
        absolute: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize tracing
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

/// Resolve the image directory and config file path.
///
/// - If `image_dir` is a directory → look for `cvm.toml` inside it
/// - If `image_dir` is a `.toml` file → use it directly (backward compat)
fn resolve_config(image_dir: &std::path::Path) -> Result<(PathBuf, PathBuf)> {
    if image_dir.is_file() && image_dir.extension().is_some_and(|e| e == "toml") {
        let dir = image_dir
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        Ok((dir, image_dir.to_path_buf()))
    } else if image_dir.is_dir() {
        let config_path = image_dir.join("cvm.toml");
        if !config_path.exists() {
            anyhow::bail!(
                "no cvm.toml found in {} — create one or point at a .toml file",
                image_dir.display()
            );
        }
        Ok((image_dir.to_path_buf(), config_path))
    } else {
        anyhow::bail!("{} is not a directory or .toml file", image_dir.display());
    }
}

fn run(cli: Cli) -> Result<()> {
    let (image_dir, config_path) = resolve_config(&cli.image_dir)?;
    let mut config = cvmbuild_config::Config::load(&config_path).context("loading config")?;

    // Resolve OVMF filenames against:
    //   1. --ovmf-dir / OVMF_DIR (explicit operator override)
    //   2. cached cvm.toml [image].ovmf_version pin (downloads release if missing)
    //   3. config file directory (backwards compat)
    if let Some(ref ovmf_dir) = cli.ovmf_dir {
        config.resolve_ovmf(ovmf_dir);
    } else if let Some(version) = config.image.ovmf_version.clone() {
        let dir = kawiri_cache::ensure_ovmf(&version)
            .with_context(|| format!("resolving pinned ovmf v{version} from cache"))?;
        tracing::info!("Using cached ovmf v{version} at {}", dir.display());
        config.resolve_ovmf(&dir);
    } else {
        let base = config_path.parent().unwrap_or(std::path::Path::new("."));
        config.resolve_ovmf(base);
    }

    match cli.command {
        Commands::DownloadModels => {
            download_models(&config, &image_dir, false)?;
            if config.models.is_empty() {
                println!("No [[models]] entries in cvm.toml");
            } else {
                println!("All models downloaded.");
            }
            Ok(())
        }
        Commands::Validate => cmd_validate(&config),
        Commands::Checks => cmd_checks(&config),
        Commands::Build {
            skip_container,
            output,
            dry_run,
            no_download,
        } => cmd_build(
            &config,
            &image_dir,
            skip_container,
            &output,
            dry_run,
            no_download,
        ),
        Commands::Extract { base, output } => cmd_extract(&config, &base, &output),
        Commands::Seal { rootfs, output } => cmd_seal(&config, &rootfs, &output),
        Commands::VerityDisk {
            source,
            output,
            label,
            uuid,
        } => cmd_verity_disk(&source, &output, &label, &uuid),
        Commands::Measure { output } => cmd_measure(&config, &output),
        Commands::BootCmd {
            output,
            tee,
            qemu,
            ovmf,
            mem,
            smp,
            port,
            absolute,
        } => cmd_boot_cmd(&BootCmdOpts {
            config: &config,
            output: &output,
            tee: &tee,
            qemu_bin: &qemu,
            ovmf: ovmf.as_deref(),
            mem: &mem,
            smp: &smp,
            port: &port,
            absolute,
        }),
    }
}

fn cmd_validate(config: &cvmbuild_config::Config) -> Result<()> {
    use cvmbuild_config::assert::Severity;

    let results = config.validate_full();

    let errors: Vec<_> = results
        .iter()
        .filter(|r| r.severity == Severity::Error)
        .collect();
    let warnings: Vec<_> = results
        .iter()
        .filter(|r| r.severity == Severity::Warning)
        .collect();

    let structural = cvmbuild_config::assert::structural_count();
    let catalog = cvmbuild_config::assert::catalog_count(config);
    let total = structural + catalog;

    for w in &warnings {
        println!("  WARN  [{}] {}", w.check_name, w.message);
    }

    if errors.is_empty() {
        println!(
            "All {} checks passed ({} structural + {} catalog).",
            total, structural, catalog,
        );
        return Ok(());
    }

    println!("Validation failed — {} error(s):\n", errors.len());
    for e in &errors {
        println!("  FAIL  [{}] {}", e.check_name, e.message);
    }
    std::process::exit(1);
}

fn cmd_checks(config: &cvmbuild_config::Config) -> Result<()> {
    use cvmbuild_config::assert::{catalog, resolve_checks};

    let active = resolve_checks(&config.assert).unwrap_or_default();
    let active_set: std::collections::HashSet<&str> = active.into_iter().collect();

    println!("Structural (always-on):");
    for check in catalog::STRUCTURAL_CHECKS {
        println!("  [on]    {:40} — {}", check.name, check.description);
    }

    // Group catalog checks by category
    let mut current_category = None;
    for check in catalog::CATALOG_CHECKS {
        if current_category != Some(check.category) {
            current_category = Some(check.category);
            println!("\n{}:", check.category.label());
        }
        let status = if active_set.contains(check.name) {
            "on"
        } else {
            "skip"
        };
        println!(
            "  [{:4}]  {:40} — {}",
            status, check.name, check.description
        );
    }

    let profile = config.assert.profile.as_deref().unwrap_or("production");
    println!(
        "\nProfile: {} ({} structural + {} catalog = {} total)",
        profile,
        catalog::STRUCTURAL_CHECKS.len(),
        active_set.len(),
        catalog::STRUCTURAL_CHECKS.len() + active_set.len(),
    );

    Ok(())
}

/// Stage the pinned kawa release binary next to the base-image Dockerfile so
/// `COPY kawa /usr/local/bin/kawa` picks up the exact released bytes.
///
/// The cache (under /var/lib/kawiri/kawa/<version>/) holds the canonical copy;
/// we copy from there into the build context. We always overwrite to avoid a
/// stale binary from a previous build sneaking into a new measurement.
fn stage_kawa(
    config: &cvmbuild_config::Config,
    image_dir: &std::path::Path,
    version: &str,
) -> Result<()> {
    let dockerfile_rel = config
        .image
        .base_image_dockerfile
        .as_deref()
        .context("kawa_version is set but base_image_dockerfile is not — cvmbuild needs to know where to stage the kawa binary")?;

    let build_context = if let Some(ref ctx) = config.image.context {
        let p = std::path::Path::new(ctx);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            image_dir.join(ctx)
        }
    } else {
        image_dir.to_path_buf()
    };
    let dockerfile_path = build_context.join(dockerfile_rel);
    let staging_dir = dockerfile_path
        .parent()
        .context("base_image_dockerfile has no parent directory")?;
    let target = staging_dir.join("kawa");

    let cached = kawiri_cache::ensure_kawa(version)?;
    std::fs::copy(&cached, &target)
        .with_context(|| format!("staging kawa binary at {}", target.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
    tracing::info!(
        "Staged kawa v{version} → {} (from {})",
        target.display(),
        cached.display()
    );
    Ok(())
}

/// Check that docker is available.
fn check_docker() -> Result<()> {
    let ok = std::process::Command::new("docker")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    if !ok {
        anyhow::bail!("docker not found — install it: apt install docker.io docker-buildx");
    }
    Ok(())
}

/// Download models specified in [[models]] from HuggingFace.
/// Models are downloaded into `<image_dir>/disks/models/<repo_name>/`.
/// Skips repos that already exist locally.
fn download_models(
    config: &cvmbuild_config::Config,
    image_dir: &std::path::Path,
    no_download: bool,
) -> Result<()> {
    if config.models.is_empty() {
        return Ok(());
    }

    let models_dir = image_dir.join("disks/models");

    // If models_dir is a dangling symlink (e.g. shared model dir not yet populated),
    // remove it so create_dir_all can create a real directory
    if models_dir.symlink_metadata().is_ok() && !models_dir.exists() {
        std::fs::remove_file(&models_dir)?;
    }

    for model in &config.models {
        let repo_name = model.repo.split('/').next_back().unwrap_or(&model.repo);
        let dest = models_dir.join(repo_name);

        if dest.is_dir() {
            // Check for real files (not broken symlinks) — HF cache leaves dangling symlinks
            let has_real_files = std::fs::read_dir(&dest)?
                .filter_map(|e| e.ok())
                .any(|e| e.path().metadata().is_ok());
            if has_real_files {
                tracing::info!(
                    "Model '{}' already exists at {}",
                    model.repo,
                    dest.display()
                );
                continue;
            }
            // Clean up broken symlinks before re-downloading
            for e in std::fs::read_dir(&dest)?.flatten() {
                if e.path().symlink_metadata().is_ok() && e.path().metadata().is_err() {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }

        if no_download {
            anyhow::bail!(
                "model '{}' not found at {} — run without --no-download to fetch it",
                model.repo,
                dest.display()
            );
        }

        tracing::info!("Downloading model '{}' → {}", model.repo, dest.display());
        std::fs::create_dir_all(&dest)?;

        let api = hf_hub::api::sync::ApiBuilder::new()
            .with_progress(true)
            .build()
            .context("failed to create HuggingFace API client")?;

        let repo = api.model(model.repo.clone());
        let repo_info = repo.info().with_context(|| {
            format!(
                "failed to fetch repo info for '{}' — check the repo name and your network",
                model.repo
            )
        })?;

        for sibling in &repo_info.siblings {
            let filename = &sibling.rfilename;

            // Apply include filters if specified
            if !model.include.is_empty() {
                let matched = model
                    .include
                    .iter()
                    .any(|pattern| glob_match(pattern, filename));
                if !matched {
                    tracing::debug!("Skipping {} (not in include patterns)", filename);
                    continue;
                }
            }

            tracing::info!("  Fetching {}", filename);
            let cached_path = repo.get(filename).with_context(|| {
                format!("failed to download '{}' from '{}'", filename, model.repo)
            })?;

            // Copy from HF cache to our models dir
            let target = dest.join(filename);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Remove any existing broken symlink at target (HF cache remnants)
            if target.symlink_metadata().is_ok() {
                if target.metadata().is_err() {
                    std::fs::remove_file(&target)?;
                } else {
                    continue; // real file already exists
                }
            }

            // Resolve symlinks — HF cache returns symlinks to blob store,
            // and hard_link() on Linux preserves symlinks instead of following them
            let real_path = cached_path
                .canonicalize()
                .with_context(|| format!("resolving HF cache path {}", cached_path.display()))?;

            // Use hard link if possible (same filesystem), fall back to copy
            if std::fs::hard_link(&real_path, &target).is_err() {
                std::fs::copy(&real_path, &target).with_context(|| {
                    format!("copying {} → {}", real_path.display(), target.display())
                })?;
            }
        }

        tracing::info!("Model '{}' downloaded to {}", model.repo, dest.display());
    }

    Ok(())
}

/// Simple glob matching supporting * and ? wildcards.
fn glob_match(pattern: &str, text: &str) -> bool {
    let mut p = pattern.chars().peekable();
    let mut t = text.chars().peekable();

    fn match_inner(
        p: &mut std::iter::Peekable<std::str::Chars<'_>>,
        t: &mut std::iter::Peekable<std::str::Chars<'_>>,
    ) -> bool {
        loop {
            match (p.peek(), t.peek()) {
                (None, None) => return true,
                (None, Some(_)) => return false,
                (Some('*'), _) => {
                    p.next();
                    // Try matching * against 0..n chars
                    let mut t_clone = t.clone();
                    loop {
                        let mut p_clone = p.clone();
                        let mut tc = t_clone.clone();
                        if match_inner(&mut p_clone, &mut tc) {
                            return true;
                        }
                        if t_clone.next().is_none() {
                            return false;
                        }
                    }
                }
                (Some('?'), Some(_)) => {
                    p.next();
                    t.next();
                }
                (Some(pc), Some(tc)) if *pc == *tc => {
                    p.next();
                    t.next();
                }
                _ => return false,
            }
        }
    }

    match_inner(&mut p, &mut t)
}

fn cmd_build(
    config: &cvmbuild_config::Config,
    image_dir: &std::path::Path,
    skip_container: bool,
    output: &std::path::Path,
    dry_run: bool,
    no_download: bool,
) -> Result<()> {
    // Validate first
    let errors = config.validate();
    if !errors.is_empty() {
        println!("Config validation failed:");
        for error in &errors {
            println!("  FAIL  {error}");
        }
        std::process::exit(1);
    }

    // Download models if needed (before container build)
    download_models(config, image_dir, no_download)?;

    // Resolve the container image source:
    //   base is a file path (exists)  → build from that file
    //   base is an OCI ref            → pull it
    //   no base + Dockerfile exists   → build from Dockerfile
    //   none of the above             → error
    enum ImageSource {
        BuildFrom(PathBuf),
        Pull(String),
    }

    let source = if let Some(ref base) = config.image.base {
        // base set — check if it's a file path
        let as_path = std::path::Path::new(base);
        let resolved = if as_path.is_absolute() {
            as_path.to_path_buf()
        } else {
            image_dir.join(base)
        };
        if resolved.is_file() {
            ImageSource::BuildFrom(resolved)
        } else {
            ImageSource::Pull(base.clone())
        }
    } else {
        let dockerfile = image_dir.join("Dockerfile");
        if dockerfile.is_file() {
            ImageSource::BuildFrom(dockerfile)
        } else {
            anyhow::bail!(
                "no base image and no Dockerfile — set [image] base in cvm.toml or add a Dockerfile to {}",
                image_dir.display()
            );
        }
    };

    if dry_run {
        let source_str = match &source {
            ImageSource::Pull(r) => format!("pull {r}"),
            ImageSource::BuildFrom(p) => format!("build {}", p.display()),
        };
        println!("=== Dry Run ===");
        println!("Image:       {} v{}", config.image.id, config.image.version);
        println!("Source:      {source_str}");
        println!(
            "Verity:      {}",
            if config.verity.enabled { "yes" } else { "no" }
        );
        println!("Remove:      {} binaries", config.security.remove.len());
        println!(
            "Firewall:    {} inbound rules, outbound={}",
            config.firewall.inbound.len(),
            config.firewall.outbound
        );
        for disk in &config.verity_disks {
            let build_status = if disk.source.is_some() {
                "build"
            } else {
                "external"
            };
            println!(
                "Disk '{}':    {} on {} at {} [{}]",
                disk.name,
                disk.device,
                disk.mountpoint,
                disk.source.as_deref().unwrap_or("-"),
                build_status
            );
        }
        println!("Output:      {}", output.display());
        println!();
        println!("Artifacts:");
        let name = format!("{}_{}", config.image.id, config.image.version);
        println!("  {name}.raw       — GPT disk (squashfs + verity)");
        println!("  {name}.vmlinuz   — kernel");
        println!("  {name}.initrd    — initrd with verity overlay");
        println!("  {name}.roothash  — root verity hash");
        println!("  manifest.json    — attestation manifest");
        println!("\nWould run: docker buildx build → extract → overlay → services → seal");
        return Ok(());
    }

    // Use tmpfs (/dev/shm) for work dir when available — the 2GB rootfs
    // extraction is I/O-bound and ~10x faster in RAM.
    let work_dir = if std::path::Path::new("/dev/shm").exists() {
        let p = PathBuf::from(format!(
            "/dev/shm/cvmbuild-{}-{}",
            config.image.id, config.image.version
        ));
        tracing::info!("Using tmpfs work dir: {}", p.display());
        p
    } else {
        output.join("work")
    };
    std::fs::create_dir_all(&work_dir)?;

    // Step 1+2: Build/pull and extract rootfs via BuildKit
    let extractor = cvmbuild_oci::OciExtractor::new(&work_dir);
    let rootfs = if skip_container {
        // Reuse existing rootfs
        let existing = work_dir.join("rootfs");
        if !existing.exists() {
            anyhow::bail!(
                "--skip-container but no existing rootfs at {}",
                existing.display()
            );
        }
        existing
    } else {
        check_docker()?;

        // Stage the pinned kawa binary into the base-image build context so the
        // base Dockerfile's `COPY kawa /usr/local/bin/kawa` picks up the exact
        // released bytes — kawa is part of the rootfs and its hash feeds into
        // every SNP/TDX measurement, so the version pin in cvm.toml MUST be
        // what actually gets baked in.
        if let Some(ref version) = config.image.kawa_version {
            stage_kawa(config, image_dir, version)?;
        }

        // Resolve APT_MIRROR: use env var if set, otherwise start embedded cache proxy.
        // Caches to /var/cache/cvmbuild/apt/. Docker reaches it via --network=host.
        let (apt_mirror, _apt_proxy) = if std::env::var("APT_MIRROR")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            tracing::info!("APT_MIRROR already set, skipping embedded cache proxy");
            (std::env::var("APT_MIRROR").unwrap_or_default(), None)
        } else {
            let cache_dir = std::path::Path::new("/var/cache/cvmbuild/apt");
            let _ = std::fs::create_dir_all(cache_dir);
            match cache::AptCacheProxy::start("http://snapshot.ubuntu.com", cache_dir) {
                Ok(proxy) => {
                    let mirror_url = proxy.url();
                    tracing::info!("apt cache proxy: {mirror_url} → http://snapshot.ubuntu.com");
                    (mirror_url, Some(proxy))
                }
                Err(e) => {
                    tracing::warn!(
                        "failed to start apt cache proxy: {e} (continuing without cache)"
                    );
                    (String::new(), None)
                }
            }
        };

        // Auto-build base image if configured and missing
        if let Some(ref base_image) = config.image.base_image {
            let inspect = std::process::Command::new("docker")
                .args(["image", "inspect", base_image])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            let exists = inspect.map(|s| s.success()).unwrap_or(false);
            if !exists {
                let base_dockerfile = match config.image.base_image_dockerfile.as_deref() {
                    Some(d) => d,
                    None => anyhow::bail!(
                        "base_image '{}' not found and no base_image_dockerfile specified in cvm.toml",
                        base_image
                    ),
                };
                let build_context = if let Some(ref ctx) = config.image.context {
                    let p = std::path::Path::new(ctx);
                    if p.is_absolute() {
                        p.to_path_buf()
                    } else {
                        image_dir.join(ctx).canonicalize().with_context(|| {
                            format!("resolving context path: {}", image_dir.join(ctx).display())
                        })?
                    }
                } else {
                    image_dir.to_path_buf()
                };
                let df_path = build_context.join(base_dockerfile);
                if !df_path.is_file() {
                    anyhow::bail!(
                        "base_image_dockerfile '{}' not found at {}",
                        base_dockerfile,
                        df_path.display()
                    );
                }
                tracing::info!(
                    "Base image '{}' not found — building from {}",
                    base_image,
                    df_path.display()
                );
                println!(
                    "Building base image: {} (from {})",
                    base_image, base_dockerfile
                );

                let mut cmd = std::process::Command::new("docker");
                cmd.args([
                    "buildx",
                    "build",
                    "--network=host",
                    "-f",
                    &df_path.to_string_lossy(),
                    "-t",
                    base_image,
                ]);
                // Pass APT_MIRROR if set
                if !apt_mirror.is_empty() {
                    cmd.args(["--build-arg", &format!("APT_MIRROR={}", apt_mirror)]);
                }
                // Pass BUILDX_CACHE if set
                if let Ok(cache) = std::env::var("BUILDX_CACHE") {
                    if !cache.is_empty() {
                        let (from, to) = if cache.starts_with('/') {
                            (
                                format!("type=local,src={}/cvm-base", cache),
                                format!("type=local,dest={}/cvm-base,mode=max", cache),
                            )
                        } else {
                            (
                                format!("type=registry,ref={}/cvm-base", cache),
                                format!("type=registry,ref={}/cvm-base,mode=max", cache),
                            )
                        };
                        cmd.args(["--cache-from", &from, "--cache-to", &to]);
                    }
                }
                // The base-image Dockerfile is self-contained — its only inputs are
                // its own directory (the kawa binary staged by stage_kawa, plus heredoc
                // content). Use the dockerfile's parent as the docker build context so
                // `COPY kawa /usr/local/bin/kawa` resolves to the staged binary instead
                // of looking for it at the global config context root.
                let base_build_context = df_path.parent().unwrap_or(&build_context);
                cmd.arg(base_build_context.to_string_lossy().to_string());
                let status = cmd.status().context("failed to build base image")?;
                if !status.success() {
                    anyhow::bail!("base image build failed for '{}'", base_image);
                }
                println!("Base image '{}' built successfully", base_image);
            }
        }

        match &source {
            ImageSource::Pull(r) => {
                tracing::info!("Pulling image: {}", r);
                extractor.pull_rootfs(r)?
            }
            ImageSource::BuildFrom(dockerfile) => {
                let build_context = if let Some(ref ctx) = config.image.context {
                    let p = std::path::Path::new(ctx);
                    if p.is_absolute() {
                        p.to_path_buf()
                    } else {
                        image_dir.join(ctx).canonicalize().with_context(|| {
                            format!("resolving context path: {}", image_dir.join(ctx).display())
                        })?
                    }
                } else {
                    dockerfile.parent().unwrap_or(image_dir).to_path_buf()
                };
                tracing::info!(
                    "Building from {} → rootfs (docker buildx)",
                    dockerfile.display(),
                );
                // Pass APT_MIRROR so image Dockerfiles use the cache proxy
                let build_args: Vec<(&str, &str)> = if apt_mirror.is_empty() {
                    vec![]
                } else {
                    vec![("APT_MIRROR", &apt_mirror)]
                };
                extractor.build_rootfs(dockerfile, &build_context, &build_args)?
            }
        }
    };

    // Step 3: Apply overlay + services + hardening
    tracing::info!("Applying overlay, services, and hardening");
    let rootfs_builder = cvmbuild_rootfs::RootfsBuilder::new(&rootfs);
    rootfs_builder.apply(config)?;

    // Clean previous cvmbuild artifacts from output dir to prevent stale files
    // from a renamed image lingering alongside new ones. Only removes known
    // cvmbuild extensions — leaves teehost files (build.log, ovmf_vars.fd) alone.
    if output.is_dir() {
        const CVMBUILD_EXTS: &[&str] = &[
            ".vmlinuz",
            ".initrd",
            ".raw",
            ".roothash",
            ".squashfs",
            ".verity",
            ".img",
            ".hashoffset",
        ];
        for entry in std::fs::read_dir(output)?.filter_map(|e| e.ok()) {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let dominated =
                CVMBUILD_EXTS.iter().any(|ext| name.ends_with(ext)) || name == "manifest.json";
            if dominated && entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                std::fs::remove_file(entry.path())?;
            }
        }
    }

    // Step 4: Seal (squashfs → verity → GPT + kernel + initrd)
    tracing::info!("Sealing image");
    let sealer = cvmbuild_image::ImageSealer::new(output);
    let result = sealer.seal(&rootfs, config)?;

    // Step 5: Build verity disks that have source defined
    // If config_env is set in cvm.toml, generate disks/config/config.env automatically
    let _config_env_dir = if !config.config_env.is_empty() {
        let dir = output.join("_config_env");
        std::fs::create_dir_all(&dir)?;
        let env_content: String = config
            .config_env
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(dir.join("config.env"), env_content + "\n")?;
        tracing::info!(
            "Generated config.env from [config_env] ({} vars)",
            config.config_env.len()
        );
        Some(dir)
    } else {
        None
    };
    let mut disk_results = Vec::new();
    for disk in &config.verity_disks {
        // Resolve source: config_env auto-generated dir > explicit source > skip
        let resolved = if disk.name == "config" && _config_env_dir.is_some() {
            _config_env_dir.clone().unwrap()
        } else if let Some(ref source_path) = disk.source {
            if std::path::Path::new(source_path).is_absolute() {
                PathBuf::from(source_path)
            } else {
                image_dir.join(source_path)
            }
        } else {
            continue;
        };
        if !resolved.is_dir() {
            anyhow::bail!(
                "verity disk '{}' source '{}' is not a directory (resolved: {})",
                disk.name,
                disk.source.as_deref().unwrap_or("<config_env>"),
                resolved.display()
            );
        }
        {
            let disk_output = output.join(format!("{}.img", disk.name));
            let uuid = disk
                .uuid
                .clone()
                .unwrap_or_else(|| deterministic_uuid(&disk.name));
            tracing::info!(
                "Building verity disk '{}' from {}",
                disk.name,
                resolved.display()
            );
            let disk_result = cvmbuild_image::ext4::create_verity_disk(
                &resolved,
                &disk_output,
                &disk.name,
                &uuid,
            )?;

            // Write roothash and hashoffset files
            let roothash_path = disk_output.with_extension("roothash");
            std::fs::write(&roothash_path, &disk_result.roothash)?;
            let hashoffset_path = disk_output.with_extension("hashoffset");
            std::fs::write(&hashoffset_path, disk_result.hashoffset.to_string())?;

            println!(
                "Verity disk '{}': {} (roothash: {})",
                disk.name,
                disk_output.display(),
                disk_result.roothash,
            );
            disk_results.push((disk.name.clone(), disk_result));
        }
    }

    // Step 6: Generate manifest (after verity disks so measurements include disk hashes)
    let kernel_hash = result
        .kernel
        .as_ref()
        .map(|k| k.1.as_str())
        .unwrap_or("UNAVAILABLE");
    let initrd_hash = result
        .initrd
        .as_ref()
        .map(|i| i.1.as_str())
        .unwrap_or("UNAVAILABLE");
    let kernel_file = result.kernel.as_ref().map(|k| k.0.as_path());
    let initrd_file = result.initrd.as_ref().map(|i| i.0.as_path());
    let disk_refs: Vec<(&str, &cvmbuild_image::ext4::VerityDiskResult)> = disk_results
        .iter()
        .map(|(name, dr)| (name.as_str(), dr))
        .collect();
    let manifest = cvmbuild_image::manifest::build_manifest(
        config,
        &result.roothash,
        kernel_hash,
        initrd_hash,
        &disk_refs,
        kernel_file,
        initrd_file,
    );
    let manifest_path = output.join("manifest.json");
    cvmbuild_image::manifest::write_manifest(&manifest, &manifest_path)?;
    tracing::info!("manifest: {}", manifest_path.display());

    println!("\n=== Build Complete ===");
    println!("Image:      {}", result.image_path.display());
    println!("Roothash:   {}", result.roothash);
    println!("Image hash: {}", result.image_hash);
    if let Some((ref path, ref hash)) = result.kernel {
        println!("Kernel:     {} ({})", path.display(), hash);
    }
    if let Some((ref path, ref hash)) = result.initrd {
        println!("Initrd:     {} ({})", path.display(), hash);
    }
    for (name, dr) in &disk_results {
        println!(
            "Disk '{}':   {} (roothash: {})",
            name,
            dr.image_path.display(),
            dr.roothash
        );
    }
    println!("Manifest:   {}", manifest_path.display());
    // Print measurements from the manifest
    if let Ok(content) = std::fs::read_to_string(&manifest_path) {
        if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(measurements) = manifest.get("measurements") {
                print_measurements(measurements);
            }
        }
    }

    // Clean up tmpfs work dir to free RAM
    if work_dir.starts_with("/dev/shm") {
        tracing::info!("Cleaning up tmpfs work dir");
        let _ = std::fs::remove_dir_all(&work_dir);
    }

    Ok(())
}

fn cmd_extract(
    config: &cvmbuild_config::Config,
    base: &str,
    output: &std::path::Path,
) -> Result<()> {
    std::fs::create_dir_all(output)?;

    let image_ref = if base == "default" {
        config.image.base.as_deref().unwrap_or_else(|| {
            eprintln!("error: no base image set in cvm.toml — cannot extract");
            std::process::exit(1);
        })
    } else {
        base
    };

    tracing::info!("Extracting rootfs from {}", image_ref);
    let extractor = cvmbuild_oci::OciExtractor::new(output);
    let rootfs = extractor.pull_and_extract(image_ref)?;
    println!("Rootfs extracted to: {}", rootfs.display());

    Ok(())
}

fn cmd_seal(
    config: &cvmbuild_config::Config,
    rootfs: &std::path::Path,
    output: &std::path::Path,
) -> Result<()> {
    // Apply overlay + services + hardening first
    tracing::info!(
        "Applying overlay, services, and hardening to {}",
        rootfs.display()
    );
    let rootfs_builder = cvmbuild_rootfs::RootfsBuilder::new(rootfs);
    rootfs_builder.apply(config)?;

    // Seal
    let sealer = cvmbuild_image::ImageSealer::new(output);
    let result = sealer.seal(rootfs, config)?;

    // Generate manifest (no verity disks in standalone seal)
    let kernel_hash = result
        .kernel
        .as_ref()
        .map(|k| k.1.as_str())
        .unwrap_or("UNAVAILABLE");
    let initrd_hash = result
        .initrd
        .as_ref()
        .map(|i| i.1.as_str())
        .unwrap_or("UNAVAILABLE");
    let kernel_file = result.kernel.as_ref().map(|k| k.0.as_path());
    let initrd_file = result.initrd.as_ref().map(|i| i.0.as_path());
    let manifest = cvmbuild_image::manifest::build_manifest(
        config,
        &result.roothash,
        kernel_hash,
        initrd_hash,
        &[],
        kernel_file,
        initrd_file,
    );
    let manifest_path = output.join("manifest.json");
    cvmbuild_image::manifest::write_manifest(&manifest, &manifest_path)?;

    println!("\n=== Seal Complete ===");
    println!("Image:      {}", result.image_path.display());
    println!("Roothash:   {}", result.roothash);
    println!("Image hash: {}", result.image_hash);
    if let Some((ref path, ref hash)) = result.kernel {
        println!("Kernel:     {} ({})", path.display(), hash);
    }
    if let Some((ref path, ref hash)) = result.initrd {
        println!("Initrd:     {} ({})", path.display(), hash);
    }
    println!("Manifest:   {}", manifest_path.display());

    Ok(())
}

/// Generate a deterministic UUID from a disk name.
/// Uses SHA-256 of a fixed namespace + name, formatted as UUID v5.
fn deterministic_uuid(name: &str) -> String {
    use sha2::Digest;
    let namespace = b"cvmbuild-verity-disk-namespace-2026";
    let mut hasher = sha2::Sha256::new();
    hasher.update(namespace);
    hasher.update(name.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let mut b = [0u8; 16];
    b.copy_from_slice(&hash[..16]);
    b[6] = (b[6] & 0x0f) | 0x50; // version 5
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

fn cmd_measure(config: &cvmbuild_config::Config, output: &std::path::Path) -> Result<()> {
    let prefix = format!("{}_{}", config.image.id, config.image.version);

    // Locate build artifacts
    let kernel_path = output.join(format!("{prefix}.vmlinuz"));
    let initrd_path = output.join(format!("{prefix}.initrd"));
    let roothash_path = output.join(format!("{prefix}.roothash"));

    if !kernel_path.exists() || !initrd_path.exists() || !roothash_path.exists() {
        anyhow::bail!(
            "build artifacts not found in {} — run 'cvmbuild build' first",
            output.display()
        );
    }

    // Reconstruct cmdline from build artifacts (same as build_manifest)
    let rootfs_roothash = std::fs::read_to_string(&roothash_path)?.trim().to_string();
    let mut disk_tuples = Vec::new();
    for disk in &config.verity_disks {
        let rh_path = output.join(format!("{}.roothash", disk.name));
        let ho_path = output.join(format!("{}.hashoffset", disk.name));
        if rh_path.exists() && ho_path.exists() {
            let rh = std::fs::read_to_string(&rh_path)?.trim().to_string();
            let ho: u64 = std::fs::read_to_string(&ho_path)?.trim().parse()?;
            disk_tuples.push((disk.name.clone(), rh, ho));
        }
    }
    let disk_refs: Vec<(&str, &str, u64)> = disk_tuples
        .iter()
        .map(|(n, r, h)| (n.as_str(), r.as_str(), *h))
        .collect();
    let cmdline = cvmbuild_image::manifest::build_boot_cmdline(
        &config.kernel.cmdline,
        &rootfs_roothash,
        &disk_refs,
    );

    // Compute measurements on-the-fly
    let snp = cvmbuild_image::manifest::compute_snp_measurements(
        config,
        Some(&kernel_path),
        Some(&initrd_path),
        &cmdline,
    );
    let tdx = cvmbuild_image::manifest::compute_tdx_measurements(
        config,
        Some(&kernel_path),
        Some(&initrd_path),
        &cmdline,
    );

    // Build JSON for printing
    let measurements = serde_json::json!({
        "snp": snp,
        "tdx": tdx,
    });
    print_measurements(&measurements);

    // Diff against existing manifest if present
    let manifest_path = output.join("manifest.json");
    if manifest_path.exists() {
        let content = std::fs::read_to_string(&manifest_path)?;
        if let Ok(old_manifest) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(old_measurements) = old_manifest.get("measurements") {
                let mut changes = Vec::new();
                for (platform, new_vals) in [("snp", &snp), ("tdx", &tdx)] {
                    if let Some(old_obj) =
                        old_measurements.get(platform).and_then(|v| v.as_object())
                    {
                        for (key, new_val) in new_vals {
                            if let Some(old_val) = old_obj.get(key).and_then(|v| v.as_str()) {
                                if old_val != new_val {
                                    let old_short = if old_val.len() > 16 {
                                        &old_val[..16]
                                    } else {
                                        old_val
                                    };
                                    let new_short = if new_val.len() > 16 {
                                        &new_val[..16]
                                    } else {
                                        new_val
                                    };
                                    changes.push(format!(
                                        "  {platform}.{key}: {old_short}… → {new_short}…"
                                    ));
                                }
                            }
                        }
                    }
                }
                if changes.is_empty() {
                    println!("manifest.json is up to date.");
                } else {
                    println!(
                        "manifest.json is STALE ({} measurement{} changed):",
                        changes.len(),
                        if changes.len() == 1 { "" } else { "s" }
                    );
                    for c in &changes {
                        println!("{c}");
                    }
                    println!("\nRun 'cvmbuild build' to update manifest.json.");
                }
            }
        }
    }

    Ok(())
}

struct BootCmdOpts<'a> {
    config: &'a cvmbuild_config::Config,
    output: &'a std::path::Path,
    tee: &'a str,
    qemu_bin: &'a str,
    ovmf: Option<&'a std::path::Path>,
    mem: &'a str,
    smp: &'a str,
    port: &'a str,
    absolute: bool,
}

fn print_measurements(measurements: &serde_json::Value) {
    if let Some(snp) = measurements.get("snp").and_then(|v| v.as_object()) {
        let max_key = snp.keys().map(|k| k.len()).max().unwrap_or(0);
        println!("\n  SNP:");
        for (key, val) in snp {
            println!(
                "    {:<width$}  {}",
                key,
                val.as_str().unwrap_or("?"),
                width = max_key
            );
        }
    }

    if let Some(tdx) = measurements.get("tdx").and_then(|v| v.as_object()) {
        let max_key = tdx.keys().map(|k| k.len()).max().unwrap_or(0);
        println!("\n  TDX:");
        for (key, val) in tdx {
            println!(
                "    {:<width$}  {}",
                key,
                val.as_str().unwrap_or("?"),
                width = max_key
            );
        }
    }

    println!();
}

fn cmd_boot_cmd(opts: &BootCmdOpts<'_>) -> Result<()> {
    let prefix = format!("{}_{}", opts.config.image.id, opts.config.image.version);

    // Optionally canonicalize output dir for absolute paths
    let output = if opts.absolute {
        opts.output.canonicalize().with_context(|| {
            format!(
                "output dir {} not found — has the image been built?",
                opts.output.display()
            )
        })?
    } else {
        opts.output.to_path_buf()
    };

    // Read roothash
    let roothash_path = output.join(format!("{prefix}.roothash"));
    let roothash = std::fs::read_to_string(&roothash_path)
        .with_context(|| {
            format!(
                "reading {} — has the image been built?",
                roothash_path.display()
            )
        })?
        .trim()
        .to_string();

    // Validate QEMU binary exists
    if !std::path::Path::new(opts.qemu_bin).exists() {
        anyhow::bail!(
            "QEMU binary not found: {} — pass --qemu-bin <path> or install matcha-provisioned QEMU",
            opts.qemu_bin
        );
    }

    // Validate all required artifacts exist
    let vmlinuz = output.join(format!("{prefix}.vmlinuz"));
    let initrd = output.join(format!("{prefix}.initrd"));
    let raw_disk = output.join(format!("{prefix}.raw"));

    let mut missing = Vec::new();
    for (label, path) in [
        ("kernel", &vmlinuz),
        ("initrd", &initrd),
        ("root disk", &raw_disk),
    ] {
        if !path.exists() {
            missing.push(format!("  {label}: {}", path.display()));
        }
    }
    for disk in &opts.config.verity_disks {
        let img = output.join(format!("{}.img", disk.name));
        if !img.exists() {
            missing.push(format!("  verity disk '{}': {}", disk.name, img.display()));
        }
    }
    if !missing.is_empty() {
        anyhow::bail!(
            "missing build artifacts — run 'cvmbuild build' first:\n{}",
            missing.join("\n")
        );
    }

    // Build cmdline using the shared builder (same as manifest measurement)
    let mut disk_tuples: Vec<(&str, String, u64)> = Vec::new();
    for disk in &opts.config.verity_disks {
        let rh = output.join(format!("{}.roothash", disk.name));
        let ho = output.join(format!("{}.hashoffset", disk.name));
        if rh.exists() {
            let hash = std::fs::read_to_string(&rh)?.trim().to_string();
            let offset: u64 = std::fs::read_to_string(&ho)
                .unwrap_or_default()
                .trim()
                .parse()
                .unwrap_or(0);
            disk_tuples.push((&disk.name, hash, offset));
        }
    }
    let disk_refs: Vec<(&str, &str, u64)> = disk_tuples
        .iter()
        .map(|(name, hash, offset)| (*name, hash.as_str(), *offset))
        .collect();
    let cmdline = cvmbuild_image::manifest::build_boot_cmdline(
        &opts.config.kernel.cmdline,
        &roothash,
        &disk_refs,
    );

    // Build QEMU command
    let mut args: Vec<String> = Vec::new();

    // Point QEMU at its share/ dir (sibling of the binary)
    let qemu_dir = std::path::Path::new(opts.qemu_bin)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let share_dir = qemu_dir.join("share/qemu");
    if share_dir.exists() {
        args.push(format!("-L {}", share_dir.display()));
    }

    match opts.tee {
        "snp" => {
            let ovmf_path = opts
                .ovmf
                .or_else(|| {
                    opts.config
                        .manifest
                        .snp
                        .ovmf_file
                        .as_ref()
                        .map(std::path::Path::new)
                })
                .context("--ovmf or [manifest.snp] ovmf_file required for SNP")?;
            if !ovmf_path.exists() {
                anyhow::bail!("OVMF firmware not found: {}", ovmf_path.display());
            }
            args.push("-machine q35,accel=kvm,confidential-guest-support=sev0".into());
            args.push("-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x30000,kernel-hashes=on".into());
            args.push("-cpu EPYC-v4,+avx512f,+avx512dq,+avx512cd,+avx512bw,+avx512vl,+avx512ifma,+avx512vbmi".into());
            args.push(format!("-bios {}", ovmf_path.display()));
            // vsock for teehost (SNP cert serving + ping)
            args.push("-device vhost-vsock-pci,guest-cid=3".into());
        }
        "tdx" => {
            let ovmf_path = opts
                .ovmf
                .or_else(|| {
                    opts.config
                        .manifest
                        .tdx
                        .ovmf_file
                        .as_ref()
                        .map(std::path::Path::new)
                })
                .context("--ovmf or [manifest.tdx] ovmf_file required for TDX")?;
            if !ovmf_path.exists() {
                anyhow::bail!("OVMF firmware not found: {}", ovmf_path.display());
            }
            // TDX requires memory-backend-memfd with share=true for confidential memory
            args.push(
                "-machine q35,accel=kvm,confidential-guest-support=tdx0,memory-backend=ram1"
                    .to_string(),
            );
            args.push(format!(
                "-object memory-backend-memfd,id=ram1,size={},share=true,prealloc=false",
                opts.mem
            ));
            // QEMU connects directly to the QGS unix socket for TDX quote generation
            args.push(r#"-object {"qom-type":"tdx-guest","id":"tdx0","quote-generation-socket":{"type":"unix","path":"/var/run/teehost/qgs.sock"}}"#.into());
            args.push("-cpu host".into());
            args.push(format!("-bios {}", ovmf_path.display()));
            args.push("-device vhost-vsock-pci,guest-cid=3".into());
        }
        "none" => {
            args.push("-machine q35,accel=kvm".into());
            args.push("-cpu host".into());
            // vsock for teehost (cert serving + ping, same as TEE modes)
            args.push("-device vhost-vsock-pci,guest-cid=3".into());
            // Use OVMF if available (matches production boot path)
            let ovmf_path = opts.ovmf.or_else(|| {
                opts.config
                    .manifest
                    .snp
                    .ovmf_file
                    .as_ref()
                    .map(std::path::Path::new)
            });
            if let Some(ovmf) = ovmf_path {
                if ovmf.exists() {
                    // OVMF_VARS needs to be writable — copy to a temp location
                    let vars_src = ovmf.with_file_name("OVMF_VARS.fd");
                    if vars_src.exists() {
                        let vars_tmp = output.join("ovmf_vars.fd");
                        if !vars_tmp.exists() {
                            std::fs::copy(&vars_src, &vars_tmp)?;
                        }
                        args.push(format!(
                            "-drive if=pflash,format=raw,unit=0,file={},readonly=on",
                            ovmf.display()
                        ));
                        args.push(format!(
                            "-drive if=pflash,format=raw,unit=1,file={}",
                            vars_tmp.display()
                        ));
                    } else {
                        args.push(format!("-bios {}", ovmf.display()));
                    }
                }
            }
        }
        other => anyhow::bail!("unknown TEE mode: {other} (use snp, tdx, or none)"),
    }

    // TDX requires disable-legacy=on,iommu_platform=on on all virtio-pci devices
    let virtio_suffix = if opts.tee == "tdx" {
        ",disable-legacy=on,iommu_platform=on"
    } else {
        ""
    };

    args.push(format!("-smp {}", opts.smp));
    args.push(format!("-m {}", opts.mem));
    args.push("-nographic -serial mon:stdio".into());
    args.push(format!("-kernel {}", vmlinuz.display()));
    args.push(format!("-initrd {}", initrd.display()));
    args.push(format!("-append \"{cmdline}\""));

    // Root disk
    args.push(format!(
        "-drive id=disk0,if=none,format=raw,file={},readonly=on",
        raw_disk.display()
    ));
    args.push(format!("-device virtio-blk-pci,drive=disk0{virtio_suffix}"));

    // Verity disks
    for disk in &opts.config.verity_disks {
        let img = output.join(format!("{}.img", disk.name));
        args.push(format!(
            "-drive id={},if=none,format=raw,file={},readonly=on",
            disk.name,
            img.display()
        ));
        args.push(format!(
            "-device virtio-blk-pci,drive={}{virtio_suffix}",
            disk.name
        ));
    }

    args.push(format!(
        "-netdev user,id=net0,hostfwd=tcp::{}-:8443",
        opts.port
    ));
    args.push(format!("-device virtio-net-pci,netdev=net0{virtio_suffix}"));
    args.push("-no-reboot".into());

    // Print mode header
    let mode_label = match opts.tee {
        "snp" => "AMD SEV-SNP",
        "tdx" => "Intel TDX",
        _ => "non-TEE (OVMF EFI)",
    };
    let title = format!("  QEMU Boot: {}", mode_label);
    let width = title.len() + 2; // trailing padding
    println!("\n╔{}╗", "═".repeat(width));
    println!("║{:<width$}║", title);
    println!("╚{}╝\n", "═".repeat(width));

    println!("sudo {} \\", opts.qemu_bin);
    for (i, arg) in args.iter().enumerate() {
        if i < args.len() - 1 {
            println!("    {arg} \\");
        } else {
            println!("    {arg}");
        }
    }

    // Show all TEE modes, mark current with *
    println!();
    let modes = [
        ("none", "non-TEE (OVMF EFI)"),
        ("snp", "AMD SEV-SNP"),
        ("tdx", "Intel TDX"),
    ];
    for (flag, label) in modes {
        let marker = if flag == opts.tee { "*" } else { " " };
        println!("  {marker} --tee {:<5} {}", flag, label);
    }

    Ok(())
}

fn cmd_verity_disk(
    source: &std::path::Path,
    output: &std::path::Path,
    label: &str,
    uuid: &str,
) -> Result<()> {
    tracing::info!("Creating ext4+verity disk from {}", source.display());
    let result = cvmbuild_image::ext4::create_verity_disk(source, output, label, uuid)?;

    println!("\n=== Verity Disk Complete ===");
    println!("Image:      {}", result.image_path.display());
    println!("Roothash:   {}", result.roothash);
    println!("Hashoffset: {}", result.hashoffset);
    println!("Image hash: {}", result.image_hash);

    // Write roothash and hashoffset files
    let roothash_path = output.with_extension("roothash");
    std::fs::write(&roothash_path, &result.roothash)?;
    println!("Roothash:   {} (written)", roothash_path.display());

    let hashoffset_path = output.with_extension("hashoffset");
    std::fs::write(&hashoffset_path, result.hashoffset.to_string())?;
    println!("Hashoffset: {} (written)", hashoffset_path.display());

    Ok(())
}
