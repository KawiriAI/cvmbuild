//! Shared on-disk cache for pinned kawa and OVMF release artifacts.
//!
//! Layout (all immutable once present):
//!     <root>/kawa/<version>/kawa
//!     <root>/ovmf/<version>/{OVMF.fd, OVMF_TDX.fd, OVMF_CODE.fd, OVMF_VARS.fd, CvmDsdt.aml}
//!
//! Root selection (in order):
//!     1. KAWIRI_CACHE_DIR env var
//!     2. /var/lib/kawiri (if writable / creatable)
//!     3. $XDG_CACHE_HOME/kawiri or $HOME/.cache/kawiri
//!
//! Multiple versions coexist; cvmbuild looks up the version pinned in cvm.toml
//! and reuses the cached copy across image builds.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

const KAWIRI_REPO: &str = "KawiriAI/kawiri";

/// Resolve the cache root, creating it if necessary.
pub fn cache_root() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("KAWIRI_CACHE_DIR") {
        let p = PathBuf::from(custom);
        std::fs::create_dir_all(&p)
            .with_context(|| format!("creating KAWIRI_CACHE_DIR {}", p.display()))?;
        return Ok(p);
    }

    let primary = PathBuf::from("/var/lib/kawiri");
    if std::fs::create_dir_all(&primary).is_ok() && is_writable(&primary) {
        return Ok(primary);
    }

    let home = std::env::var("HOME").context("HOME not set; cannot fall back to user cache")?;
    let xdg = std::env::var("XDG_CACHE_HOME").unwrap_or_else(|_| format!("{home}/.cache"));
    let fallback = PathBuf::from(xdg).join("kawiri");
    std::fs::create_dir_all(&fallback)
        .with_context(|| format!("creating user cache dir {}", fallback.display()))?;
    tracing::warn!(
        "/var/lib/kawiri not writable — using fallback cache at {}",
        fallback.display()
    );
    Ok(fallback)
}

fn is_writable(p: &Path) -> bool {
    let probe = p.join(".cvmbuild-write-probe");
    let ok = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// Ensure the kawa binary for `version` is present in the cache.
/// Returns the absolute path to the binary.
pub fn ensure_kawa(version: &str) -> Result<PathBuf> {
    let dir = cache_root()?.join("kawa").join(version);
    let bin = dir.join("kawa");
    if bin.is_file() {
        tracing::debug!("kawa v{version} cached at {}", bin.display());
        return Ok(bin);
    }

    let asset = format!("kawa-v{version}-linux-x86_64.tar.gz");
    let url = format!("https://github.com/{KAWIRI_REPO}/releases/download/kawa-v{version}/{asset}");

    tracing::info!("Downloading kawa v{version} → {}", dir.display());
    download_release(&url, &dir)
        .with_context(|| format!("downloading kawa v{version} from {url}"))?;

    // Release tarball ships the binary as `kawa-bin`. Rename to `kawa` so the
    // base-image Dockerfile's `COPY kawa /usr/local/bin/kawa` works directly
    // when we stage from this cache.
    let staged = dir.join("kawa-bin");
    if staged.exists() && !bin.exists() {
        std::fs::rename(&staged, &bin)
            .with_context(|| format!("renaming kawa-bin → kawa in {}", dir.display()))?;
    }
    if !bin.is_file() {
        anyhow::bail!(
            "kawa release tarball did not contain kawa-bin (or kawa) — got: {:?}",
            list_dir(&dir).unwrap_or_default()
        );
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
    Ok(bin)
}

/// Ensure the OVMF release for `version` is present in the cache.
/// Returns the absolute path to the directory containing OVMF.fd, etc.
pub fn ensure_ovmf(version: &str) -> Result<PathBuf> {
    let dir = cache_root()?.join("ovmf").join(version);
    if dir.join("OVMF.fd").is_file() {
        tracing::debug!("ovmf v{version} cached at {}", dir.display());
        return Ok(dir);
    }

    let asset = format!("ovmf-v{version}.tar.gz");
    let url = format!("https://github.com/{KAWIRI_REPO}/releases/download/ovmf-v{version}/{asset}");

    tracing::info!("Downloading ovmf v{version} → {}", dir.display());
    download_release(&url, &dir)
        .with_context(|| format!("downloading ovmf v{version} from {url}"))?;

    if !dir.join("OVMF.fd").is_file() {
        anyhow::bail!(
            "ovmf release tarball did not contain OVMF.fd — got: {:?}",
            list_dir(&dir).unwrap_or_default()
        );
    }
    Ok(dir)
}

/// Download a tar.gz from `url` and atomically extract it into `target`.
/// Uses curl + tar from PATH to avoid pulling in extra Rust deps.
fn download_release(url: &str, target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Stage in a sibling directory so a crashed run never leaves a partial
    // dir at the version-named final path (which we treat as authoritative).
    let staging = target.with_file_name(format!(
        ".{}.partial",
        target.file_name().and_then(|s| s.to_str()).unwrap_or("dl")
    ));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)?;

    let mut curl = Command::new("curl")
        .args(["-fsSL", url])
        .stdout(Stdio::piped())
        .spawn()
        .context("spawning curl (is it installed?)")?;
    let curl_stdout = curl.stdout.take().expect("curl stdout piped");

    let tar_status = Command::new("tar")
        .args(["-xz", "-C"])
        .arg(&staging)
        .stdin(curl_stdout)
        .status()
        .context("running tar (is it installed?)")?;
    let curl_status = curl.wait().context("waiting on curl")?;

    if !curl_status.success() {
        let _ = std::fs::remove_dir_all(&staging);
        anyhow::bail!("curl failed for {url} (status {curl_status})");
    }
    if !tar_status.success() {
        let _ = std::fs::remove_dir_all(&staging);
        anyhow::bail!("tar extraction failed (status {tar_status})");
    }

    // Atomic-ish swap-in. If another build raced us, we'll just overwrite —
    // contents are version-pinned and content-equal.
    if target.exists() {
        let _ = std::fs::remove_dir_all(target);
    }
    std::fs::rename(&staging, target)
        .with_context(|| format!("renaming {} → {}", staging.display(), target.display()))?;
    Ok(())
}

fn list_dir(p: &Path) -> Result<Vec<String>> {
    Ok(std::fs::read_dir(p)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect())
}
