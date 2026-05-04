//! Kernel and initrd extraction from a rootfs /boot/ directory.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::squashfs::sha256_file;

/// Extract the kernel (vmlinuz) from a rootfs.
///
/// Looks for `/boot/vmlinuz-*` in the rootfs directory.
/// Copies it to `output_dir/{name}.vmlinuz` and returns (path, sha256).
pub fn extract_kernel(rootfs: &Path, output_dir: &Path, name: &str) -> Result<(PathBuf, String)> {
    let boot_dir = rootfs.join("boot");
    let vmlinuz =
        find_single_glob(&boot_dir, "vmlinuz-*").context("looking for vmlinuz in rootfs /boot/")?;

    let output_path = output_dir.join(format!("{name}.vmlinuz"));
    std::fs::copy(&vmlinuz, &output_path)
        .with_context(|| format!("copying {} to {}", vmlinuz.display(), output_path.display()))?;

    let hash = sha256_file(&output_path)?;
    Ok((output_path, hash))
}

/// Extract the base initrd from a rootfs.
///
/// Looks for the conventional initrd filename in `/boot/`, trying:
///   - `initrd.img-*`     (Debian / Ubuntu)
///   - `initramfs-*.img`  (Fedora / RHEL / SUSE)
///   - `initramfs-linux*.img` (Arch / Alpine variants)
///
/// Copies it to `output_dir/{name}.initrd.base` and returns (path, sha256).
pub fn extract_base_initrd(
    rootfs: &Path,
    output_dir: &Path,
    name: &str,
) -> Result<(PathBuf, String)> {
    let boot_dir = rootfs.join("boot");
    const PATTERNS: &[&str] = &["initrd.img-*", "initramfs-*.img", "initramfs-linux*.img"];
    let initrd = PATTERNS
        .iter()
        .find_map(|p| find_single_glob(&boot_dir, p).ok())
        .with_context(|| {
            format!(
                "no initrd in {} matching any of {:?}",
                boot_dir.display(),
                PATTERNS
            )
        })?;

    let output_path = output_dir.join(format!("{name}.initrd.base"));
    std::fs::copy(&initrd, &output_path)
        .with_context(|| format!("copying {} to {}", initrd.display(), output_path.display()))?;

    let hash = sha256_file(&output_path)?;
    Ok((output_path, hash))
}

/// Find a single file matching a glob pattern in a directory.
fn find_single_glob(dir: &Path, pattern: &str) -> Result<PathBuf> {
    if !dir.exists() {
        anyhow::bail!("{} does not exist", dir.display());
    }

    let mut matches = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if glob_match(pattern, &name_str) {
            matches.push(entry.path());
        }
    }

    match matches.len() {
        0 => anyhow::bail!("no files matching '{}' in {}", pattern, dir.display()),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => {
            // Multiple matches — pick the latest by name (highest kernel version)
            matches.sort();
            tracing::warn!(
                "found {} files matching '{}', using {}",
                n,
                pattern,
                matches.last().unwrap().display()
            );
            Ok(matches.into_iter().last().unwrap())
        }
    }
}

/// Simple glob matching: only supports `*` as wildcard prefix/suffix.
fn glob_match(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix)
    } else {
        pattern == name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_kernel_from_fake_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        let boot = rootfs.join("boot");
        std::fs::create_dir_all(&boot).unwrap();
        std::fs::write(boot.join("vmlinuz-6.8.0-100-generic"), b"fake kernel").unwrap();
        std::fs::write(boot.join("initrd.img-6.8.0-100-generic"), b"fake initrd").unwrap();

        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();

        let (path, hash) = extract_kernel(&rootfs, &output, "test").unwrap();
        assert!(path.exists());
        assert_eq!(hash.len(), 64);
        assert!(path.to_string_lossy().ends_with("test.vmlinuz"));

        let (ipath, ihash) = extract_base_initrd(&rootfs, &output, "test").unwrap();
        assert!(ipath.exists());
        assert_eq!(ihash.len(), 64);
    }

    #[test]
    fn glob_match_works() {
        assert!(glob_match("vmlinuz-*", "vmlinuz-6.8.0-100-generic"));
        assert!(!glob_match("vmlinuz-*", "initrd.img-6.8.0"));
        assert!(glob_match("*.img", "test.img"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
    }
}
