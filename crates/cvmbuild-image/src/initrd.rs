//! Initrd packaging — copy the dracut-produced initrd to the output dir.
//!
//! Historically cvmbuild built a CPIO overlay with verity activation
//! scripts and prepended it to the initramfs-tools-produced base initrd.
//! That CPIO was then byte-rewritten to zero non-deterministic fields
//! (inode numbers, mtimes) because initramfs-tools doesn't support
//! reproducible builds.
//!
//! As of cvm-base's switch to dracut (with `--reproducible`) and
//! cvmbuild's `stage_dracut_modules` (which ships the verity-cvm dracut
//! module from Rust assets), the initrd dracut emits at base-image build
//! time is already deterministic and already contains our verity
//! activation. There's nothing left to overlay or rewrite — we just copy
//! the file and hash it.
//!
//! See `crates/cvmbuild-cli/assets/dracut/` for the module source.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::squashfs::sha256_file;

/// Copy the dracut-produced base initrd to the output path and return its sha256.
pub fn build_initrd(
    base_initrd: &Path,
    output_path: &Path,
    _config: &cvmbuild_config::Config,
) -> Result<(PathBuf, String)> {
    std::fs::copy(base_initrd, output_path)
        .with_context(|| format!("copying {} → {}", base_initrd.display(), output_path.display()))?;
    let hash = sha256_file(output_path)?;
    Ok((output_path.to_path_buf(), hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> cvmbuild_config::Config {
        cvmbuild_config::Config::parse(
            r#"
[image]
id = "test"
version = "0.1.0"
base = "test:latest"
[kernel]
cmdline = "root=/dev/mapper/root lockdown=confidentiality iommu=pt"
initrd_modules = ["dm-verity", "dm-mod"]
[verity]
enabled = true
panic_on_corruption = true
[security]
remove = ["bash", "sh", "dash", "apt", "dpkg", "pip", "dmsetup"]
lock_modules = true
[firewall]
inbound = [{ port = 8443, proto = "tcp" }]
outbound = "deny"
[[verity_disks]]
name = "models"
device = "vdb"
mountpoint = "/mnt/models"
description = "model weights disk"
"#,
        )
        .unwrap()
    }

    #[test]
    fn build_initrd_copies_input_byte_for_byte() {
        let tmp = tempfile::tempdir().unwrap();
        let base_path = tmp.path().join("base.initrd");
        let body = b"\x07\x07\x01\x00\x00\x00FAKE_DRACUT_INITRD_DATA";
        std::fs::write(&base_path, body).unwrap();

        let output_path = tmp.path().join("final.initrd");
        let (path, hash) = build_initrd(&base_path, &output_path, &test_config()).unwrap();

        assert!(path.exists());
        assert_eq!(hash.len(), 64);
        assert_eq!(std::fs::read(&path).unwrap(), body);
    }
}
