use std::path::{Path, PathBuf};

use anyhow::Result;
use cvmbuild_config::Config;

pub mod ext4;
pub mod gpt;
pub mod initrd;
pub mod kernel;
pub mod manifest;
pub mod squashfs;
pub mod verity;

/// Seal a rootfs into a final CVM disk image.
pub struct ImageSealer {
    output_dir: PathBuf,
}

/// Result of sealing an image.
pub struct SealResult {
    /// Path to the final GPT disk image.
    pub image_path: PathBuf,
    /// dm-verity root hash of the squashfs partition.
    pub roothash: String,
    /// SHA256 of the squashfs data.
    pub squashfs_hash: String,
    /// SHA256 of the final image.
    pub image_hash: String,
    /// Kernel path and hash (if extracted).
    pub kernel: Option<(PathBuf, String)>,
    /// Initrd path and hash (if built).
    pub initrd: Option<(PathBuf, String)>,
}

impl ImageSealer {
    pub fn new(output_dir: &Path) -> Self {
        Self {
            output_dir: output_dir.to_path_buf(),
        }
    }

    /// Seal a rootfs directory into a CVM disk image with all artifacts.
    ///
    /// Pipeline: rootfs → squashfs → verity → GPT + kernel + initrd + manifest
    pub fn seal(&self, rootfs: &Path, config: &Config) -> Result<SealResult> {
        std::fs::create_dir_all(&self.output_dir)?;

        let name = format!("{}_{}", config.image.id, config.image.version);

        // Step 1: Extract kernel from rootfs /boot/
        tracing::info!("Extracting kernel");
        let kernel_result = kernel::extract_kernel(rootfs, &self.output_dir, &name);
        let kernel = match kernel_result {
            Ok(k) => {
                tracing::info!("kernel: {} ({})", k.1, k.0.display());
                Some(k)
            }
            Err(e) => {
                tracing::warn!("No kernel found: {e:#} — skipping");
                None
            }
        };

        // Step 2: Extract base initrd, then remove from rootfs for reproducibility.
        // The initrd CPIO is non-deterministic across Docker builds (metadata varies),
        // so we exclude it from the squashfs to ensure identical roothash.
        let base_initrd = kernel::extract_base_initrd(rootfs, &self.output_dir, &name);
        if base_initrd.is_ok() {
            let boot_dir = rootfs.join("boot");
            for entry in std::fs::read_dir(&boot_dir)? {
                let entry = entry?;
                let name = entry.file_name();
                if name.to_string_lossy().starts_with("initrd.img") {
                    std::fs::remove_file(entry.path())?;
                }
            }
            tracing::info!("Removed initrd from rootfs for reproducible squashfs");
        }

        // Step 3: Create squashfs from rootfs
        tracing::info!("Creating squashfs from rootfs");
        let squashfs_path = self.output_dir.join("root.squashfs");
        let squashfs_hash = squashfs::create_squashfs(rootfs, &squashfs_path)?;
        tracing::info!("squashfs: {}", squashfs_hash);

        // Step 4: Create dm-verity hash tree
        tracing::info!("Computing dm-verity hash tree");
        let verity_path = self.output_dir.join("root.verity");
        let roothash = verity::create_verity(&squashfs_path, &verity_path)?;
        tracing::info!("roothash: {}", roothash);

        // Write roothash file
        let roothash_path = self.output_dir.join(format!("{name}.roothash"));
        std::fs::write(&roothash_path, &roothash)?;

        // Step 5: Assemble GPT image
        tracing::info!("Assembling GPT disk image");
        let image_path = self.output_dir.join(format!("{name}.raw"));
        let image_hash = gpt::assemble_gpt(&squashfs_path, &verity_path, &image_path)?;
        tracing::info!("image: {}", image_hash);

        // Step 6: Build initrd with verity overlay
        let initrd_result = if let Ok((base_path, _)) = base_initrd {
            let initrd_path = self.output_dir.join(format!("{name}.initrd"));
            tracing::info!("Building initrd with verity overlay");
            match initrd::build_initrd(&base_path, &initrd_path, config) {
                Ok(r) => {
                    tracing::info!("initrd: {} ({})", r.1, r.0.display());
                    // Clean up base initrd
                    let _ = std::fs::remove_file(&base_path);
                    Some(r)
                }
                Err(e) => {
                    tracing::warn!("Failed to build initrd: {e:#}");
                    None
                }
            }
        } else {
            tracing::warn!("No base initrd found — skipping initrd build");
            None
        };

        Ok(SealResult {
            image_path,
            roothash,
            squashfs_hash,
            image_hash,
            kernel,
            initrd: initrd_result,
        })
    }

    /// Seal without config (legacy compatibility — no kernel/initrd/manifest).
    pub fn seal_rootfs_only(&self, rootfs: &Path) -> Result<SealResult> {
        std::fs::create_dir_all(&self.output_dir)?;

        let squashfs_path = self.output_dir.join("root.squashfs");
        let squashfs_hash = squashfs::create_squashfs(rootfs, &squashfs_path)?;

        let verity_path = self.output_dir.join("root.verity");
        let roothash = verity::create_verity(&squashfs_path, &verity_path)?;

        let image_path = self.output_dir.join("image.raw");
        let image_hash = gpt::assemble_gpt(&squashfs_path, &verity_path, &image_path)?;

        Ok(SealResult {
            image_path,
            roothash,
            squashfs_hash,
            image_hash,
            kernel: None,
            initrd: None,
        })
    }
}
