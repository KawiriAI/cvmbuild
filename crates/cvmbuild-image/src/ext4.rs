//! ext4 filesystem creation + dm-verity disk assembly.
//!
//! Creates ext4 filesystems from directories using `mke2fs` (from e2fsprogs),
//! then appends an inline dm-verity hash tree using our pure Rust verity
//! implementation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::squashfs::sha256_file;
use crate::verity;

/// Result of creating a verity-protected ext4 disk.
pub struct VerityDiskResult {
    pub image_path: PathBuf,
    pub roothash: String,
    pub hashoffset: u64,
    pub image_hash: String,
}

/// Create an ext4 image with inline dm-verity hash tree.
///
/// Pipeline: mke2fs → pure-Rust verity computation → append hash tree.
/// The hash tree is appended directly after the ext4 data (inline layout),
/// matching `veritysetup format` + manual append.
pub fn create_verity_disk(
    source_dir: &Path,
    output_path: &Path,
    label: &str,
    fs_uuid: &str,
) -> Result<VerityDiskResult> {
    // Step 1: Create ext4 image
    let data_size = create_ext4(source_dir, output_path, label, fs_uuid)?;
    tracing::info!(
        "ext4 data: {} bytes ({:.2} MiB)",
        data_size,
        data_size as f64 / (1024.0 * 1024.0)
    );

    // Step 2: Compute verity hash tree (no superblock, empty salt for reproducibility)
    let hash_path = output_path.with_extension("hashtree");
    let salt = &[]; // empty salt, matches kcvmx --salt=-
    let roothash = verity::create_verity_no_superblock(output_path, &hash_path, salt)?;
    tracing::info!("roothash: {}", roothash);

    // Step 3: Append hash tree after ext4 data (inline layout)
    let hash_data =
        std::fs::read(&hash_path).with_context(|| format!("reading {}", hash_path.display()))?;
    tracing::info!(
        "hash tree: {} bytes, hashoffset: {}",
        hash_data.len(),
        data_size
    );

    // Append hash tree
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(output_path)
            .with_context(|| format!("opening {} for append", output_path.display()))?;
        file.write_all(&hash_data)?;
    }

    // Clean up separate hash tree file
    let _ = std::fs::remove_file(&hash_path);

    let image_hash = sha256_file(output_path)?;

    Ok(VerityDiskResult {
        image_path: output_path.to_path_buf(),
        roothash,
        hashoffset: data_size,
        image_hash,
    })
}

/// Create an ext4 filesystem image from a source directory.
///
/// Shells out to `mke2fs -d` which populates from a directory without root.
/// Returns the image size in bytes.
fn create_ext4(source_dir: &Path, output_path: &Path, label: &str, fs_uuid: &str) -> Result<u64> {
    let source_size = dir_size(source_dir)?;
    // 10% overhead + 64 MiB minimum for ext4 metadata
    let image_size = std::cmp::max(source_size + source_size / 10, 64 * 1024 * 1024);
    // Round up to 4K block boundary
    let image_size = image_size.div_ceil(4096) * 4096;
    let blocks = image_size / 4096;

    tracing::info!(
        "mke2fs: source={} bytes, image={} bytes ({} blocks)",
        source_size,
        image_size,
        blocks
    );

    let output = std::process::Command::new("mke2fs")
        .args([
            "-t",
            "ext4",
            "-d",
            &source_dir.to_string_lossy(),
            "-b",
            "4096",
            "-L",
            label,
            "-U",
            fs_uuid,
            "-E",
            &format!("hash_seed={fs_uuid}"),
            "-T",
            "default",
            &output_path.to_string_lossy(),
            &blocks.to_string(),
        ])
        .env("SOURCE_DATE_EPOCH", "0")
        .output()
        .context("failed to run mke2fs — is e2fsprogs installed?")?;

    if !output.status.success() {
        anyhow::bail!(
            "mke2fs failed (exit {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // mke2fs does NOT truncate pre-existing files — if the output file already
    // exists from a previous build (with an appended hash tree), the file will
    // be larger than image_size. Truncate to the exact size so that the verity
    // computation only covers the actual ext4 data.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(output_path)
        .with_context(|| {
            format!(
                "opening {} for truncate after mke2fs",
                output_path.display()
            )
        })?;
    file.set_len(image_size)?;

    Ok(image_size)
}

/// Calculate total size of a directory's contents in bytes.
fn dir_size(path: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in walkdir(path)? {
        let meta = std::fs::symlink_metadata(&entry)?;
        if meta.is_file() {
            total += meta.len();
        }
    }
    Ok(total)
}

/// Simple recursive directory walker.
fn walkdir(path: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    walkdir_inner(path, &mut files)?;
    Ok(files)
}

fn walkdir_inner(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let entry = entry?;
        let ftype = entry.file_type()?;
        if ftype.is_dir() {
            walkdir_inner(&entry.path(), files)?;
        } else {
            files.push(entry.path());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_mke2fs() -> bool {
        std::process::Command::new("mke2fs")
            .arg("-V")
            .output()
            .is_ok()
    }

    #[test]
    fn dir_size_works() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a"), vec![0u8; 1024]).unwrap();
        std::fs::write(tmp.path().join("b"), vec![0u8; 2048]).unwrap();
        let size = dir_size(tmp.path()).unwrap();
        assert_eq!(size, 3072);
    }

    #[test]
    fn create_verity_disk_end_to_end() {
        if !has_mke2fs() {
            eprintln!("mke2fs not found, skipping");
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("data");
        std::fs::create_dir_all(source.join("subdir")).unwrap();
        std::fs::write(source.join("hello.txt"), "Hello, verity!").unwrap();
        std::fs::write(source.join("subdir/nested.txt"), "Nested file").unwrap();

        let output = tmp.path().join("test.img");
        let result = create_verity_disk(
            &source,
            &output,
            "test",
            "cb9faa28-968e-4601-a47e-f1dc67ebaddc",
        )
        .unwrap();

        assert!(result.image_path.exists());
        assert_eq!(result.roothash.len(), 64);
        assert!(result.hashoffset > 0);
        assert_eq!(result.image_hash.len(), 64);

        // Image should be larger than hashoffset (data + hash tree)
        let image_size = std::fs::metadata(&result.image_path).unwrap().len();
        assert!(image_size > result.hashoffset);
    }

    #[test]
    fn create_verity_disk_reproducible() {
        if !has_mke2fs() {
            eprintln!("mke2fs not found, skipping");
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("data");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("test.txt"), "reproducible content").unwrap();

        let uuid = "cb9faa28-968e-4601-a47e-f1dc67ebaddc";

        // Two separate ext4 images, then compare roothashes
        let ext4_a = tmp.path().join("a.ext4");
        let ext4_b = tmp.path().join("b.ext4");

        let size_a = create_ext4(&source, &ext4_a, "repro", uuid).unwrap();
        let size_b = create_ext4(&source, &ext4_b, "repro", uuid).unwrap();

        assert_eq!(size_a, size_b, "image sizes must match");

        let data_a = std::fs::read(&ext4_a).unwrap();
        let data_b = std::fs::read(&ext4_b).unwrap();
        assert_eq!(data_a, data_b, "ext4 images must be bit-identical");
    }
}
