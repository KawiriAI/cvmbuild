use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Create a squashfs image from a directory using cvmbuild-squashfs (pure Rust).
///
/// Uses zstd compression and deterministic settings (mod_time=0, uid/gid=0).
/// Handles regular files, directories, symlinks, and hard links.
/// Returns the SHA256 hash of the resulting squashfs file.
pub fn create_squashfs(rootfs: &Path, output: &Path) -> Result<String> {
    cvmbuild_squashfs::create_squashfs(rootfs, output)
}

/// Compute SHA256 hash of a file.
pub fn sha256_file(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_file_works() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello world").unwrap();
        let hash = sha256_file(tmp.path()).unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn create_squashfs_from_dir() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let rootfs = tmp_dir.path().join("rootfs");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::write(rootfs.join("etc/hostname"), "test-cvm\n").unwrap();
        fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        fs::write(rootfs.join("usr/bin/hello"), "#!/bin/sh\necho hello\n").unwrap();

        let output = tmp_dir.path().join("test.squashfs");
        let hash = create_squashfs(&rootfs, &output).unwrap();

        // Output file should exist and be non-empty
        assert!(output.exists());
        assert!(output.metadata().unwrap().len() > 0);
        // Hash should be 64 hex chars
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn squashfs_with_hardlinks() {
        use cvmbuild_squashfs::reader::SquashfsReader;

        let tmp_dir = tempfile::tempdir().unwrap();
        let rootfs = tmp_dir.path().join("rootfs");

        // Create a rootfs with hard links
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        fs::write(rootfs.join("etc/hostname"), "test-cvm\n").unwrap();
        fs::write(rootfs.join("etc/hosts"), "127.0.0.1 localhost\n").unwrap();
        fs::write(rootfs.join("usr/bin/hello"), "#!/bin/sh\necho hello\n").unwrap();
        // Create a hard link
        fs::hard_link(
            rootfs.join("usr/bin/hello"),
            rootfs.join("usr/bin/hello-link"),
        )
        .unwrap();
        // More files after hard link
        fs::write(rootfs.join("etc/world"), "world\n").unwrap();

        let output = tmp_dir.path().join("test.squashfs");
        let _hash = create_squashfs(&rootfs, &output).unwrap();

        // Read it back with cvmbuild-squashfs reader
        let reader = SquashfsReader::open(&output).unwrap();
        let file_count = reader.verify().unwrap();
        eprintln!("verified {} files", file_count);
        assert!(
            file_count >= 4,
            "expected at least 4 files, got {}",
            file_count
        );

        // Verify hard links share the same inode
        let mut inode_map: std::collections::HashMap<u32, Vec<String>> =
            std::collections::HashMap::new();
        reader
            .walk(|path, inode| {
                if let cvmbuild_squashfs::reader::Inode::File(f) = inode {
                    inode_map
                        .entry(f.inode_number)
                        .or_default()
                        .push(path.to_string());
                }
                Ok(())
            })
            .unwrap();
        let shared = inode_map.values().filter(|v| v.len() > 1).count();
        eprintln!("inodes shared by multiple files: {}", shared);
        assert!(shared >= 1, "expected at least 1 shared inode (hard link)");
    }

    #[test]
    fn squashfs_is_reproducible() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let rootfs = tmp_dir.path().join("rootfs");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::write(rootfs.join("etc/hostname"), "reproducible\n").unwrap();

        let out1 = tmp_dir.path().join("first.squashfs");
        let out2 = tmp_dir.path().join("second.squashfs");

        let hash1 = create_squashfs(&rootfs, &out1).unwrap();
        let hash2 = create_squashfs(&rootfs, &out2).unwrap();

        assert_eq!(hash1, hash2, "squashfs builds should be reproducible");
    }

    #[test]
    fn squashfs_many_files_metadata_blocks() {
        use cvmbuild_squashfs::reader::SquashfsReader;

        let tmp_dir = tempfile::tempdir().unwrap();
        let rootfs = tmp_dir.path().join("rootfs");

        for dir_idx in 0..50 {
            let dir = rootfs.join(format!("dir{:03}", dir_idx));
            fs::create_dir_all(&dir).unwrap();
            for file_idx in 0..100 {
                let content = format!("content of dir{:03}/file{:04}\n", dir_idx, file_idx);
                fs::write(dir.join(format!("file{:04}", file_idx)), content).unwrap();
            }
            // Add some symlinks
            for link_idx in 0..5 {
                let target = format!("file{:04}", link_idx);
                let link_name = format!("link{:04}", link_idx);
                std::os::unix::fs::symlink(&target, dir.join(link_name)).unwrap();
            }
            // Add nested dirs
            let nested = dir.join("nested");
            fs::create_dir_all(&nested).unwrap();
            fs::write(nested.join("deep_file"), "deep content\n").unwrap();
        }
        // Add some empty files too
        let empty_dir = rootfs.join("empty_files");
        fs::create_dir_all(&empty_dir).unwrap();
        for i in 0..50 {
            fs::write(empty_dir.join(format!("empty{:03}", i)), "").unwrap();
        }

        let output = tmp_dir.path().join("many_files.squashfs");
        let _hash = create_squashfs(&rootfs, &output).unwrap();

        // Verify the image is readable
        let reader = SquashfsReader::open(&output).unwrap();
        let file_count = reader.verify().unwrap();
        assert!(
            file_count >= 5000,
            "expected >= 5000 files, got {}",
            file_count
        );
        eprintln!("squashfs_many_files: {} files verified", file_count);
    }
}
