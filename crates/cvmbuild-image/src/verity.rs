//! Pure Rust dm-verity hash tree computation.
//!
//! Implements the Linux kernel dm-verity version 1 algorithm:
//! - Hash each 4096-byte data block: SHA256(salt || block)
//! - Pack hashes into 4096-byte hash blocks (128 hashes per block)
//! - Repeat upward until one hash block remains
//! - Root hash = SHA256(salt || final_hash_block)
//!
//! Reference: https://docs.kernel.org/admin-guide/device-mapper/verity.html

use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

const BLOCK_SIZE: usize = 4096;
const DIGEST_SIZE: usize = 32; // SHA-256
/// Number of SHA-256 hashes that fit in one 4K block.
pub const HASHES_PER_BLOCK: usize = BLOCK_SIZE / DIGEST_SIZE; // 128

/// dm-verity superblock (512 bytes, written at start of hash device).
#[repr(C, packed)]
struct VeritySuperblock {
    signature: [u8; 8],   // "verity\0\0"
    version: u32,         // 1
    hash_type: u32,       // 1 = normal
    uuid: [u8; 16],       // hash device UUID
    algorithm: [u8; 32],  // "sha256\0..."
    data_block_size: u32, // 4096
    hash_block_size: u32, // 4096
    data_blocks: u64,     // count of data blocks
    salt_size: u16,       // salt length in bytes
    _pad1: [u8; 6],
    salt: [u8; 256], // salt value (zero-padded)
    _pad2: [u8; 168],
}

impl VeritySuperblock {
    fn new(data_blocks: u64, salt: &[u8]) -> Self {
        let mut sb = Self {
            signature: *b"verity\0\0",
            version: 1u32.to_le(),
            hash_type: 1u32.to_le(),
            uuid: [0u8; 16],
            algorithm: [0u8; 32],
            data_block_size: (BLOCK_SIZE as u32).to_le(),
            hash_block_size: (BLOCK_SIZE as u32).to_le(),
            data_blocks: data_blocks.to_le(),
            salt_size: (salt.len() as u16).to_le(),
            _pad1: [0u8; 6],
            salt: [0u8; 256],
            _pad2: [0u8; 168],
        };
        sb.algorithm[..6].copy_from_slice(b"sha256");
        sb.salt[..salt.len()].copy_from_slice(salt);
        sb
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

/// Create a dm-verity hash tree for a data file. Pure Rust implementation.
///
/// Writes the hash tree (with superblock) to `hash_path`.
/// Returns the root hash as a hex string.
pub fn create_verity(data_path: &Path, hash_path: &Path) -> Result<String> {
    create_verity_with_salt(data_path, hash_path, &[])
}

/// Create a dm-verity hash tree with a specific salt.
pub fn create_verity_with_salt(data_path: &Path, hash_path: &Path, salt: &[u8]) -> Result<String> {
    create_verity_impl(data_path, hash_path, salt, true)
}

/// Create a dm-verity hash tree without a superblock (matches `veritysetup --no-superblock`).
pub fn create_verity_no_superblock(
    data_path: &Path,
    hash_path: &Path,
    salt: &[u8],
) -> Result<String> {
    create_verity_impl(data_path, hash_path, salt, false)
}

fn create_verity_impl(
    data_path: &Path,
    hash_path: &Path,
    salt: &[u8],
    write_superblock: bool,
) -> Result<String> {
    let data =
        std::fs::read(data_path).with_context(|| format!("reading {}", data_path.display()))?;

    let (root_hash, hash_tree) = compute_verity_tree(&data, salt)?;

    let mut output = Vec::new();

    if write_superblock {
        let num_data_blocks = data.len().div_ceil(BLOCK_SIZE) as u64;
        let superblock = VeritySuperblock::new(num_data_blocks, salt);
        let mut sb_block = [0u8; BLOCK_SIZE];
        sb_block[..512].copy_from_slice(superblock.as_bytes());
        output.extend_from_slice(&sb_block);
    }

    output.extend_from_slice(&hash_tree);

    std::fs::write(hash_path, &output)
        .with_context(|| format!("writing {}", hash_path.display()))?;

    Ok(hex::encode(&root_hash))
}

/// Compute the dm-verity Merkle tree from data bytes.
///
/// Returns (root_hash, hash_tree_bytes).
/// Hash tree is ordered root-first (level N, then N-1, ... then level 0).
fn compute_verity_tree(data: &[u8], salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let num_data_blocks = data.len().div_ceil(BLOCK_SIZE);

    if num_data_blocks == 0 {
        anyhow::bail!("data is empty");
    }

    // Level 0: hash each data block
    let mut level_hashes: Vec<Vec<u8>> = Vec::new();
    let mut current_hashes = Vec::with_capacity(num_data_blocks * DIGEST_SIZE);

    for i in 0..num_data_blocks {
        let start = i * BLOCK_SIZE;
        let end = std::cmp::min(start + BLOCK_SIZE, data.len());
        let mut block = [0u8; BLOCK_SIZE];
        block[..end - start].copy_from_slice(&data[start..end]);

        let hash = verity_hash(salt, &block);
        current_hashes.extend_from_slice(&hash);
    }

    // Pack into hash blocks (zero-pad the last one)
    level_hashes.push(pack_into_blocks(&current_hashes));

    // Build upper levels until we have a single hash block
    while current_hashes.len() > DIGEST_SIZE {
        let num_blocks_at_level = current_hashes.len().div_ceil(BLOCK_SIZE);
        let mut next_hashes = Vec::with_capacity(num_blocks_at_level * DIGEST_SIZE);

        for i in 0..num_blocks_at_level {
            let start = i * BLOCK_SIZE;
            let end = std::cmp::min(start + BLOCK_SIZE, current_hashes.len());
            let mut block = [0u8; BLOCK_SIZE];
            block[..end - start].copy_from_slice(&current_hashes[start..end]);

            let hash = verity_hash(salt, &block);
            next_hashes.extend_from_slice(&hash);
        }

        current_hashes = next_hashes;

        if current_hashes.len() > DIGEST_SIZE {
            level_hashes.push(pack_into_blocks(&current_hashes));
        }
    }

    // Root hash is the single remaining hash
    let root_hash = current_hashes;

    // Build the on-disk hash tree: root level first, then down to leaf level
    let mut hash_tree = Vec::new();

    // The root hash block (pack root hash into a full block, hash it)
    // Actually: the hash tree stores levels from root down.
    // The root hash itself is NOT in the tree — it's the output.
    // Level ordering on disk: highest level first (fewest blocks), leaf level last.
    for level in level_hashes.iter().rev() {
        hash_tree.extend_from_slice(level);
    }

    Ok((root_hash, hash_tree))
}

/// Compute dm-verity version 1 hash: SHA256(salt || data).
fn verity_hash(salt: &[u8], data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; DIGEST_SIZE];
    hash.copy_from_slice(&result);
    hash
}

/// Pack raw hash bytes into 4096-byte blocks (zero-padding the last one).
fn pack_into_blocks(hashes: &[u8]) -> Vec<u8> {
    let num_blocks = hashes.len().div_ceil(BLOCK_SIZE);
    let mut packed = vec![0u8; num_blocks * BLOCK_SIZE];
    packed[..hashes.len()].copy_from_slice(hashes);
    packed
}

/// Simple hex encoding (to avoid adding a dependency).
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verity_hash_is_deterministic() {
        let salt = [0u8; 32];
        let data = [0u8; BLOCK_SIZE];
        let h1 = verity_hash(&salt, &data);
        let h2 = verity_hash(&salt, &data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn verity_hash_differs_with_different_data() {
        let salt = [0u8; 32];
        let d1 = [0u8; BLOCK_SIZE];
        let mut d2 = [0u8; BLOCK_SIZE];
        d2[0] = 1;
        assert_ne!(verity_hash(&salt, &d1), verity_hash(&salt, &d2));
    }

    #[test]
    fn pack_into_blocks_pads_correctly() {
        // 33 bytes → 1 block of 4096 bytes
        let data = vec![0xAB; 33];
        let packed = pack_into_blocks(&data);
        assert_eq!(packed.len(), BLOCK_SIZE);
        assert_eq!(packed[32], 0xAB);
        assert_eq!(packed[33], 0x00);
    }

    #[test]
    fn compute_tree_single_block() {
        // Single 4K block → root hash with no intermediate levels
        let data = vec![0u8; BLOCK_SIZE];
        let salt = [0u8; 32];
        let (root_hash, _tree) = compute_verity_tree(&data, &salt).unwrap();
        assert_eq!(root_hash.len(), DIGEST_SIZE);
    }

    #[test]
    fn compute_tree_multiple_blocks() {
        // 256 blocks (1 MiB) → should produce a multi-level tree
        let data = vec![0u8; 256 * BLOCK_SIZE];
        let salt = [0u8; 32];
        let (root_hash, tree) = compute_verity_tree(&data, &salt).unwrap();
        assert_eq!(root_hash.len(), DIGEST_SIZE);
        // Tree should have level 0 (256 hashes = 2 blocks) + root
        assert!(tree.len() >= 2 * BLOCK_SIZE);
    }

    #[test]
    fn create_verity_writes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let data_path = tmp.path().join("data.img");
        let hash_path = tmp.path().join("hash.img");

        // Create a small data image (128 KiB = 32 blocks)
        let data = vec![0x42u8; 32 * BLOCK_SIZE];
        std::fs::write(&data_path, &data).unwrap();

        let root_hash = create_verity(&data_path, &hash_path).unwrap();

        // Root hash should be 64 hex chars (32 bytes)
        assert_eq!(root_hash.len(), 64);
        // Hash file should exist and contain superblock + tree
        assert!(hash_path.exists());
        let hash_data = std::fs::read(&hash_path).unwrap();
        // At minimum: 1 block for superblock + 1 block for leaf hashes
        assert!(hash_data.len() >= 2 * BLOCK_SIZE);
        // Superblock signature
        assert_eq!(&hash_data[..6], b"verity");
    }

    #[test]
    fn verity_is_reproducible() {
        let tmp = tempfile::tempdir().unwrap();
        let data_path = tmp.path().join("data.img");
        let hash1_path = tmp.path().join("hash1.img");
        let hash2_path = tmp.path().join("hash2.img");

        let data = vec![0x55u8; 64 * BLOCK_SIZE];
        std::fs::write(&data_path, &data).unwrap();

        let h1 = create_verity(&data_path, &hash1_path).unwrap();
        let h2 = create_verity(&data_path, &hash2_path).unwrap();

        assert_eq!(h1, h2, "verity should be reproducible");
    }

    /// Compare our implementation against `veritysetup format --no-superblock`.
    /// Skipped if veritysetup is not installed.
    #[test]
    fn matches_veritysetup() {
        // Check if veritysetup is available
        if std::process::Command::new("veritysetup")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("veritysetup not found, skipping integration test");
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let data_path = tmp.path().join("data.img");
        let our_hash_path = tmp.path().join("our_hash.img");
        let their_hash_path = tmp.path().join("their_hash.img");

        // Create deterministic test data (256 blocks = 1 MiB)
        let data = vec![0xAAu8; 256 * BLOCK_SIZE];
        std::fs::write(&data_path, &data).unwrap();

        let salt_hex = "0".repeat(64); // 32 zero bytes
        let salt = [0u8; 32];

        // Run veritysetup
        let output = std::process::Command::new("veritysetup")
            .args([
                "format",
                "--no-superblock",
                &format!("--salt={salt_hex}"),
                &data_path.to_string_lossy(),
                &their_hash_path.to_string_lossy(),
            ])
            .output()
            .expect("failed to run veritysetup");

        assert!(
            output.status.success(),
            "veritysetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Parse root hash from veritysetup output
        let stdout = String::from_utf8_lossy(&output.stdout);
        let their_root_hash = stdout
            .lines()
            .find(|l| l.starts_with("Root hash:"))
            .and_then(|l| l.strip_prefix("Root hash:"))
            .map(|h| h.trim().to_string())
            .expect("could not parse root hash from veritysetup");

        // Run our implementation
        let our_root_hash = create_verity_no_superblock(&data_path, &our_hash_path, &salt).unwrap();

        // Compare root hashes
        assert_eq!(
            our_root_hash, their_root_hash,
            "root hash mismatch!\n  ours:   {our_root_hash}\n  theirs: {their_root_hash}"
        );

        // Compare hash tree files byte-for-byte
        let our_bytes = std::fs::read(&our_hash_path).unwrap();
        let their_bytes = std::fs::read(&their_hash_path).unwrap();
        assert_eq!(
            our_bytes.len(),
            their_bytes.len(),
            "hash tree size mismatch: ours={} theirs={}",
            our_bytes.len(),
            their_bytes.len()
        );
        assert_eq!(our_bytes, their_bytes, "hash tree content differs");
    }

    /// Compare against veritysetup with empty salt (--salt=-), which is what
    /// production uses. This is the configuration that caused dm-verity corruption.
    #[test]
    fn matches_veritysetup_empty_salt() {
        if std::process::Command::new("veritysetup")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("veritysetup not found, skipping integration test");
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let data_path = tmp.path().join("data.img");
        let our_hash_path = tmp.path().join("our_hash.img");
        let their_hash_path = tmp.path().join("their_hash.img");

        // Create deterministic test data (256 blocks = 1 MiB)
        let data = vec![0xAAu8; 256 * BLOCK_SIZE];
        std::fs::write(&data_path, &data).unwrap();

        // Run veritysetup with empty salt
        let output = std::process::Command::new("veritysetup")
            .args([
                "format",
                "--no-superblock",
                "--salt=-",
                &data_path.to_string_lossy(),
                &their_hash_path.to_string_lossy(),
            ])
            .output()
            .expect("failed to run veritysetup");

        assert!(
            output.status.success(),
            "veritysetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let their_root_hash = stdout
            .lines()
            .find(|l| l.starts_with("Root hash:"))
            .and_then(|l| l.strip_prefix("Root hash:"))
            .map(|h| h.trim().to_string())
            .expect("could not parse root hash from veritysetup");

        // Our implementation with empty salt
        let our_root_hash = create_verity_no_superblock(&data_path, &our_hash_path, &[]).unwrap();

        // Compare root hashes
        assert_eq!(
            our_root_hash, their_root_hash,
            "root hash mismatch (empty salt)!\n  ours:   {our_root_hash}\n  theirs: {their_root_hash}"
        );

        // Compare hash tree files byte-for-byte
        let our_bytes = std::fs::read(&our_hash_path).unwrap();
        let their_bytes = std::fs::read(&their_hash_path).unwrap();
        assert_eq!(
            our_bytes.len(),
            their_bytes.len(),
            "hash tree size mismatch (empty salt): ours={} theirs={}",
            our_bytes.len(),
            their_bytes.len()
        );
        assert_eq!(
            our_bytes, their_bytes,
            "hash tree content differs (empty salt)"
        );
    }

    /// Test with larger data (16384 blocks = 64 MiB) matching config disk size.
    #[test]
    fn matches_veritysetup_large_empty_salt() {
        if std::process::Command::new("veritysetup")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("veritysetup not found, skipping integration test");
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let data_path = tmp.path().join("data.img");
        let our_hash_path = tmp.path().join("our_hash.img");
        let their_hash_path = tmp.path().join("their_hash.img");

        // Create deterministic test data (16384 blocks = 64 MiB)
        let data = vec![0x42u8; 16384 * BLOCK_SIZE];
        std::fs::write(&data_path, &data).unwrap();

        let output = std::process::Command::new("veritysetup")
            .args([
                "format",
                "--no-superblock",
                "--salt=-",
                &data_path.to_string_lossy(),
                &their_hash_path.to_string_lossy(),
            ])
            .output()
            .expect("failed to run veritysetup");

        assert!(
            output.status.success(),
            "veritysetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        eprintln!("veritysetup output:\n{stdout}");

        let their_root_hash = stdout
            .lines()
            .find(|l| l.starts_with("Root hash:"))
            .and_then(|l| l.strip_prefix("Root hash:"))
            .map(|h| h.trim().to_string())
            .expect("could not parse root hash from veritysetup");

        let our_root_hash = create_verity_no_superblock(&data_path, &our_hash_path, &[]).unwrap();

        let our_bytes = std::fs::read(&our_hash_path).unwrap();
        let their_bytes = std::fs::read(&their_hash_path).unwrap();

        eprintln!(
            "our hash tree: {} bytes ({} blocks)",
            our_bytes.len(),
            our_bytes.len() / BLOCK_SIZE
        );
        eprintln!(
            "their hash tree: {} bytes ({} blocks)",
            their_bytes.len(),
            their_bytes.len() / BLOCK_SIZE
        );
        eprintln!("our root hash:   {our_root_hash}");
        eprintln!("their root hash: {their_root_hash}");

        assert_eq!(
            our_bytes.len(),
            their_bytes.len(),
            "hash tree size mismatch: ours={} ({} blocks) theirs={} ({} blocks)",
            our_bytes.len(),
            our_bytes.len() / BLOCK_SIZE,
            their_bytes.len(),
            their_bytes.len() / BLOCK_SIZE
        );
        assert_eq!(
            our_root_hash, their_root_hash,
            "root hash mismatch (large, empty salt)"
        );
        assert_eq!(
            our_bytes, their_bytes,
            "hash tree content differs (large, empty salt)"
        );
    }
}
