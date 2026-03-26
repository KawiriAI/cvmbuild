//! Integration tests: kernel mount + mksquashfs comparison.
//! Requires root (sudo). Run with: cargo test --test mount_test -- --ignored
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn run(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd)
        .args(args)
        .env_remove("SOURCE_DATE_EPOCH")
        .output()
        .unwrap_or_else(|e| {
            panic!("failed to run {cmd}: {e}");
        });
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        panic!(
            "{cmd} {:?} failed:\nstdout: {stdout}\nstderr: {stderr}",
            args
        );
    }
    stdout
}

/// Find the nix mksquashfs 4.7 (linked against zstd 1.5.7 for byte-identical output).
/// Falls back to system mksquashfs if the nix one isn't available.
fn find_mksquashfs() -> String {
    // The nix mksquashfs path — built with zstd 1.5.7 matching our Rust zstd-sys crate
    let nix_path = "/nix/store/q57fjvaknspyw4km42wssb3n9szmrglv-squashfs-4.7.4/bin/mksquashfs";
    if Path::new(nix_path).exists() {
        return nix_path.to_string();
    }
    // Try to find any nix squashfs-tools 4.7 in the store
    if let Ok(entries) = fs::read_dir("/nix/store") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains("squashfs-4.7") && entry.path().join("bin/mksquashfs").exists() {
                return entry
                    .path()
                    .join("bin/mksquashfs")
                    .to_string_lossy()
                    .to_string();
            }
        }
    }
    "mksquashfs".to_string()
}

/// Build a test rootfs with files, dirs, symlinks, hardlinks, multi-block files.
fn make_test_rootfs() -> TempDir {
    let rootfs = TempDir::new().unwrap();
    let r = rootfs.path();

    fs::create_dir_all(r.join("etc")).unwrap();
    fs::create_dir_all(r.join("usr/bin")).unwrap();
    fs::create_dir_all(r.join("var/lib")).unwrap();
    fs::create_dir_all(r.join("a/b/c/d")).unwrap();

    fs::write(r.join("etc/hostname"), "testhost\n").unwrap();
    fs::write(r.join("etc/hosts"), "127.0.0.1 localhost\n").unwrap();
    fs::write(r.join("usr/bin/hello"), "#!/bin/sh\necho hello\n").unwrap();
    fs::write(r.join("var/lib/empty"), "").unwrap();

    // Multi-block file (>128 KiB)
    let big = vec![0x42u8; 200_000];
    fs::write(r.join("bigfile"), &big).unwrap();

    // Incompressible content
    let mut random_content = vec![0u8; 50_000];
    for (i, b) in random_content.iter_mut().enumerate() {
        *b = ((i * 7 + 13) % 256) as u8;
    }
    fs::write(r.join("random.bin"), &random_content).unwrap();

    // Symlinks
    symlink("hostname", r.join("etc/hostname.link")).unwrap();
    symlink("/usr/bin/hello", r.join("abs_link")).unwrap();
    symlink("../etc/hosts", r.join("var/lib/hosts_link")).unwrap();

    // Hard links
    fs::hard_link(r.join("etc/hosts"), r.join("etc/hosts.bak")).unwrap();

    // Deep nesting
    fs::write(r.join("a/b/c/d/deep.txt"), "deep content").unwrap();

    rootfs
}

/// Recursively collect all file paths under a directory (sorted).
fn collect_files(dir: &Path, prefix: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let rel = prefix.join(entry.file_name());
        let ft = entry.file_type().unwrap();
        if ft.is_dir() {
            result.push(rel.clone());
            result.extend(collect_files(&entry.path(), &rel));
        } else {
            result.push(rel);
        }
    }
    result
}

#[test]
#[ignore] // requires root
fn mount_and_read_all() {
    let rootfs = make_test_rootfs();
    let r = rootfs.path();
    let random_content: Vec<u8> = (0..50_000).map(|i| ((i * 7 + 13) % 256) as u8).collect();

    let out_dir = TempDir::new().unwrap();
    let sqfs_path = out_dir.path().join("test.squashfs");
    let hash = cvmbuild_squashfs::create_squashfs(r, &sqfs_path).unwrap();
    println!("squashfs SHA256: {hash}");
    println!(
        "squashfs size: {} bytes",
        fs::metadata(&sqfs_path).unwrap().len()
    );

    let mnt = TempDir::new().unwrap();
    let mnt_path = mnt.path().to_str().unwrap();
    let sqfs_str = sqfs_path.to_str().unwrap();

    run(
        "mount",
        &["-o", "ro,loop", "-t", "squashfs", sqfs_str, mnt_path],
    );

    // Read all files recursively
    let output = Command::new("find")
        .args([mnt_path, "-type", "f", "-exec", "cat", "{}", ";"])
        .output()
        .expect("find failed");
    assert!(
        output.status.success(),
        "find+cat failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify specific file contents
    assert_eq!(
        fs::read_to_string(Path::new(mnt_path).join("etc/hostname")).unwrap(),
        "testhost\n"
    );
    assert_eq!(
        fs::read_to_string(Path::new(mnt_path).join("etc/hosts")).unwrap(),
        "127.0.0.1 localhost\n"
    );
    assert_eq!(
        fs::read_to_string(Path::new(mnt_path).join("usr/bin/hello")).unwrap(),
        "#!/bin/sh\necho hello\n"
    );
    assert!(fs::read(Path::new(mnt_path).join("var/lib/empty"))
        .unwrap()
        .is_empty());

    let big_read = fs::read(Path::new(mnt_path).join("bigfile")).unwrap();
    assert_eq!(big_read.len(), 200_000);
    assert!(big_read.iter().all(|&b| b == 0x42));

    assert_eq!(
        fs::read(Path::new(mnt_path).join("random.bin")).unwrap(),
        random_content
    );

    assert_eq!(
        fs::read_to_string(Path::new(mnt_path).join("a/b/c/d/deep.txt")).unwrap(),
        "deep content"
    );

    // Verify symlinks
    assert_eq!(
        fs::read_link(Path::new(mnt_path).join("etc/hostname.link"))
            .unwrap()
            .to_str()
            .unwrap(),
        "hostname"
    );
    assert_eq!(
        fs::read_link(Path::new(mnt_path).join("abs_link"))
            .unwrap()
            .to_str()
            .unwrap(),
        "/usr/bin/hello"
    );

    // Check dmesg for SQUASHFS errors
    let dmesg = Command::new("dmesg").output().expect("dmesg failed");
    let dmesg_str = String::from_utf8_lossy(&dmesg.stdout);
    let sqfs_errors: Vec<&str> = dmesg_str
        .lines()
        .filter(|l| l.contains("SQUASHFS error"))
        .collect();
    assert!(
        sqfs_errors.is_empty(),
        "SQUASHFS errors in dmesg: {sqfs_errors:?}"
    );

    let _ = Command::new("umount").arg(mnt_path).output();
}

#[test]
#[ignore] // requires root + mksquashfs
fn compare_with_mksquashfs() {
    let rootfs = make_test_rootfs();
    let r = rootfs.path();

    // Create squashfs with our writer
    let out_dir = TempDir::new().unwrap();
    let ours_path = out_dir.path().join("ours.squashfs");
    cvmbuild_squashfs::create_squashfs(r, &ours_path).unwrap();

    // Create squashfs with mksquashfs (same settings: zstd, 128K blocks, all-root)
    let ref_path = out_dir.path().join("ref.squashfs");
    let mksquashfs = find_mksquashfs();
    run(
        &mksquashfs,
        &[
            r.to_str().unwrap(),
            ref_path.to_str().unwrap(),
            "-comp",
            "zstd",
            "-b",
            "131072",
            "-all-root",
            "-noappend",
            "-no-xattrs",
            "-mkfs-time",
            "0",
            "-all-time",
            "0",
        ],
    );

    // Mount both
    let mnt_ours = TempDir::new().unwrap();
    let mnt_ref = TempDir::new().unwrap();

    run(
        "mount",
        &[
            "-o",
            "ro,loop",
            "-t",
            "squashfs",
            ours_path.to_str().unwrap(),
            mnt_ours.path().to_str().unwrap(),
        ],
    );
    run(
        "mount",
        &[
            "-o",
            "ro,loop",
            "-t",
            "squashfs",
            ref_path.to_str().unwrap(),
            mnt_ref.path().to_str().unwrap(),
        ],
    );

    // Compare: same files, same contents, same symlink targets, same permissions
    let ours_files = collect_files(mnt_ours.path(), Path::new(""));
    let ref_files = collect_files(mnt_ref.path(), Path::new(""));

    assert_eq!(
        ours_files, ref_files,
        "file lists must match\nours: {ours_files:?}\nref: {ref_files:?}"
    );

    for rel_path in &ours_files {
        let our_full = mnt_ours.path().join(rel_path);
        let ref_full = mnt_ref.path().join(rel_path);

        let our_meta = fs::symlink_metadata(&our_full).unwrap();
        let ref_meta = fs::symlink_metadata(&ref_full).unwrap();

        // Same file type
        assert_eq!(
            our_meta.file_type(),
            ref_meta.file_type(),
            "type mismatch for {rel_path:?}"
        );

        if our_meta.is_file() {
            // Same contents
            let our_data = fs::read(&our_full).unwrap();
            let ref_data = fs::read(&ref_full).unwrap();
            assert_eq!(
                our_data,
                ref_data,
                "content mismatch for {rel_path:?}: ours {} bytes, ref {} bytes",
                our_data.len(),
                ref_data.len()
            );
        } else if our_meta.is_symlink() {
            // Same target
            let our_target = fs::read_link(&our_full).unwrap();
            let ref_target = fs::read_link(&ref_full).unwrap();
            assert_eq!(
                our_target, ref_target,
                "symlink target mismatch for {rel_path:?}"
            );
        }
    }

    // Check no SQUASHFS errors from either mount
    let dmesg = Command::new("dmesg").output().expect("dmesg failed");
    let dmesg_str = String::from_utf8_lossy(&dmesg.stdout);
    let sqfs_errors: Vec<&str> = dmesg_str
        .lines()
        .filter(|l| l.contains("SQUASHFS error"))
        .collect();
    assert!(
        sqfs_errors.is_empty(),
        "SQUASHFS errors in dmesg: {sqfs_errors:?}"
    );

    println!("All files match between our writer and mksquashfs!");

    let _ = Command::new("umount")
        .arg(mnt_ours.path().to_str().unwrap())
        .output();
    let _ = Command::new("umount")
        .arg(mnt_ref.path().to_str().unwrap())
        .output();
}

#[test]
#[ignore] // requires mksquashfs
fn byte_identical_with_mksquashfs() {
    use sha2::{Digest, Sha256};

    let rootfs = make_test_rootfs();
    let r = rootfs.path();

    // Create squashfs with our writer
    let out_dir = TempDir::new().unwrap();
    let ours_path = out_dir.path().join("ours.squashfs");
    let our_hash = cvmbuild_squashfs::create_squashfs(r, &ours_path).unwrap();

    // Create squashfs with mksquashfs (same settings)
    let ref_path = out_dir.path().join("ref.squashfs");
    let mksquashfs = find_mksquashfs();
    run(
        &mksquashfs,
        &[
            r.to_str().unwrap(),
            ref_path.to_str().unwrap(),
            "-comp",
            "zstd",
            "-b",
            "131072",
            "-all-root",
            "-noappend",
            "-no-xattrs",
            "-mkfs-time",
            "0",
            "-all-time",
            "0",
        ],
    );

    let ref_data = fs::read(&ref_path).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&ref_data);
    let ref_hash = format!("{:x}", hasher.finalize());

    let our_data = fs::read(&ours_path).unwrap();

    println!("our hash:  {our_hash}");
    println!("ref hash:  {ref_hash}");
    println!("our size:  {} bytes", our_data.len());
    println!("ref size:  {} bytes", ref_data.len());

    // Dump superblock fields for comparison
    let read_u32 = |d: &[u8], off: usize| u32::from_le_bytes(d[off..off + 4].try_into().unwrap());
    let read_u16 = |d: &[u8], off: usize| u16::from_le_bytes(d[off..off + 2].try_into().unwrap());
    let read_u64 = |d: &[u8], off: usize| u64::from_le_bytes(d[off..off + 8].try_into().unwrap());

    println!("\n=== SUPERBLOCK COMPARISON ===");
    for (label, d) in [("OURS", &our_data), ("REF ", &ref_data)] {
        println!("{label}: inode_count={} mod_time={} block_size={} frag_count={} comp={} blog={} flags=0x{:04x} ids={} ver={}.{}",
            read_u32(d, 4), read_u32(d, 8), read_u32(d, 12), read_u32(d, 16),
            read_u16(d, 20), read_u16(d, 22), read_u16(d, 24), read_u16(d, 26),
            read_u16(d, 28), read_u16(d, 30));
        println!(
            "{label}: root_ref=0x{:x} bytes_used={} id_tbl=0x{:x} xattr_tbl=0x{:x}",
            read_u64(d, 32),
            read_u64(d, 40),
            read_u64(d, 48),
            read_u64(d, 56)
        );
        println!(
            "{label}: inode_tbl=0x{:x} dir_tbl=0x{:x} frag_tbl=0x{:x} lookup_tbl=0x{:x}",
            read_u64(d, 64),
            read_u64(d, 72),
            read_u64(d, 80),
            read_u64(d, 88)
        );
    }

    if our_hash != ref_hash {
        // Find first N differences
        let min_len = our_data.len().min(ref_data.len());
        let mut diffs = 0;
        for i in 0..min_len {
            if our_data[i] != ref_data[i] {
                if diffs < 5 {
                    println!(
                        "diff at byte {i} (0x{i:x}): ours=0x{:02x} ref=0x{:02x}",
                        our_data[i], ref_data[i]
                    );
                    let start = i.saturating_sub(4);
                    let end = (i + 12).min(min_len);
                    println!("  ours[{start}..{end}]: {:02x?}", &our_data[start..end]);
                    println!("  ref [{start}..{end}]: {:02x?}", &ref_data[start..end]);
                }
                diffs += 1;
            }
        }
        println!("total differing bytes: {diffs} / {min_len}");
        if our_data.len() != ref_data.len() {
            println!(
                "size mismatch: ours={} ref={}",
                our_data.len(),
                ref_data.len()
            );
        }
        panic!("output is NOT byte-identical to mksquashfs");
    }

    println!("SUCCESS: byte-identical output! SHA256: {our_hash}");
}
