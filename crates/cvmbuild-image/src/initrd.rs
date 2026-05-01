//! Initrd overlay builder — generates CPIO overlay and concatenates with base initrd.
//!
//! The Linux kernel supports multiple initrd images (concatenated CPIOs).
//! We extract the base initrd from the container's /boot/ and prepend our
//! verity activation overlay.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::cpio::CpioBuilder;
use crate::squashfs::sha256_file;

/// Build the final initrd: overlay CPIO + (deterministic) base initrd.
///
/// Returns (output_path, sha256).
pub fn build_initrd(
    base_initrd: &Path,
    output_path: &Path,
    config: &cvmbuild_config::Config,
) -> Result<(PathBuf, String)> {
    let overlay = build_overlay_cpio(config)?;

    // Read the base initrd produced by initramfs-tools inside the docker
    // build. It's typically structured as:
    //   - 0..N: uncompressed CPIO (kernel modules + firmware + early boot)
    //   - N..end: zstd-compressed CPIO (rest of initramfs userland)
    //
    // Both segments embed inode numbers and mtimes from the docker build's
    // ephemeral filesystem, so they differ between cold-cache builds — the
    // exact reproducibility leak that drove the rootfs hash fix elsewhere
    // in cvmbuild. Rewrite both to zero those fields before concatenating.
    let base = std::fs::read(base_initrd)
        .with_context(|| format!("opening {}", base_initrd.display()))?;
    let deterministic_base = make_initrd_deterministic(&base)
        .context("rewriting base initrd to be deterministic")?;

    // Concatenate: overlay CPIO first (uncompressed), then base initrd.
    //
    // The Linux kernel processes concatenated CPIOs in order. Putting the
    // uncompressed overlay first avoids "invalid magic at start of compressed
    // archive" errors that occur when raw CPIO follows a compressed stream.
    // This is the same pattern the kernel uses for CPU microcode (uncompressed
    // CPIO prepended to compressed initramfs).
    //
    // For duplicate paths, the LAST occurrence wins, so the base initrd's files
    // take precedence. Our overlay only adds NEW files (scripts/local-top/verity-root,
    // verity services, udev rules) that don't exist in the base.
    let mut out = std::fs::File::create(output_path)
        .with_context(|| format!("creating {}", output_path.display()))?;
    out.write_all(&overlay).context("writing overlay CPIO")?;
    out.write_all(&deterministic_base)
        .context("writing deterministic base initrd")?;
    drop(out);

    let hash = sha256_file(output_path)?;
    Ok((output_path.to_path_buf(), hash))
}

/// Walk a CPIO new-c byte stream and zero the per-entry inode + mtime
/// fields in-place. Returns the rewritten buffer (same length, ino + mtime
/// fields replaced with `00000000`). nlink is left alone — link-count
/// differences would change tarball semantics.
///
/// CPIO new-c header layout (every field is 8-byte ASCII hex):
///   off  field           note
///   0    "070701"         (6-byte magic, NOT 8 hex)
///   6    c_ino            ← ZERO
///   14   c_mode
///   22   c_uid
///   30   c_gid
///   38   c_nlink
///   46   c_mtime          ← ZERO
///   54   c_filesize
///   62   c_devmajor
///   70   c_devminor
///   78   c_rdevmajor
///   86   c_rdevminor
///   94   c_namesize
///   102  c_check
///   110  c_name (length c_namesize, NUL-terminated)
///        + 4-byte padding to align c_data
///   ?    c_data (c_filesize bytes)
///        + 4-byte padding to align next header
fn rewrite_cpio_dets(buf: &mut [u8]) -> Result<()> {
    const ZERO_HEX: &[u8] = b"00000000";
    let mut pos = 0;
    while pos + 110 <= buf.len() {
        if &buf[pos..pos + 6] != b"070701" {
            // Could be padding before next archive — skip null bytes.
            if buf[pos] == 0 {
                pos += 1;
                continue;
            }
            // Not CPIO header and not padding — stop walking.
            break;
        }
        let namesize = parse_hex8(&buf[pos + 94..pos + 102])
            .context("parsing CPIO c_namesize")?;
        let filesize = parse_hex8(&buf[pos + 54..pos + 62])
            .context("parsing CPIO c_filesize")?;
        // Zero the two non-deterministic fields.
        buf[pos + 6..pos + 14].copy_from_slice(ZERO_HEX); // c_ino
        buf[pos + 46..pos + 54].copy_from_slice(ZERO_HEX); // c_mtime

        // Detect TRAILER!!! and stop — anything past it is concatenation
        // padding for the next archive segment, which the caller handles.
        let name_start = pos + 110;
        let name_end = name_start + namesize as usize;
        if name_end > buf.len() {
            anyhow::bail!("CPIO name overruns buffer at offset {pos}");
        }
        let name = &buf[name_start..name_end - 1];
        let name_padded = (name_end + 3) & !3;
        let data_end = name_padded + filesize as usize;
        let data_padded = (data_end + 3) & !3;
        if data_padded > buf.len() {
            anyhow::bail!("CPIO data overruns buffer at offset {pos}");
        }
        pos = data_padded;
        if name == b"TRAILER!!!" {
            break;
        }
    }
    Ok(())
}

fn parse_hex8(s: &[u8]) -> Result<u32> {
    let s = std::str::from_utf8(s).context("CPIO field not ASCII")?;
    u32::from_str_radix(s, 16).context("CPIO field not hex")
}

/// Find the byte offset where the uncompressed CPIO segments end and a
/// zstd-compressed segment begins (zstd magic `28 b5 2f fd`). Returns
/// `None` if no zstd segment is found.
fn find_zstd_offset(buf: &[u8]) -> Option<usize> {
    const ZSTD_MAGIC: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
    buf.windows(4)
        .position(|w| w == ZSTD_MAGIC)
        .map(|i| i)
}

/// Rewrite a base initrd to remove non-deterministic fields:
///   1. Zero inode + mtime in every uncompressed CPIO entry header.
///   2. Decompress the trailing zstd segment, do the same, recompress
///      with a fixed level (no embedded mtime).
fn make_initrd_deterministic(base: &[u8]) -> Result<Vec<u8>> {
    let zstd_off = find_zstd_offset(base);

    // Phase 1: rewrite the leading uncompressed CPIO portion.
    let mut head = match zstd_off {
        Some(off) => base[..off].to_vec(),
        None => base.to_vec(),
    };
    rewrite_cpio_dets(&mut head)?;

    // Phase 2: decompress, rewrite, recompress the trailing zstd segment.
    if let Some(off) = zstd_off {
        let compressed = &base[off..];
        let mut decoded = zstd::stream::decode_all(compressed)
            .context("decoding zstd-compressed initramfs segment")?;
        rewrite_cpio_dets(&mut decoded)?;
        // Recompress at level 19 (initramfs-tools uses ~19 by default for
        // size). Level is part of the algorithm, not a "build setting", so
        // identical input + level → identical output.
        let recompressed = zstd::stream::encode_all(decoded.as_slice(), 19)
            .context("re-encoding zstd-compressed initramfs segment")?;
        head.extend_from_slice(&recompressed);
    }

    Ok(head)
}

/// Build the overlay CPIO containing verity activation infrastructure.
fn build_overlay_cpio(config: &cvmbuild_config::Config) -> Result<Vec<u8>> {
    let verity_disks = &config.verity_disks;
    let mut cpio = CpioBuilder::new();

    // Directory structure
    cpio.add_dir("usr", 0o755);
    cpio.add_dir("usr/local", 0o755);
    cpio.add_dir("usr/local/lib", 0o755);
    cpio.add_dir("usr/local/lib/cvmbuild", 0o755);
    cpio.add_dir("etc", 0o755);
    cpio.add_dir("etc/systemd", 0o755);
    cpio.add_dir("etc/systemd/system", 0o755);
    cpio.add_dir("etc/udev", 0o755);
    cpio.add_dir("etc/udev/rules.d", 0o755);
    cpio.add_dir("etc/systemd/system/initrd-switch-root.target.d", 0o755);

    // Root verity activation — runs in initramfs local-top stage before root mount.
    // The veritysetup binary is already in the base initrd (copied by the Dockerfile's
    // initramfs-tools hook). We provide the activation script via this CPIO overlay.
    cpio.add_dir("scripts", 0o755);
    cpio.add_dir("scripts/local-top", 0o755);

    let verity_root_script = generate_verity_root_script(config);
    cpio.add_file(
        "scripts/local-top/verity-root",
        0o755,
        verity_root_script.into_bytes(),
    );

    // ORDER file — required by initramfs-tools' /init to discover local-top scripts.
    // Without this, init fails with "can't open /scripts/local-top/ORDER".
    cpio.add_file(
        "scripts/local-top/ORDER",
        0o644,
        b"/scripts/local-top/verity-root\n".to_vec(),
    );

    // Data disk verity services and udev rules (for model/config disks)

    // 1. verity-activate.py — baked with allowed disk names
    let activate_script = generate_verity_activate(verity_disks);
    cpio.add_file(
        "usr/local/lib/cvmbuild/verity-activate.py",
        0o755,
        activate_script.into_bytes(),
    );

    // 2. Verity service units — one per disk
    for disk in verity_disks {
        let service = generate_verity_service(disk);
        cpio.add_file(
            &format!("etc/systemd/system/verity-{}.service", disk.name),
            0o644,
            service.into_bytes(),
        );
    }

    // 3. Udev rules — SYSTEMD_READY=1 for verity devices
    let udev_rules = generate_udev_rules(verity_disks);
    cpio.add_file(
        "etc/udev/rules.d/99-z-cvmbuild-verity.rules",
        0o644,
        udev_rules.into_bytes(),
    );

    // 4. dm-verity blkid probe rule — the base initrd has 55-dm.rules and
    //    60-persistent-storage-dm.rules missing, so udevd never runs blkid
    //    on dm-* devices. Without ID_FS_TYPE in the udev database,
    //    wait-for-root (libudev) blocks for 30 seconds. This rule fixes it.
    cpio.add_file(
        "etc/udev/rules.d/56-dm-blkid.rules",
        0o644,
        b"SUBSYSTEM==\"block\", KERNEL==\"dm-[0-9]*\", IMPORT{builtin}=\"blkid\"\n".to_vec(),
    );

    // 5. Keep verity alive during switch-root
    let keep_verity = "[Unit]\nAfter=veritysetup.target\nRequires=veritysetup.target\n";
    cpio.add_file(
        "etc/systemd/system/initrd-switch-root.target.d/keep-verity.conf",
        0o644,
        keep_verity.as_bytes().to_vec(),
    );

    // 6. Mask blk-availability.service (prevents unmounting /sysroot)
    cpio.add_symlink("etc/systemd/system/blk-availability.service", "/dev/null");

    Ok(cpio.finish())
}

/// Generate the verity-activate.py script with allowed disk names baked in.
fn generate_verity_activate(verity_disks: &[cvmbuild_config::VerityDiskConfig]) -> String {
    let allowed_names = verity_disks
        .iter()
        .map(|d| format!("\"{}\"", d.name))
        .collect::<Vec<_>>()
        .join(", ");
    let disk_name_help = verity_disks
        .iter()
        .map(|d| d.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"#!/usr/bin/python3 -I
"""cvmbuild dm-verity activation script — zero-shell safe.

Reads roothash and hashoffset from /proc/cmdline for the named disk,
then calls veritysetup to open the dm-verity device.
"""

import subprocess
import sys


def parse_cmdline(name):
    with open("/proc/cmdline", "r") as f:
        cmdline = f.read().strip()

    params = {{}}
    for token in cmdline.split():
        if "=" in token:
            key, _, value = token.partition("=")
            params[key] = value

    roothash_key = f"{{name}}_roothash"
    hashoffset_key = f"{{name}}_hashoffset"

    roothash = params.get(roothash_key)
    if not roothash:
        print(f"FATAL: {{roothash_key}} not found in kernel cmdline", file=sys.stderr)
        sys.exit(1)

    hashoffset = params.get(hashoffset_key)
    if not hashoffset:
        print(f"FATAL: {{hashoffset_key}} not found in kernel cmdline", file=sys.stderr)
        sys.exit(1)

    try:
        bytes.fromhex(roothash)
    except ValueError:
        print(f"FATAL: {{roothash_key}} is not valid hex: {{roothash}}", file=sys.stderr)
        sys.exit(1)
    if len(roothash) not in (64, 128):
        print(f"FATAL: {{roothash_key}} has invalid length {{len(roothash)}}: {{roothash}}", file=sys.stderr)
        sys.exit(1)

    try:
        offset = int(hashoffset)
        if offset <= 0:
            raise ValueError("must be positive")
    except ValueError:
        print(f"FATAL: {{hashoffset_key}} is not a valid positive integer: {{hashoffset}}", file=sys.stderr)
        sys.exit(1)

    return roothash, offset


def activate_verity(name, device):
    roothash, hashoffset = parse_cmdline(name)
    mapper_name = f"verity-{{name}}"

    print(f"verity-activate: opening {{device}} as /dev/mapper/{{mapper_name}}")
    print(f"  roothash:   {{roothash}}")
    print(f"  hashoffset: {{hashoffset}}")

    data_blocks = hashoffset // 4096
    result = subprocess.run(
        [
            "/usr/sbin/veritysetup",
            "open",
            "--no-superblock", "--format=1",
            "--hash=sha256", "--data-block-size=4096", "--hash-block-size=4096",
            "--salt=-", f"--data-blocks={{data_blocks}}",
            f"--hash-offset={{hashoffset}}",
            "--panic-on-corruption",
            device,
            mapper_name,
            device,
            roothash,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"FATAL: veritysetup failed (exit {{result.returncode}})", file=sys.stderr)
        if result.stderr:
            print(f"  stderr: {{result.stderr.strip()}}", file=sys.stderr)
        sys.exit(1)

    print(f"verity-activate: /dev/mapper/{{mapper_name}} is now active")

    import os
    dm_path = f"/dev/mapper/{{mapper_name}}"
    try:
        real = os.path.realpath(dm_path)
        dm_sysfs = f"/sys/block/{{os.path.basename(real)}}/uevent"
        if os.path.exists(dm_sysfs):
            with open(dm_sysfs, "w") as f:
                f.write("change")
            print(f"  triggered uevent via {{dm_sysfs}}")
    except Exception as e:
        print(f"  WARNING: uevent trigger failed: {{e}}")

    subprocess.run(
        ["/usr/bin/udevadm", "settle", "--timeout=10"],
        capture_output=True, text=True,
    )


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {{sys.argv[0]}} <name> <device>", file=sys.stderr)
        print("  name:   disk name ({disk_name_help})", file=sys.stderr)
        print("  device: block device (/dev/vdb, /dev/vdc)", file=sys.stderr)
        sys.exit(1)

    name = sys.argv[1]
    device = sys.argv[2]

    ALLOWED_NAMES = ({allowed_names})
    if name not in ALLOWED_NAMES:
        print(f"FATAL: disk name must be one of {{ALLOWED_NAMES}}: {{name}}", file=sys.stderr)
        sys.exit(1)

    if not device.startswith("/dev/") or ".." in device:
        print(f"FATAL: device must be a clean /dev/ path: {{device}}", file=sys.stderr)
        sys.exit(1)

    activate_verity(name, device)


if __name__ == "__main__":
    main()
"#
    )
}

/// Generate a verity activation systemd service unit.
fn generate_verity_service(disk: &cvmbuild_config::VerityDiskConfig) -> String {
    format!(
        "\
[Unit]
Description=dm-verity activation for {description}
DefaultDependencies=no
After=dev-{device}.device local-fs-pre.target
Requires=dev-{device}.device
Before=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=DM_DISABLE_UDEV=1
ExecStart=/usr/bin/python3 -I /usr/local/lib/cvmbuild/verity-activate.py {name} /dev/{device}
NoNewPrivileges=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
",
        name = disk.name,
        device = disk.device,
        description = disk.description,
    )
}

/// Generate the verity-root initramfs script that activates dm-verity for the root filesystem.
///
/// Runs during initramfs local-top stage (before root is mounted).
/// Reads `roothash=` from kernel cmdline, opens /dev/vda1 + /dev/vda2 via veritysetup.
fn generate_verity_root_script(config: &cvmbuild_config::Config) -> String {
    let panic_flag = if config.verity.panic_on_corruption {
        " \\\n    --panic-on-corruption"
    } else {
        ""
    };

    format!(
        r#"#!/bin/sh
PREREQ=""
prereqs() {{ echo "$PREREQ"; }}
case $1 in prereqs) prereqs; exit 0;; esac
. /scripts/functions

log_begin_msg "verity-root: activating dm-verity for root filesystem"

modprobe dm-mod 2>/dev/null || true
modprobe dm-verity 2>/dev/null || true

ROOTHASH=""
for x in $(cat /proc/cmdline); do
    case "$x" in roothash=*) ROOTHASH="${{x#roothash=}}";; esac
done
[ -z "$ROOTHASH" ] && panic "verity-root: roothash= not found in kernel cmdline"

DATA_DEV="/dev/vda1"
HASH_DEV="/dev/vda2"
wait_for_udev 10
n=0; while [ ! -b "$DATA_DEV" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n+1)); done
[ ! -b "$DATA_DEV" ] && panic "verity-root: $DATA_DEV not found"
[ ! -b "$HASH_DEV" ] && panic "verity-root: $HASH_DEV not found"

log_begin_msg "verity-root: data=$DATA_DEV hash=$HASH_DEV roothash=$ROOTHASH"

DM_DISABLE_UDEV=1 veritysetup open{panic_flag} \
    "$DATA_DEV" root "$HASH_DEV" "$ROOTHASH" || \
    panic "verity-root: veritysetup failed (exit $?)"

# DM_DISABLE_UDEV=1 skips udev notification, so wait-for-root (libudev)
# can't find /dev/mapper/root. Trigger a udev change event on the dm
# block device so it gets registered. We find it via sysfs dm/name
# since readlink won't resolve the node with udev disabled.
for _sysdev in /sys/block/dm-*; do
    [ -f "$_sysdev/dm/name" ] || continue
    if [ "$(cat "$_sysdev/dm/name")" = "root" ]; then
        echo change > "$_sysdev/uevent" 2>/dev/null || true
        break
    fi
done
udevadm settle --timeout=5 2>/dev/null || true

log_end_msg
"#
    )
}

/// Generate udev rules that set SYSTEMD_READY=1 for verity mapper devices.
fn generate_udev_rules(verity_disks: &[cvmbuild_config::VerityDiskConfig]) -> String {
    let mut rules =
        String::from("# cvmbuild dm-verity — mark verity devices as ready for systemd\n");
    for disk in verity_disks {
        rules.push_str(&format!(
            "SUBSYSTEM==\"block\", ENV{{DM_NAME}}==\"verity-{name}\", ENV{{SYSTEMD_READY}}=\"1\"\n",
            name = disk.name,
        ));
    }
    rules
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
[[verity_disks]]
name = "config"
device = "vdc"
mountpoint = "/mnt/config"
description = "configuration disk"
"#,
        )
        .unwrap()
    }

    #[test]
    fn overlay_cpio_contains_expected_entries() {
        let config = test_config();
        let cpio = build_overlay_cpio(&config).unwrap();
        let s = String::from_utf8_lossy(&cpio);

        // Root verity activation script
        assert!(s.contains("scripts/local-top/verity-root"));
        // Data disk verity
        assert!(s.contains("verity-activate.py"));
        assert!(s.contains("verity-models.service"));
        assert!(s.contains("verity-config.service"));
        assert!(s.contains("99-z-cvmbuild-verity.rules"));
        assert!(s.contains("keep-verity.conf"));
        assert!(s.contains("blk-availability.service"));
    }

    #[test]
    fn verity_root_script_has_panic_on_corruption() {
        let config = test_config();
        let script = generate_verity_root_script(&config);
        assert!(script.contains("--panic-on-corruption"));
        assert!(script.contains("roothash="));
        assert!(script.contains("/dev/vda1"));
        assert!(script.contains("/dev/vda2"));
        assert!(script.contains("veritysetup open"));
        assert!(script.contains("udevadm settle"));
        assert!(script.contains(". /scripts/functions"));
    }

    #[test]
    fn verity_activate_has_allowed_names() {
        let config = test_config();
        let script = generate_verity_activate(&config.verity_disks);
        assert!(script.contains("\"models\", \"config\""));
        assert!(script.contains("parse_cmdline"));
        assert!(script.contains("--panic-on-corruption"));
    }

    #[test]
    fn verity_service_has_correct_device() {
        let config = test_config();
        let disk = &config.verity_disks[0];
        let svc = generate_verity_service(disk);
        assert!(svc.contains("dev-vdb.device"));
        assert!(svc.contains("verity-activate.py models /dev/vdb"));
        assert!(svc.contains("DM_DISABLE_UDEV=1"));
    }

    #[test]
    fn udev_rules_match_disk_names() {
        let config = test_config();
        let rules = generate_udev_rules(&config.verity_disks);
        assert!(rules.contains("verity-models"));
        assert!(rules.contains("verity-config"));
        assert!(rules.contains("SYSTEMD_READY"));
    }

    #[test]
    fn build_initrd_concatenates() {
        let tmp = tempfile::tempdir().unwrap();
        let base_path = tmp.path().join("base.initrd");
        std::fs::write(&base_path, b"FAKE_BASE_INITRD_DATA").unwrap();

        let output_path = tmp.path().join("final.initrd");
        let config = test_config();
        let (path, hash) = build_initrd(&base_path, &output_path, &config).unwrap();

        assert!(path.exists());
        assert_eq!(hash.len(), 64);

        // Output should contain both overlay CPIO and base data
        let data = std::fs::read(&path).unwrap();
        // Overlay CPIO comes first (starts with CPIO magic)
        assert_eq!(&data[..6], b"070701");
        // Base initrd is appended after
        assert!(data.windows(21).any(|w| w == b"FAKE_BASE_INITRD_DATA"));
    }
}
