use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Assemble a GPT disk image from squashfs + verity partitions.
///
/// Layout:
///   Partition 1: root (squashfs data) — Linux root x86-64
///   Partition 2: root-verity (hash tree) — Linux root verity x86-64
///
/// Uses Discoverable Partitions Specification type GUIDs so systemd
/// can auto-discover partitions without explicit fstab entries.
///
/// Returns SHA256 hash of the final image.
pub fn assemble_gpt(
    squashfs_path: &Path,
    verity_path: &Path,
    output_path: &Path,
) -> Result<String> {
    let squashfs_data = std::fs::read(squashfs_path)
        .with_context(|| format!("reading {}", squashfs_path.display()))?;
    let verity_data =
        std::fs::read(verity_path).with_context(|| format!("reading {}", verity_path.display()))?;

    let sector_size: u64 = 512;
    let align_sectors: u64 = 2048; // 1 MiB alignment

    // Calculate partition sizes in sectors (aligned up to 1 MiB)
    let squashfs_sectors =
        align_up(squashfs_data.len() as u64, sector_size * align_sectors) / sector_size;
    let verity_sectors =
        align_up(verity_data.len() as u64, sector_size * align_sectors) / sector_size;

    // Partition 1 starts at first aligned boundary after GPT header (34 sectors)
    let part1_start = align_sectors;
    let part1_end = part1_start + squashfs_sectors - 1;

    // Partition 2 starts at next aligned boundary
    let part2_start = align_up(part1_end + 1, align_sectors);
    let part2_end = part2_start + verity_sectors - 1;

    // Total disk size (+ 33 sectors for backup GPT at end)
    let total_sectors = part2_end + 1 + 33;
    let total_bytes = total_sectors * sector_size;

    tracing::info!(
        "GPT layout: squashfs={} MiB, verity={} MiB, total={} MiB",
        squashfs_sectors * sector_size / (1024 * 1024),
        verity_sectors * sector_size / (1024 * 1024),
        total_bytes / (1024 * 1024),
    );

    // Create the raw disk file filled with zeros
    let mut disk = vec![0u8; total_bytes as usize];

    // Write partition data at the correct offsets
    let p1_offset = (part1_start * sector_size) as usize;
    disk[p1_offset..p1_offset + squashfs_data.len()].copy_from_slice(&squashfs_data);

    let p2_offset = (part2_start * sector_size) as usize;
    disk[p2_offset..p2_offset + verity_data.len()].copy_from_slice(&verity_data);

    // Create GPT using gptman
    let mut cursor = std::io::Cursor::new(&mut disk[..]);
    let disk_guid = random_guid();
    let mut gpt =
        gptman::GPT::new_from(&mut cursor, sector_size, disk_guid).context("creating GPT")?;

    // Linux root x86-64 (Discoverable Partitions Spec)
    // 4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709
    let root_type_guid: [u8; 16] = guid_from_str("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709");

    // Linux root verity x86-64
    // 2C7357ED-EBD2-46D9-AEC1-23D437EC80FE
    let verity_type_guid: [u8; 16] = guid_from_str("2C7357ED-EBD2-46D9-AEC1-23D437EC80FE");

    // Add root partition
    gpt[1] = gptman::GPTPartitionEntry {
        partition_type_guid: root_type_guid,
        unique_partition_guid: random_guid(),
        starting_lba: part1_start,
        ending_lba: part1_end,
        attribute_bits: 0,
        partition_name: "root".into(),
    };

    // Add verity partition
    gpt[2] = gptman::GPTPartitionEntry {
        partition_type_guid: verity_type_guid,
        unique_partition_guid: random_guid(),
        starting_lba: part2_start,
        ending_lba: part2_end,
        attribute_bits: 0,
        partition_name: "root-verity".into(),
    };

    // Write protective MBR (required for kernel to discover GPT)
    gptman::GPT::write_protective_mbr_into(&mut cursor, sector_size)
        .context("writing protective MBR")?;

    // Write GPT headers + partition table to disk
    gpt.write_into(&mut cursor).context("writing GPT to disk")?;

    // Write the final image
    let final_data = cursor.into_inner();
    std::fs::write(output_path, final_data)
        .with_context(|| format!("writing {}", output_path.display()))?;

    // Compute hash
    let written = std::fs::read(output_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&written);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Parse a GUID string like "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" into
/// the mixed-endian [u8; 16] format used by GPT.
fn guid_from_str(s: &str) -> [u8; 16] {
    let hex: String = s.replace('-', "");
    let bytes: Vec<u8> = (0..32)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();

    // GPT uses mixed-endian: first 3 components are little-endian, last 2 are big-endian
    [
        bytes[3], bytes[2], bytes[1], bytes[0], // time_low (LE)
        bytes[5], bytes[4], // time_mid (LE)
        bytes[7], bytes[6], // time_hi_and_version (LE)
        bytes[8], bytes[9], // clock_seq
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], // node
    ]
}

/// Generate a random GUID.
fn random_guid() -> [u8; 16] {
    let mut guid = [0u8; 16];
    // Use system random
    let _ = getrandom(&mut guid);
    // Set version 4 (random) and variant bits
    guid[6] = (guid[6] & 0x0F) | 0x40; // version 4
    guid[8] = (guid[8] & 0x3F) | 0x80; // variant 1
    guid
}

fn getrandom(buf: &mut [u8]) -> Result<()> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open("/dev/urandom").context("opening /dev/urandom")?;
    f.read_exact(buf).context("reading /dev/urandom")?;
    Ok(())
}

/// Align a value up to the nearest multiple of alignment.
fn align_up(value: u64, alignment: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    value.div_ceil(alignment) * alignment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_up_works() {
        assert_eq!(align_up(0, 1024), 0);
        assert_eq!(align_up(1, 1024), 1024);
        assert_eq!(align_up(1024, 1024), 1024);
        assert_eq!(align_up(1025, 1024), 2048);
    }

    #[test]
    fn guid_from_str_parses_correctly() {
        // Linux root x86-64 type GUID
        let guid = guid_from_str("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709");
        // First 4 bytes should be time_low in little-endian
        assert_eq!(guid[0], 0xE3);
        assert_eq!(guid[1], 0xBC);
        assert_eq!(guid[2], 0x68);
        assert_eq!(guid[3], 0x4F);
    }

    #[test]
    fn random_guid_has_correct_version() {
        let guid = random_guid();
        assert_eq!(guid[6] & 0xF0, 0x40); // version 4
        assert_eq!(guid[8] & 0xC0, 0x80); // variant 1
    }
}
