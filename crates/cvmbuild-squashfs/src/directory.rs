/// Directory table builder.
///
/// Groups directory entries into headers (max 256 per header, inode delta
/// must fit in i16) and writes them into a MetadataWriter.
///
/// Index entries are created every ~8192 bytes of directory data (matching
/// mksquashfs behavior). The distance check itself triggers group splits.
use crate::format::{DirEntry, DirHeader, DirIndexEntry, METADATA_BLOCK_SIZE};
use crate::inode::InodeRef;
use crate::writer::MetadataWriter;

/// A single directory child ready to be written.
#[derive(Debug, Clone)]
pub struct DirChild {
    pub name: Vec<u8>,
    pub inode_number: u32,
    pub inode_ref: InodeRef,
    pub entry_type: u16,
}

/// Builds the directory table.
pub struct DirectoryTable {
    pub meta: MetadataWriter,
}

impl DirectoryTable {
    pub fn new() -> Self {
        Self {
            meta: MetadataWriter::new(),
        }
    }

    /// Write a single directory's entries to the table.
    ///
    /// `children` must be sorted by name (caller responsibility).
    ///
    /// Returns `(block_offset, byte_offset, total_dir_size, index_entries, index_names)`:
    /// - `block_offset`: metadata block byte offset from the start of the directory table
    /// - `byte_offset`: offset within the uncompressed metadata block
    /// - `total_dir_size`: total bytes written for this directory (for dir inode `file_size`)
    /// - `index_entries`: directory index entries at metadata block boundaries
    /// - `index_names`: name of first entry at each metadata block boundary
    pub fn write_directory(
        &mut self,
        children: &[DirChild],
    ) -> (u64, u16, u32, Vec<DirIndexEntry>, Vec<Vec<u8>>) {
        let (start_blk, start_off) = self.meta.position();

        if children.is_empty() {
            return (start_blk, start_off, 0, vec![], vec![]);
        }

        // Phase 1: Build flat directory data buffer with mksquashfs-compatible
        // grouping and index creation.
        let (dir_buf, raw_indexes) = build_directory_data(children);
        let total_bytes = dir_buf.len() as u32;

        // Phase 2: Write dir_buf to MetadataWriter and compute start_block
        // for each index entry. Mimics mksquashfs write_dir(): writes data
        // in chunks aligned to metadata block boundaries, recording the
        // compressed block offset for each index entry.
        let mut final_indexes: Vec<DirIndexEntry> = Vec::new();
        let mut final_names: Vec<Vec<u8>> = Vec::new();

        if raw_indexes.is_empty() {
            // No indexes — write all data in one shot.
            self.meta.write(&dir_buf);
        } else {
            let mut idx = 0;
            let mut boundary = METADATA_BLOCK_SIZE - start_off as usize;
            let mut written = 0;

            loop {
                // Get compressed offset of the current (possibly partial) metadata block.
                let block_offset = self.meta.position().0 as u32;

                // Assign start_block to all indexes whose position falls before
                // the next metadata block boundary.
                while idx < raw_indexes.len() && (raw_indexes[idx].0 as usize) < boundary {
                    final_indexes.push(DirIndexEntry {
                        index: raw_indexes[idx].0,
                        start_block: block_offset,
                        name_size: raw_indexes[idx].1,
                    });
                    final_names.push(raw_indexes[idx].2.clone());
                    idx += 1;
                }

                // Write data up to the next metadata block boundary.
                let chunk_end = boundary.min(dir_buf.len());
                if chunk_end > written {
                    self.meta.write(&dir_buf[written..chunk_end]);
                    written = chunk_end;
                }

                if written >= dir_buf.len() {
                    break;
                }

                boundary += METADATA_BLOCK_SIZE;
            }
        }

        (
            start_blk,
            start_off,
            total_bytes,
            final_indexes,
            final_names,
        )
    }
}

/// Build the flat directory data buffer and collect raw index entries.
///
/// Single-pass algorithm matching mksquashfs's `scan8_add_dir_entry`:
/// - Groups entries by inode metadata block, i16 delta range, and 256-entry limit
/// - Distance > 8192 bytes from last index triggers both a new group AND an index entry
/// - Index entries record (byte_offset, name_size-1, name)
///
/// Returns `(dir_buf, raw_indexes)` where `raw_indexes` contains
/// `(index_offset, name_size_minus_1, name)` tuples.
#[allow(clippy::type_complexity)]
fn build_directory_data(children: &[DirChild]) -> (Vec<u8>, Vec<(u32, u32, Vec<u8>)>) {
    let mut dir_buf = Vec::new();
    let mut raw_indexes: Vec<(u32, u32, Vec<u8>)> = Vec::new();

    let mut entry_count: u32 = 0;
    let mut group_inode_block: u32 = 0;
    let mut group_base_inode: u32 = 0;
    let mut header_count_offset: usize = 0; // position of current header's count field
    let mut index_count_offset: usize = 0; // byte offset at last index (or 0)
    let mut have_header = false;

    for child in children {
        let child_block = (child.inode_ref >> 16) as u32;
        let name_len = child.name.len();
        let entry_total = 8 + name_len; // sizeof(dir_entry) + name

        // Distance check: would adding this entry push distance past 8192?
        // (matches mksquashfs condition in scan8_add_dir_entry)
        let distance = dir_buf.len() + entry_total - index_count_offset;
        let distance_exceeded = have_header && distance > METADATA_BLOCK_SIZE;

        let need_new_group = entry_count >= 256
            || (have_header && child_block != group_inode_block)
            || distance_exceeded
            || (have_header && {
                let delta = child.inode_number as i64 - group_base_inode as i64;
                delta > i16::MAX as i64 || delta < i16::MIN as i64
            });

        if need_new_group && have_header {
            // Check distance for index creation. This fires even when the group
            // split was triggered by other conditions (256 entries, different block,
            // delta overflow) — matching mksquashfs behavior.
            let dist = dir_buf.len() + entry_total - index_count_offset;
            if dist > METADATA_BLOCK_SIZE {
                raw_indexes.push((
                    dir_buf.len() as u32,
                    name_len as u32 - 1,
                    child.name.clone(),
                ));
                index_count_offset = dir_buf.len();
            }

            // Finalize current group header: patch count field (count - 1).
            let count_minus_1 = entry_count - 1;
            dir_buf[header_count_offset..header_count_offset + 4]
                .copy_from_slice(&count_minus_1.to_le_bytes());

            entry_count = 0;
            have_header = false;
        }

        if !have_header {
            // Write new group header (count is a placeholder, patched when group ends).
            header_count_offset = dir_buf.len();
            let header = DirHeader {
                count: 0xFFFF_FFFF, // placeholder
                start_block: child_block,
                inode_number: child.inode_number,
            };
            header.write_to(&mut dir_buf).unwrap();
            group_inode_block = child_block;
            group_base_inode = child.inode_number;
            have_header = true;
        }

        // Write directory entry.
        let delta = child.inode_number as i32 - group_base_inode as i32;
        let inode_byte_offset = (child.inode_ref & 0xFFFF) as u16;
        let entry = DirEntry {
            offset: inode_byte_offset,
            inode_delta: delta as i16,
            entry_type: child.entry_type,
            name_size: (name_len as u16) - 1,
        };
        entry.write_to(&mut dir_buf).unwrap();
        dir_buf.extend_from_slice(&child.name);
        entry_count += 1;
    }

    // Finalize last group header.
    if have_header && entry_count > 0 {
        let count_minus_1 = entry_count - 1;
        dir_buf[header_count_offset..header_count_offset + 4]
            .copy_from_slice(&count_minus_1.to_le_bytes());
    }

    (dir_buf, raw_indexes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{DIR_TYPE_DIR, DIR_TYPE_FILE};
    use crate::inode::make_inode_ref;

    #[test]
    fn empty_directory() {
        let mut dt = DirectoryTable::new();
        let (_, _, size, idx, _) = dt.write_directory(&[]);
        assert_eq!(size, 0);
        assert!(idx.is_empty());
    }

    #[test]
    fn single_entry() {
        let mut dt = DirectoryTable::new();
        let children = vec![DirChild {
            name: b"hello".to_vec(),
            inode_number: 2,
            inode_ref: make_inode_ref(0, 0),
            entry_type: DIR_TYPE_FILE,
        }];
        let (blk, off, size, idx, _) = dt.write_directory(&children);
        // Should have header (12 bytes) + entry (8 bytes + 5 bytes name) = 25 bytes
        assert_eq!(blk, 0);
        assert_eq!(off, 0);
        assert_eq!(size, 25);
        assert!(idx.is_empty()); // too small for index
    }

    #[test]
    fn grouping_by_block() {
        // Entries with different inode metadata blocks should be in separate groups.
        let mut dt = DirectoryTable::new();
        let children: Vec<DirChild> = (0..4)
            .map(|i| {
                let block = if i < 2 { 0 } else { 100 };
                DirChild {
                    name: format!("f{i}").into_bytes(),
                    inode_number: i + 1,
                    inode_ref: make_inode_ref(block, 0),
                    entry_type: DIR_TYPE_DIR,
                }
            })
            .collect();
        let (_, _, size, idx, _) = dt.write_directory(&children);
        // Two groups: header(12) + 2 entries(10 each) + header(12) + 2 entries(10 each) = 64
        assert_eq!(size, 64);
        assert!(idx.is_empty()); // too small for index
    }

    #[test]
    fn distance_based_index() {
        // Create enough entries to exceed 8192 bytes and trigger index creation.
        let mut dt = DirectoryTable::new();
        // Each entry: 8 bytes header + 20 bytes name = 28 bytes
        // Group header: 12 bytes
        // 8192 / 28 ≈ 292 entries per 8192 bytes (plus headers every 256 entries)
        // With 256 entries per group: 12 + 256*28 = 7180 bytes (first group)
        // Next group starts, distance check: 7180 + 28 = 7208 < 8192, no index yet
        // After ~293 entries: 12 + 256*28 + 12 + 37*28 = 8228 > 8192 → index
        let children: Vec<DirChild> = (0..350)
            .map(|i| DirChild {
                name: format!("entry_{:014}", i).into_bytes(), // 20-char name
                inode_number: i + 1,
                inode_ref: make_inode_ref(0, (i * 30 % 8000) as u16),
                entry_type: DIR_TYPE_FILE,
            })
            .collect();
        let (_, _, size, idx, names) = dt.write_directory(&children);
        assert!(size > 8192);
        // Should have at least one index entry
        assert!(!idx.is_empty());
        assert_eq!(idx.len(), names.len());
    }
}
