/// Inode table builder.
///
/// Assigns sequential inode numbers and writes inode structures into a
/// `MetadataWriter`. Tracks hard links so duplicate files share an inode.
use std::collections::HashMap;

use crate::format::{
    BasicDirInode, BasicFileInode, BasicSymlinkInode, DirIndexEntry, ExtDirInode, ExtFileInode,
    InodeHeader, INODE_BASIC_DIR, INODE_BASIC_FILE, INODE_BASIC_SYMLINK, INODE_EXT_DIR,
    INODE_EXT_FILE, METADATA_BLOCK_SIZE, NO_XATTR,
};
use crate::writer::MetadataWriter;

/// Packed inode reference: `(metadata_block_byte_offset << 16) | offset_within_block`.
pub type InodeRef = u64;

pub fn make_inode_ref(block_offset: u64, byte_offset: u16) -> InodeRef {
    (block_offset << 16) | byte_offset as u64
}

/// Builds the inode table by accumulating inode data in a MetadataWriter.
pub struct InodeTable {
    pub meta: MetadataWriter,
    /// Map (device, host_inode) -> (our_inode_number, inode_ref) for hard link dedup.
    hardlink_map: HashMap<(u64, u64), (u32, InodeRef)>,
}

impl InodeTable {
    pub fn new() -> Self {
        Self {
            meta: MetadataWriter::new(),
            hardlink_map: HashMap::new(),
        }
    }

    /// Look up an existing inode for a hard link.
    pub fn lookup_hardlink(&self, dev: u64, host_ino: u64) -> Option<(u32, InodeRef)> {
        self.hardlink_map.get(&(dev, host_ino)).copied()
    }

    /// Register a file for hard link tracking.
    pub fn register_hardlink(&mut self, dev: u64, host_ino: u64, inum: u32, iref: InodeRef) {
        self.hardlink_map.insert((dev, host_ino), (inum, iref));
    }

    /// Add a regular file inode.
    ///
    /// - `inum`: pre-assigned inode number
    /// - `permissions`: file mode bits (e.g. 0o644)
    /// - `uid_idx`, `gid_idx`: indices into the ID table
    /// - `file_size`: total file size in bytes
    /// - `start_block`: byte offset of first data block in the output file
    /// - `block_sizes`: compressed size of each data block
    /// - `fragment_idx`: fragment index (NO_FRAGMENT if none)
    /// - `fragment_offset`: offset within fragment block
    /// - `nlink`: hard link count
    ///
    /// Returns `(inode_number, inode_ref)`.
    #[allow(clippy::too_many_arguments)]
    pub fn add_file(
        &mut self,
        inum: u32,
        permissions: u16,
        uid_idx: u16,
        gid_idx: u16,
        file_size: u64,
        start_block: u64,
        block_sizes: &[u32],
        fragment_idx: u32,
        fragment_offset: u32,
        nlink: u32,
        sparse: u64,
    ) -> (u32, InodeRef) {
        let (blk_off, byte_off) = self.meta.position();
        let iref = make_inode_ref(blk_off, byte_off);

        let use_extended = nlink > 1 || file_size >= (1u64 << 32) || start_block >= (1u64 << 32);

        if use_extended {
            let hdr = InodeHeader {
                inode_type: INODE_EXT_FILE,
                permissions,
                uid_idx,
                gid_idx,
                mtime: 0,
                inode_number: inum,
            };
            let body = ExtFileInode {
                start_block,
                file_size,
                sparse,
                nlink,
                fragment: fragment_idx,
                offset: fragment_offset,
                xattr_idx: NO_XATTR,
            };
            let mut buf = Vec::with_capacity(64 + block_sizes.len() * 4);
            hdr.write_to(&mut buf).unwrap();
            body.write_to(&mut buf).unwrap();
            for &bs in block_sizes {
                buf.extend_from_slice(&bs.to_le_bytes());
            }
            self.meta.write(&buf);
        } else {
            let hdr = InodeHeader {
                inode_type: INODE_BASIC_FILE,
                permissions,
                uid_idx,
                gid_idx,
                mtime: 0,
                inode_number: inum,
            };
            let body = BasicFileInode {
                start_block: start_block as u32,
                fragment: fragment_idx,
                offset: fragment_offset,
                file_size: file_size as u32,
            };
            let mut buf = Vec::with_capacity(48 + block_sizes.len() * 4);
            hdr.write_to(&mut buf).unwrap();
            body.write_to(&mut buf).unwrap();
            for &bs in block_sizes {
                buf.extend_from_slice(&bs.to_le_bytes());
            }
            self.meta.write(&buf);
        }

        (inum, iref)
    }

    /// Add a directory inode.
    ///
    /// - `inum`: pre-assigned inode number
    /// - `dir_block_offset`: byte offset of this dir's entries within the directory table
    ///   (from the start of the dir table, i.e., metadata block offset)
    /// - `dir_byte_offset`: offset within the uncompressed metadata block
    /// - `dir_size`: total size of the directory entries in bytes (including +3)
    /// - `nlink`: 2 + number of subdirectories
    /// - `parent_inode`: inode number of parent directory
    /// - `child_count`: number of directory entries
    /// - `entry_byte_count`: sum of (8 + name.len()) for all entries (no headers)
    /// - `index_entries`: directory index entries (from directory table builder)
    /// - `index_names`: names corresponding to each index entry
    ///
    /// Returns `(inode_number, inode_ref)`.
    #[allow(clippy::too_many_arguments)]
    pub fn add_dir(
        &mut self,
        inum: u32,
        permissions: u16,
        uid_idx: u16,
        gid_idx: u16,
        dir_block_offset: u64,
        dir_byte_offset: u16,
        dir_size: u32,
        nlink: u32,
        parent_inode: u32,
        child_count: u32,
        entry_byte_count: u32,
        index_entries: &[DirIndexEntry],
        index_names: &[Vec<u8>],
    ) -> (u32, InodeRef) {
        let (blk_off, byte_off) = self.meta.position();
        let iref = make_inode_ref(blk_off, byte_off);

        // Use extended dir (LDIR) matching mksquashfs: when entry count >= 257
        // OR entry byte count (without headers) >= 8192 OR dir_size doesn't
        // fit in u16 OR there are index entries.
        let use_extended = child_count >= 257
            || entry_byte_count >= METADATA_BLOCK_SIZE as u32
            || dir_size > 65535
            || !index_entries.is_empty();

        if use_extended {
            let hdr = InodeHeader {
                inode_type: INODE_EXT_DIR,
                permissions,
                uid_idx,
                gid_idx,
                mtime: 0,
                inode_number: inum,
            };
            let body = ExtDirInode {
                nlink,
                file_size: dir_size,
                start_block: dir_block_offset as u32,
                parent_inode,
                // On-disk i_count is the actual number of index entries
                // (mksquashfs stores the raw count, NOT count-1).
                i_count: index_entries.len() as u16,
                offset: dir_byte_offset,
                xattr_idx: NO_XATTR,
            };
            let mut buf = Vec::with_capacity(48);
            hdr.write_to(&mut buf).unwrap();
            body.write_to(&mut buf).unwrap();
            // Write directory index entries
            for (idx_entry, name) in index_entries.iter().zip(index_names.iter()) {
                idx_entry.write_to(&mut buf).unwrap();
                buf.extend_from_slice(name);
            }
            self.meta.write(&buf);
        } else {
            let hdr = InodeHeader {
                inode_type: INODE_BASIC_DIR,
                permissions,
                uid_idx,
                gid_idx,
                mtime: 0,
                inode_number: inum,
            };
            let body = BasicDirInode {
                start_block: dir_block_offset as u32,
                nlink,
                // On-disk value = actual_dir_data_bytes + 3.
                // Caller already includes the +3 in dir_size.
                file_size: dir_size as u16,
                offset: dir_byte_offset,
                parent_inode,
            };
            let mut buf = Vec::with_capacity(36);
            hdr.write_to(&mut buf).unwrap();
            body.write_to(&mut buf).unwrap();
            self.meta.write(&buf);
        }

        (inum, iref)
    }

    /// Add a symlink inode.
    ///
    /// Returns `(inode_number, inode_ref)`.
    pub fn add_symlink(
        &mut self,
        inum: u32,
        permissions: u16,
        uid_idx: u16,
        gid_idx: u16,
        target: &[u8],
        nlink: u32,
    ) -> (u32, InodeRef) {
        let (blk_off, byte_off) = self.meta.position();
        let iref = make_inode_ref(blk_off, byte_off);

        let hdr = InodeHeader {
            inode_type: INODE_BASIC_SYMLINK,
            permissions,
            uid_idx,
            gid_idx,
            mtime: 0,
            inode_number: inum,
        };
        let body = BasicSymlinkInode {
            nlink,
            symlink_size: target.len() as u32,
        };
        let mut buf = Vec::with_capacity(32 + target.len());
        hdr.write_to(&mut buf).unwrap();
        body.write_to(&mut buf).unwrap();
        buf.extend_from_slice(target);
        self.meta.write(&buf);

        (inum, iref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::NO_FRAGMENT;

    #[test]
    fn inode_numbering() {
        let mut table = InodeTable::new();
        let (n1, _) = table.add_symlink(1, 0o777, 0, 0, b"target", 1);
        let (n2, _) = table.add_symlink(2, 0o777, 0, 0, b"target2", 1);
        assert_eq!(n1, 1);
        assert_eq!(n2, 2);
    }

    #[test]
    fn hardlink_lookup() {
        let mut table = InodeTable::new();
        let (inum, iref) = table.add_file(1, 0o644, 0, 0, 100, 0, &[], NO_FRAGMENT, 0, 1, 0);
        table.register_hardlink(1, 42, inum, iref);
        assert_eq!(table.lookup_hardlink(1, 42), Some((inum, iref)));
        assert_eq!(table.lookup_hardlink(1, 99), None);
    }

    #[test]
    fn inode_ref_encoding() {
        let r = make_inode_ref(0x1000, 0x0040);
        assert_eq!(r, 0x1000_0040);
        assert_eq!(r >> 16, 0x1000);
        assert_eq!(r & 0xFFFF, 0x0040);
    }
}
