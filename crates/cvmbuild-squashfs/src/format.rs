/// On-disk squashfs 4.0 format constants and struct serialization.
///
/// All multi-byte values are little-endian. Structs serialize via explicit
/// `write_to()` methods to guarantee correct field order and padding.
use std::io::{self, Write};

// -- Magic and version --
pub const SQUASHFS_MAGIC: u32 = 0x7371_7368; // "hsqs" LE
pub const MAJOR_VERSION: u16 = 4;
pub const MINOR_VERSION: u16 = 0;

// -- Block sizes --
pub const DATA_BLOCK_SIZE: u32 = 131_072; // 128 KiB
pub const DATA_BLOCK_LOG: u16 = 17; // log2(131072)
pub const METADATA_BLOCK_SIZE: usize = 8192; // 8 KiB

// -- Compression IDs --
pub const ZSTD_COMPRESSION: u16 = 6;

// -- Bit flags for stored-size fields --
/// Data block: bit 24 set = block is stored uncompressed
pub const DATA_BLOCK_UNCOMPRESSED: u32 = 1 << 24;
/// Metadata block: bit 15 set = block is stored uncompressed
pub const META_BLOCK_UNCOMPRESSED: u16 = 1 << 15;

// -- Superblock flags --
pub const FLAG_NO_XATTRS: u16 = 0x0200;
pub const FLAG_EXPORTABLE: u16 = 0x0080;
pub const FLAG_NO_FRAG: u16 = 0x0010;
pub const FLAG_ALWAYS_FRAG: u16 = 0x0020;
pub const FLAG_DUPLICATES: u16 = 0x0040;

// -- Sentinel values --
pub const NO_FRAGMENT: u32 = 0xFFFF_FFFF;
pub const NO_XATTR: u32 = 0xFFFF_FFFF;
pub const INVALID_BLK: u64 = 0xFFFF_FFFF_FFFF_FFFF;

// -- Inode types --
pub const INODE_BASIC_DIR: u16 = 1;
pub const INODE_BASIC_FILE: u16 = 2;
pub const INODE_BASIC_SYMLINK: u16 = 3;
pub const INODE_EXT_DIR: u16 = 8;
pub const INODE_EXT_FILE: u16 = 9;
pub const INODE_EXT_SYMLINK: u16 = 10;

// -- Dir entry types (match inode types) --
pub const DIR_TYPE_DIR: u16 = 1;
pub const DIR_TYPE_FILE: u16 = 2;
pub const DIR_TYPE_SYMLINK: u16 = 3;

/// Superblock: 96 bytes on disk.
#[derive(Debug, Clone)]
pub struct Superblock {
    pub magic: u32,
    pub inode_count: u32,
    pub modification_time: u32,
    pub block_size: u32,
    pub fragment_entry_count: u32,
    pub compression_id: u16,
    pub block_log: u16,
    pub flags: u16,
    pub id_count: u16,
    pub version_major: u16,
    pub version_minor: u16,
    pub root_inode_ref: u64,
    pub bytes_used: u64,
    pub id_table_start: u64,
    pub xattr_id_table_start: u64,
    pub inode_table_start: u64,
    pub directory_table_start: u64,
    pub fragment_table_start: u64,
    pub lookup_table_start: u64,
}

impl Superblock {
    pub fn new() -> Self {
        Self {
            magic: SQUASHFS_MAGIC,
            inode_count: 0,
            modification_time: 0,
            block_size: DATA_BLOCK_SIZE,
            fragment_entry_count: 0,
            compression_id: ZSTD_COMPRESSION,
            block_log: DATA_BLOCK_LOG,
            flags: FLAG_NO_XATTRS | FLAG_DUPLICATES,
            id_count: 0,
            version_major: MAJOR_VERSION,
            version_minor: MINOR_VERSION,
            root_inode_ref: 0,
            bytes_used: 0,
            id_table_start: INVALID_BLK,
            xattr_id_table_start: INVALID_BLK,
            inode_table_start: 0,
            directory_table_start: 0,
            fragment_table_start: INVALID_BLK,
            lookup_table_start: INVALID_BLK,
        }
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.magic.to_le_bytes())?;
        w.write_all(&self.inode_count.to_le_bytes())?;
        w.write_all(&self.modification_time.to_le_bytes())?;
        w.write_all(&self.block_size.to_le_bytes())?;
        w.write_all(&self.fragment_entry_count.to_le_bytes())?;
        w.write_all(&self.compression_id.to_le_bytes())?;
        w.write_all(&self.block_log.to_le_bytes())?;
        w.write_all(&self.flags.to_le_bytes())?;
        w.write_all(&self.id_count.to_le_bytes())?;
        w.write_all(&self.version_major.to_le_bytes())?;
        w.write_all(&self.version_minor.to_le_bytes())?;
        w.write_all(&self.root_inode_ref.to_le_bytes())?;
        w.write_all(&self.bytes_used.to_le_bytes())?;
        w.write_all(&self.id_table_start.to_le_bytes())?;
        w.write_all(&self.xattr_id_table_start.to_le_bytes())?;
        w.write_all(&self.inode_table_start.to_le_bytes())?;
        w.write_all(&self.directory_table_start.to_le_bytes())?;
        w.write_all(&self.fragment_table_start.to_le_bytes())?;
        w.write_all(&self.lookup_table_start.to_le_bytes())?;
        Ok(())
    }

    pub const SIZE: usize = 96;
}

/// Common inode header: type + permissions + ids + timestamps.
/// Prepended to every inode variant.
#[derive(Debug, Clone)]
pub struct InodeHeader {
    pub inode_type: u16,
    pub permissions: u16,
    pub uid_idx: u16,
    pub gid_idx: u16,
    pub mtime: u32,
    pub inode_number: u32,
}

impl InodeHeader {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.inode_type.to_le_bytes())?;
        w.write_all(&self.permissions.to_le_bytes())?;
        w.write_all(&self.uid_idx.to_le_bytes())?;
        w.write_all(&self.gid_idx.to_le_bytes())?;
        w.write_all(&self.mtime.to_le_bytes())?;
        w.write_all(&self.inode_number.to_le_bytes())?;
        Ok(())
    }
}

/// Basic directory inode (type 1).
#[derive(Debug, Clone)]
pub struct BasicDirInode {
    pub start_block: u32,
    pub nlink: u32,
    pub file_size: u16,
    pub offset: u16,
    pub parent_inode: u32,
}

impl BasicDirInode {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.start_block.to_le_bytes())?;
        w.write_all(&self.nlink.to_le_bytes())?;
        w.write_all(&self.file_size.to_le_bytes())?;
        w.write_all(&self.offset.to_le_bytes())?;
        w.write_all(&self.parent_inode.to_le_bytes())?;
        Ok(())
    }
}

/// Extended directory inode (type 8).
#[derive(Debug, Clone)]
pub struct ExtDirInode {
    pub nlink: u32,
    pub file_size: u32,
    pub start_block: u32,
    pub parent_inode: u32,
    pub i_count: u16,
    pub offset: u16,
    pub xattr_idx: u32,
}

impl ExtDirInode {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.nlink.to_le_bytes())?;
        w.write_all(&self.file_size.to_le_bytes())?;
        w.write_all(&self.start_block.to_le_bytes())?;
        w.write_all(&self.parent_inode.to_le_bytes())?;
        w.write_all(&self.i_count.to_le_bytes())?;
        w.write_all(&self.offset.to_le_bytes())?;
        w.write_all(&self.xattr_idx.to_le_bytes())?;
        Ok(())
    }
}

/// Basic file inode (type 2).
/// Used when file_size < 2^32 and nlink == 1 and no sparse/xattr.
#[derive(Debug, Clone)]
pub struct BasicFileInode {
    pub start_block: u32,
    pub fragment: u32,
    pub offset: u32,
    pub file_size: u32,
    // followed by block_sizes: [u32; N]
}

impl BasicFileInode {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.start_block.to_le_bytes())?;
        w.write_all(&self.fragment.to_le_bytes())?;
        w.write_all(&self.offset.to_le_bytes())?;
        w.write_all(&self.file_size.to_le_bytes())?;
        Ok(())
    }
}

/// Extended file inode (type 9).
/// Used when file_size >= 2^32 or nlink > 1.
#[derive(Debug, Clone)]
pub struct ExtFileInode {
    pub start_block: u64,
    pub file_size: u64,
    pub sparse: u64,
    pub nlink: u32,
    pub fragment: u32,
    pub offset: u32,
    pub xattr_idx: u32,
    // followed by block_sizes: [u32; N]
}

impl ExtFileInode {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.start_block.to_le_bytes())?;
        w.write_all(&self.file_size.to_le_bytes())?;
        w.write_all(&self.sparse.to_le_bytes())?;
        w.write_all(&self.nlink.to_le_bytes())?;
        w.write_all(&self.fragment.to_le_bytes())?;
        w.write_all(&self.offset.to_le_bytes())?;
        w.write_all(&self.xattr_idx.to_le_bytes())?;
        Ok(())
    }
}

/// Basic symlink inode (type 3).
#[derive(Debug, Clone)]
pub struct BasicSymlinkInode {
    pub nlink: u32,
    pub symlink_size: u32,
    // followed by target path bytes
}

impl BasicSymlinkInode {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.nlink.to_le_bytes())?;
        w.write_all(&self.symlink_size.to_le_bytes())?;
        Ok(())
    }
}

/// Directory table header. Groups up to 256 entries that share
/// a common metadata block reference.
#[derive(Debug, Clone)]
pub struct DirHeader {
    /// Number of entries following this header, minus 1.
    pub count: u32,
    /// Byte offset of the metadata block (from inode_table_start)
    /// where the inodes in this group live.
    pub start_block: u32,
    /// Base inode number — entries store delta from this.
    pub inode_number: u32,
}

impl DirHeader {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.count.to_le_bytes())?;
        w.write_all(&self.start_block.to_le_bytes())?;
        w.write_all(&self.inode_number.to_le_bytes())?;
        Ok(())
    }
}

/// Directory table entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Offset within the uncompressed metadata block.
    pub offset: u16,
    /// inode_number - base_inode_number (signed).
    pub inode_delta: i16,
    /// Entry type (1=dir, 2=file, 3=symlink).
    pub entry_type: u16,
    /// Length of the name, minus 1.
    pub name_size: u16,
    // followed by name bytes
}

impl DirEntry {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.offset.to_le_bytes())?;
        w.write_all(&self.inode_delta.to_le_bytes())?;
        w.write_all(&self.entry_type.to_le_bytes())?;
        w.write_all(&self.name_size.to_le_bytes())?;
        Ok(())
    }
}

/// Directory index entry (stored after ExtDirInode in the inode table).
///
/// Allows the kernel to skip to the right metadata block when searching
/// a large directory. One entry per metadata block boundary crossed.
#[derive(Debug, Clone)]
pub struct DirIndexEntry {
    /// Cumulative byte offset in the uncompressed directory data where
    /// this metadata block starts.
    pub index: u32,
    /// Compressed byte offset of the metadata block (relative to dir table start).
    pub start_block: u32,
    /// Length of `name` minus 1.
    pub name_size: u32,
    // followed by `name` bytes (name_size + 1 bytes)
}

impl DirIndexEntry {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.index.to_le_bytes())?;
        w.write_all(&self.start_block.to_le_bytes())?;
        w.write_all(&self.name_size.to_le_bytes())?;
        Ok(())
    }
}

/// Fragment table entry: describes one compressed fragment block on disk.
#[derive(Debug, Clone)]
pub struct FragmentEntry {
    /// Byte offset of the compressed fragment block in the file.
    pub start: u64,
    /// Size of the compressed block. Bit 24 = uncompressed.
    pub size: u32,
    /// Unused, must be 0.
    pub unused: u32,
}

impl FragmentEntry {
    pub const SIZE: usize = 16;

    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.start.to_le_bytes())?;
        w.write_all(&self.size.to_le_bytes())?;
        w.write_all(&self.unused.to_le_bytes())?;
        Ok(())
    }
}
