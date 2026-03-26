/// Squashfs 4.0 reader.
///
/// Reads a squashfs image, parses the superblock, inode table, directory
/// table, fragment table, and ID table. Supports extracting file contents,
/// listing directories, and reading symlink targets.
use std::collections::HashMap;
use std::io::{self, Cursor, Read};

use anyhow::{bail, ensure, Context, Result};

use crate::format::*;

/// Parsed superblock information.
#[derive(Debug, Clone)]
pub struct SuperblockInfo {
    pub inode_count: u32,
    pub modification_time: u32,
    pub block_size: u32,
    pub block_log: u16,
    pub fragment_entry_count: u32,
    pub compression_id: u16,
    pub flags: u16,
    pub id_count: u16,
    pub root_inode_ref: u64,
    pub bytes_used: u64,
    pub inode_table_start: u64,
    pub directory_table_start: u64,
    pub fragment_table_start: u64,
    pub id_table_start: u64,
    pub xattr_id_table_start: u64,
    pub lookup_table_start: u64,
}

/// A parsed inode.
#[derive(Debug, Clone)]
pub enum Inode {
    File(FileInode),
    Dir(DirInode),
    Symlink(SymlinkInode),
}

#[derive(Debug, Clone)]
pub struct FileInode {
    pub inode_number: u32,
    pub permissions: u16,
    pub uid_idx: u16,
    pub gid_idx: u16,
    pub file_size: u64,
    pub start_block: u64,
    pub fragment: u32,
    pub fragment_offset: u32,
    pub nlink: u32,
    pub block_sizes: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct DirInode {
    pub inode_number: u32,
    pub permissions: u16,
    pub uid_idx: u16,
    pub gid_idx: u16,
    pub nlink: u32,
    pub file_size: u32,
    pub start_block: u32,
    pub offset: u16,
    pub parent_inode: u32,
}

#[derive(Debug, Clone)]
pub struct SymlinkInode {
    pub inode_number: u32,
    pub permissions: u16,
    pub uid_idx: u16,
    pub gid_idx: u16,
    pub nlink: u32,
    pub target: String,
}

/// A directory entry as read from the directory table.
#[derive(Debug, Clone)]
pub struct DirEntryInfo {
    pub name: String,
    pub inode_number: u32,
    pub inode_ref: u64,
    pub entry_type: u16,
}

/// Squashfs reader.
pub struct SquashfsReader {
    data: Vec<u8>,
    pub sb: SuperblockInfo,
    ids: Vec<u32>,
    fragments: Vec<ParsedFragment>,
}

#[derive(Debug, Clone)]
struct ParsedFragment {
    start: u64,
    size: u32,
}

impl SquashfsReader {
    /// Open a squashfs image from a byte slice.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        ensure!(
            data.len() >= Superblock::SIZE,
            "file too small for superblock"
        );

        let sb = parse_superblock(&data)?;
        let ids = read_id_table(&data, &sb)?;
        let fragments = read_fragment_table(&data, &sb)?;

        Ok(Self {
            data,
            sb,
            ids,
            fragments,
        })
    }

    /// Open a squashfs image from a file path.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let data = std::fs::read(path).context("read squashfs file")?;
        Self::from_bytes(data)
    }

    /// Get the ID (uid or gid) at the given index.
    pub fn get_id(&self, idx: u16) -> Result<u32> {
        self.ids
            .get(idx as usize)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("ID index {idx} out of range"))
    }

    /// Read the root directory inode.
    pub fn root_inode(&self) -> Result<Inode> {
        self.read_inode(self.sb.root_inode_ref)
    }

    /// Read an inode at the given reference.
    pub fn read_inode(&self, inode_ref: u64) -> Result<Inode> {
        let block_offset = inode_ref >> 16;
        let byte_offset = (inode_ref & 0xFFFF) as usize;

        let abs_offset = self.sb.inode_table_start + block_offset;
        let mut reader = MetadataReader::new(&self.data, abs_offset);
        reader.skip(byte_offset)?;

        // Read base header
        let inode_type = reader.read_u16()?;
        let permissions = reader.read_u16()?;
        let uid_idx = reader.read_u16()?;
        let gid_idx = reader.read_u16()?;
        let _mtime = reader.read_u32()?;
        let inode_number = reader.read_u32()?;

        match inode_type {
            INODE_BASIC_DIR => {
                let start_block = reader.read_u32()?;
                let nlink = reader.read_u32()?;
                let file_size = reader.read_u16()? as u32;
                let offset = reader.read_u16()?;
                let parent_inode = reader.read_u32()?;
                Ok(Inode::Dir(DirInode {
                    inode_number,
                    permissions,
                    uid_idx,
                    gid_idx,
                    nlink,
                    file_size,
                    start_block,
                    offset,
                    parent_inode,
                }))
            }
            INODE_EXT_DIR => {
                let nlink = reader.read_u32()?;
                let file_size = reader.read_u32()?;
                let start_block = reader.read_u32()?;
                let parent_inode = reader.read_u32()?;
                let _i_count = reader.read_u16()?;
                let offset = reader.read_u16()?;
                let _xattr_idx = reader.read_u32()?;
                Ok(Inode::Dir(DirInode {
                    inode_number,
                    permissions,
                    uid_idx,
                    gid_idx,
                    nlink,
                    file_size,
                    start_block,
                    offset,
                    parent_inode,
                }))
            }
            INODE_BASIC_FILE => {
                let start_block = reader.read_u32()? as u64;
                let fragment = reader.read_u32()?;
                let fragment_offset = reader.read_u32()?;
                let file_size = reader.read_u32()? as u64;

                let block_count = if fragment != NO_FRAGMENT {
                    file_size / self.sb.block_size as u64
                } else {
                    file_size.div_ceil(self.sb.block_size as u64)
                };

                let mut block_sizes = Vec::with_capacity(block_count as usize);
                for _ in 0..block_count {
                    block_sizes.push(reader.read_u32()?);
                }

                Ok(Inode::File(FileInode {
                    inode_number,
                    permissions,
                    uid_idx,
                    gid_idx,
                    file_size,
                    start_block,
                    fragment,
                    fragment_offset,
                    nlink: 1,
                    block_sizes,
                }))
            }
            INODE_EXT_FILE => {
                let start_block = reader.read_u64()?;
                let file_size = reader.read_u64()?;
                let _sparse = reader.read_u64()?;
                let nlink = reader.read_u32()?;
                let fragment = reader.read_u32()?;
                let fragment_offset = reader.read_u32()?;
                let _xattr_idx = reader.read_u32()?;

                let block_count = if fragment != NO_FRAGMENT {
                    file_size / self.sb.block_size as u64
                } else {
                    file_size.div_ceil(self.sb.block_size as u64)
                };

                let mut block_sizes = Vec::with_capacity(block_count as usize);
                for _ in 0..block_count {
                    block_sizes.push(reader.read_u32()?);
                }

                Ok(Inode::File(FileInode {
                    inode_number,
                    permissions,
                    uid_idx,
                    gid_idx,
                    file_size,
                    start_block,
                    fragment,
                    fragment_offset,
                    nlink,
                    block_sizes,
                }))
            }
            INODE_BASIC_SYMLINK => {
                let nlink = reader.read_u32()?;
                let symlink_size = reader.read_u32()?;
                let mut target_bytes = vec![0u8; symlink_size as usize];
                reader.read_exact(&mut target_bytes)?;
                let target = String::from_utf8_lossy(&target_bytes).into_owned();
                Ok(Inode::Symlink(SymlinkInode {
                    inode_number,
                    permissions,
                    uid_idx,
                    gid_idx,
                    nlink,
                    target,
                }))
            }
            INODE_EXT_SYMLINK => {
                let nlink = reader.read_u32()?;
                let symlink_size = reader.read_u32()?;
                let mut target_bytes = vec![0u8; symlink_size as usize];
                reader.read_exact(&mut target_bytes)?;
                // Extended symlink has xattr after the target
                let _xattr_idx = reader.read_u32()?;
                let target = String::from_utf8_lossy(&target_bytes).into_owned();
                Ok(Inode::Symlink(SymlinkInode {
                    inode_number,
                    permissions,
                    uid_idx,
                    gid_idx,
                    nlink,
                    target,
                }))
            }
            _ => bail!("unsupported inode type {inode_type}"),
        }
    }

    /// Read directory entries for a directory inode.
    pub fn read_dir(&self, dir: &DirInode) -> Result<Vec<DirEntryInfo>> {
        let abs_offset = self.sb.directory_table_start + dir.start_block as u64;
        let mut reader = MetadataReader::new(&self.data, abs_offset);
        reader.skip(dir.offset as usize)?;

        let mut entries = Vec::new();
        let mut bytes_read: u32 = 0;
        // file_size includes the +3 offset; actual data = file_size - 3
        let data_size = dir.file_size.saturating_sub(3);

        while bytes_read < data_size {
            // Read directory header
            let count = reader.read_u32()?;
            let start_block = reader.read_u32()?;
            let base_inode = reader.read_u32()?;
            bytes_read += 12;

            let entry_count = count + 1;
            for _ in 0..entry_count {
                let offset = reader.read_u16()?;
                let inode_delta = reader.read_i16()?;
                let entry_type = reader.read_u16()?;
                let name_size = reader.read_u16()?;
                let name_len = name_size as usize + 1;

                let mut name_bytes = vec![0u8; name_len];
                reader.read_exact(&mut name_bytes)?;
                bytes_read += 8 + name_len as u32;

                let inode_number = (base_inode as i64 + inode_delta as i64) as u32;
                let inode_ref = ((start_block as u64) << 16) | offset as u64;

                entries.push(DirEntryInfo {
                    name: String::from_utf8_lossy(&name_bytes).into_owned(),
                    inode_number,
                    inode_ref,
                    entry_type,
                });
            }
        }

        Ok(entries)
    }

    /// Read file data for a file inode.
    pub fn read_file(&self, file: &FileInode) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(file.file_size as usize);
        let block_size = self.sb.block_size as usize;

        // Read full data blocks
        let mut current_offset = file.start_block;
        for &stored_size in &file.block_sizes {
            let is_uncompressed = stored_size & DATA_BLOCK_UNCOMPRESSED != 0;
            let size = (stored_size & !DATA_BLOCK_UNCOMPRESSED) as usize;

            if size == 0 {
                // Sparse block
                result.resize(result.len() + block_size, 0);
                continue;
            }

            let block_data = &self.data[current_offset as usize..current_offset as usize + size];

            if is_uncompressed {
                result.extend_from_slice(block_data);
            } else {
                let decompressed = zstd::bulk::decompress(block_data, block_size)
                    .context("decompress data block")?;
                result.extend_from_slice(&decompressed);
            }
            current_offset += size as u64;
        }

        // Read fragment tail
        if file.fragment != NO_FRAGMENT {
            let frag = self
                .fragments
                .get(file.fragment as usize)
                .ok_or_else(|| anyhow::anyhow!("fragment index {} out of range", file.fragment))?;

            let is_uncompressed = frag.size & DATA_BLOCK_UNCOMPRESSED != 0;
            let frag_stored_size = (frag.size & !DATA_BLOCK_UNCOMPRESSED) as usize;
            let frag_block =
                &self.data[frag.start as usize..frag.start as usize + frag_stored_size];

            let decompressed = if is_uncompressed {
                frag_block.to_vec()
            } else {
                zstd::bulk::decompress(frag_block, self.sb.block_size as usize)
                    .context("decompress fragment block")?
            };

            let tail_size = (file.file_size as usize) - result.len();
            let offset = file.fragment_offset as usize;
            ensure!(
                offset + tail_size <= decompressed.len(),
                "fragment offset+size exceeds decompressed fragment block"
            );
            result.extend_from_slice(&decompressed[offset..offset + tail_size]);
        }

        ensure!(
            result.len() == file.file_size as usize,
            "read {} bytes but expected {}",
            result.len(),
            file.file_size
        );

        Ok(result)
    }

    /// Walk the entire filesystem tree, calling the callback for each entry.
    /// Callback receives (path, inode).
    pub fn walk<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(&str, &Inode) -> Result<()>,
    {
        let root = self.root_inode()?;
        callback("/", &root)?;
        if let Inode::Dir(ref dir) = root {
            self.walk_dir(dir, "/", &mut callback)?;
        }
        Ok(())
    }

    fn walk_dir<F>(&self, dir: &DirInode, path: &str, callback: &mut F) -> Result<()>
    where
        F: FnMut(&str, &Inode) -> Result<()>,
    {
        let entries = self.read_dir(dir)?;
        for entry in &entries {
            let child_path = if path == "/" {
                format!("/{}", entry.name)
            } else {
                format!("{}/{}", path, entry.name)
            };

            let inode = self.read_inode(entry.inode_ref)?;
            callback(&child_path, &inode)?;

            if let Inode::Dir(ref child_dir) = inode {
                self.walk_dir(child_dir, &child_path, callback)?;
            }
        }
        Ok(())
    }

    /// List all files in the image with their paths. Returns (path, inode_type, size).
    pub fn list_all(&self) -> Result<Vec<(String, &'static str, u64)>> {
        let mut result = Vec::new();
        self.walk(|path, inode| {
            match inode {
                Inode::File(f) => result.push((path.to_string(), "file", f.file_size)),
                Inode::Dir(_) => result.push((path.to_string(), "dir", 0)),
                Inode::Symlink(s) => {
                    result.push((path.to_string(), "symlink", s.target.len() as u64))
                }
            }
            Ok(())
        })?;
        Ok(result)
    }

    /// Verify the image: read all inodes, all file data, check consistency.
    /// Returns the number of files successfully read.
    pub fn verify(&self) -> Result<u32> {
        let mut file_count = 0u32;
        let mut seen_inodes: HashMap<u32, String> = HashMap::new();

        self.walk(|path, inode| {
            match inode {
                Inode::File(f) => {
                    if seen_inodes.contains_key(&f.inode_number) {
                        // Hard link — skip reading data again
                        file_count += 1;
                        return Ok(());
                    }
                    let data = self
                        .read_file(f)
                        .with_context(|| format!("read file {path}"))?;
                    ensure!(
                        data.len() == f.file_size as usize,
                        "size mismatch for {path}: got {} expected {}",
                        data.len(),
                        f.file_size
                    );
                    seen_inodes.insert(f.inode_number, path.to_string());
                    file_count += 1;
                }
                Inode::Dir(_) => {}
                Inode::Symlink(s) => {
                    ensure!(!s.target.is_empty(), "empty symlink target for {path}");
                }
            }
            Ok(())
        })?;

        Ok(file_count)
    }
}

// -- Superblock parsing --

fn parse_superblock(data: &[u8]) -> Result<SuperblockInfo> {
    let mut c = Cursor::new(data);
    let magic = read_u32(&mut c)?;
    ensure!(magic == SQUASHFS_MAGIC, "bad magic: 0x{magic:08x}");

    let inode_count = read_u32(&mut c)?;
    let modification_time = read_u32(&mut c)?;
    let block_size = read_u32(&mut c)?;
    let fragment_entry_count = read_u32(&mut c)?;
    let compression_id = read_u16(&mut c)?;
    let block_log = read_u16(&mut c)?;
    let flags = read_u16(&mut c)?;
    let id_count = read_u16(&mut c)?;
    let version_major = read_u16(&mut c)?;
    let version_minor = read_u16(&mut c)?;

    ensure!(
        version_major == 4,
        "unsupported major version {version_major}"
    );
    ensure!(
        version_minor == 0,
        "unsupported minor version {version_minor}"
    );
    ensure!(
        block_size == (1u32 << block_log),
        "block_size/block_log mismatch"
    );
    ensure!(
        compression_id == ZSTD_COMPRESSION,
        "only zstd compression supported, got {compression_id}"
    );

    let root_inode_ref = read_u64(&mut c)?;
    let bytes_used = read_u64(&mut c)?;
    let id_table_start = read_u64(&mut c)?;
    let xattr_id_table_start = read_u64(&mut c)?;
    let inode_table_start = read_u64(&mut c)?;
    let directory_table_start = read_u64(&mut c)?;
    let fragment_table_start = read_u64(&mut c)?;
    let lookup_table_start = read_u64(&mut c)?;

    ensure!(
        inode_table_start < directory_table_start,
        "inode table must precede directory table"
    );
    ensure!(id_count > 0, "must have at least one ID entry");

    Ok(SuperblockInfo {
        inode_count,
        modification_time,
        block_size,
        block_log,
        fragment_entry_count,
        compression_id,
        flags,
        id_count,
        root_inode_ref,
        bytes_used,
        inode_table_start,
        directory_table_start,
        fragment_table_start,
        id_table_start,
        xattr_id_table_start,
        lookup_table_start,
    })
}

// -- Lookup table reading (used by ID table and fragment table) --

/// Read a two-level lookup table: u64 offsets → metadata blocks → entries.
fn read_lookup_table(
    data: &[u8],
    table_start: u64,
    entry_count: u32,
    entry_size: usize,
) -> Result<Vec<u8>> {
    if entry_count == 0 {
        return Ok(Vec::new());
    }

    let total_bytes = entry_count as usize * entry_size;
    let entries_per_block = METADATA_BLOCK_SIZE / entry_size;
    let block_count = (entry_count as usize).div_ceil(entries_per_block);

    // Read u64 offsets
    let mut offsets = Vec::with_capacity(block_count);
    let offset_start = table_start as usize;
    for i in 0..block_count {
        let pos = offset_start + i * 8;
        ensure!(pos + 8 <= data.len(), "lookup table offset out of bounds");
        let off = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        offsets.push(off);
    }

    // Read metadata blocks
    let mut result = Vec::with_capacity(total_bytes);
    for &offset in &offsets {
        let block = read_metadata_block(data, offset as usize)?;
        result.extend_from_slice(&block);
    }

    result.truncate(total_bytes);
    Ok(result)
}

fn read_id_table(data: &[u8], sb: &SuperblockInfo) -> Result<Vec<u32>> {
    let raw = read_lookup_table(data, sb.id_table_start, sb.id_count as u32, 4)?;
    let mut ids = Vec::with_capacity(sb.id_count as usize);
    for chunk in raw.chunks_exact(4) {
        ids.push(u32::from_le_bytes(chunk.try_into().unwrap()));
    }
    Ok(ids)
}

fn read_fragment_table(data: &[u8], sb: &SuperblockInfo) -> Result<Vec<ParsedFragment>> {
    if sb.fragment_table_start == INVALID_BLK || sb.fragment_entry_count == 0 {
        return Ok(Vec::new());
    }
    let raw = read_lookup_table(
        data,
        sb.fragment_table_start,
        sb.fragment_entry_count,
        FragmentEntry::SIZE,
    )?;
    let mut frags = Vec::with_capacity(sb.fragment_entry_count as usize);
    for chunk in raw.chunks_exact(FragmentEntry::SIZE) {
        let start = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let size = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        frags.push(ParsedFragment { start, size });
    }
    Ok(frags)
}

// -- Metadata block reading --

/// Read and decompress a single metadata block at the given byte offset.
/// Returns the uncompressed data.
fn read_metadata_block(data: &[u8], offset: usize) -> Result<Vec<u8>> {
    ensure!(
        offset + 2 <= data.len(),
        "metadata block header at {offset} out of bounds"
    );
    let header = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
    let is_uncompressed = header & META_BLOCK_UNCOMPRESSED != 0;
    let stored_size = (header & !META_BLOCK_UNCOMPRESSED) as usize;

    let block_start = offset + 2;
    ensure!(
        block_start + stored_size <= data.len(),
        "metadata block data at {offset} (size {stored_size}) out of bounds"
    );

    let block_data = &data[block_start..block_start + stored_size];

    if is_uncompressed {
        Ok(block_data.to_vec())
    } else {
        zstd::bulk::decompress(block_data, METADATA_BLOCK_SIZE).context("decompress metadata block")
    }
}

/// A streaming metadata reader that transparently handles block boundaries.
struct MetadataReader<'a> {
    data: &'a [u8],
    /// Current byte position in the image (at a block header or past end).
    block_pos: usize,
    /// Uncompressed data of the current block.
    block_data: Vec<u8>,
    /// Read offset within block_data.
    offset: usize,
}

impl<'a> MetadataReader<'a> {
    fn new(data: &'a [u8], start_offset: u64) -> Self {
        Self {
            data,
            block_pos: start_offset as usize,
            block_data: Vec::new(),
            offset: 0,
        }
    }

    /// Ensure we have a loaded block and enough data at the current offset.
    fn ensure_loaded(&mut self) -> Result<()> {
        if self.offset < self.block_data.len() {
            return Ok(());
        }
        // Load next block
        if self.block_data.is_empty() {
            // First load — read the block at block_pos
            self.block_data = read_metadata_block(self.data, self.block_pos)?;
            let header = u16::from_le_bytes(
                self.data[self.block_pos..self.block_pos + 2]
                    .try_into()
                    .unwrap(),
            );
            let stored = (header & !META_BLOCK_UNCOMPRESSED) as usize;
            self.block_pos += 2 + stored;
        } else {
            // Advance to next block
            self.block_data = read_metadata_block(self.data, self.block_pos)?;
            let header = u16::from_le_bytes(
                self.data[self.block_pos..self.block_pos + 2]
                    .try_into()
                    .unwrap(),
            );
            let stored = (header & !META_BLOCK_UNCOMPRESSED) as usize;
            self.block_pos += 2 + stored;
        }
        self.offset = 0;
        Ok(())
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        let mut remaining = n;
        while remaining > 0 {
            self.ensure_loaded()?;
            let available = self.block_data.len() - self.offset;
            let to_skip = remaining.min(available);
            self.offset += to_skip;
            remaining -= to_skip;
        }
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut written = 0;
        while written < buf.len() {
            self.ensure_loaded()?;
            let available = self.block_data.len() - self.offset;
            let to_read = (buf.len() - written).min(available);
            buf[written..written + to_read]
                .copy_from_slice(&self.block_data[self.offset..self.offset + to_read]);
            self.offset += to_read;
            written += to_read;
        }
        Ok(())
    }

    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_i16(&mut self) -> Result<i16> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        Ok(i16::from_le_bytes(buf))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

// -- Helpers --

fn read_u16<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_superblock_validates_magic() {
        let data = vec![0u8; 96];
        let err = parse_superblock(&data).unwrap_err();
        assert!(err.to_string().contains("bad magic"));
    }
}
