#![allow(clippy::new_without_default)]
//! Standalone pure-Rust squashfs 4.0 writer and reader.
//!
//! Produces and reads squashfs images. Supports regular files,
//! directories, symlinks, and hard links with zstd compression.
//!
//! The output is byte-identical to `mksquashfs` when called with:
//! ```bash
//! mksquashfs <rootfs> <output> -comp zstd -b 131072 -all-root -noappend -no-xattrs -mkfs-time 0 -all-time 0
//! ```
//!
//! # Example
//! ```no_run
//! let hash = cvmbuild_squashfs::create_squashfs(
//!     std::path::Path::new("/my/rootfs"),
//!     std::path::Path::new("/tmp/output.squashfs"),
//! ).unwrap();
//! println!("SHA256: {hash}");
//!
//! // Read it back
//! let reader = cvmbuild_squashfs::reader::SquashfsReader::open(
//!     std::path::Path::new("/tmp/output.squashfs"),
//! ).unwrap();
//! let files = reader.verify().unwrap();
//! println!("verified {files} files");
//! ```

pub mod directory;
pub mod format;
pub mod fragment;
pub mod inode;
pub mod reader;
pub mod writer;

use std::collections::HashMap;
use std::fs;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::directory::{DirChild, DirectoryTable};
use crate::format::{
    Superblock, DATA_BLOCK_SIZE, DIR_TYPE_DIR, DIR_TYPE_FILE, DIR_TYPE_SYMLINK, FLAG_DUPLICATES,
    FLAG_EXPORTABLE, FLAG_NO_XATTRS, METADATA_BLOCK_SIZE, META_BLOCK_UNCOMPRESSED, NO_FRAGMENT,
};
use crate::fragment::FragmentTable;
use crate::inode::InodeTable;
use crate::writer::{compress_files_parallel, write_compressed_file};

const ZSTD_LEVEL: i32 = 3;

/// File data info collected during data block writing phase.
struct FileDataInfo {
    file_size: u64,
    start_block: u64,
    block_sizes: Vec<u32>,
    frag_idx: u32,
    frag_offset: u32,
    sparse: u64,
}

/// Create a squashfs 4.0 image from a directory tree.
///
/// All files are owned by uid=0/gid=0 with mtime=0 for reproducibility.
/// Output is byte-identical to mksquashfs with equivalent options.
/// Returns the SHA-256 hex digest of the output file.
pub fn create_squashfs(rootfs: &Path, output: &Path) -> Result<String> {
    let file = fs::File::create(output).context("create output file")?;
    let mut out = BufWriter::new(file);

    // Phase 0: Scan the filesystem tree (sorted by name at each level)
    let tree = scan_tree(rootfs)?;

    // Phase 1: Assign inode numbers in mksquashfs order.
    // DFS traversal, name-sorted: files/symlinks get numbers as encountered,
    // directories get numbers after their entire subtree, root is last.
    let mut next_inum = 1u32;
    let mut inode_numbers: HashMap<usize, u32> = HashMap::new();
    let mut hl_inum_map: HashMap<(u64, u64), u32> = HashMap::new();
    assign_inode_numbers_dfs(
        &tree,
        tree.root,
        &mut next_inum,
        &mut inode_numbers,
        &mut hl_inum_map,
    );
    // Root directory gets the last inode number
    inode_numbers.insert(tree.root, next_inum);
    next_inum += 1;
    let total_inodes = next_inum - 1;

    // Write placeholder superblock (96 bytes)
    let mut sb = Superblock::new();
    sb.write_to(&mut out)?;

    // Phase 2: Write data blocks + fragments.
    // Step 1: DFS walk to collect files needing data blocks (with dedup).
    // Step 2: Parallel zstd compression of all data blocks.
    // Step 3: Sequential write to output + fragment handling.
    let mut frag_table = FragmentTable::new();
    let mut file_data: HashMap<usize, FileDataInfo> = HashMap::new();
    let mut hl_data_first: HashMap<(u64, u64), usize> = HashMap::new();
    let mut dedup_map: HashMap<(u64, [u8; 32]), usize> = HashMap::new();

    // Step 1: Collect files in DFS order
    let mut data_files: Vec<(usize, DataFileEntry)> = Vec::new();
    // Maps child_idx → first_idx for content-dedup copies
    let mut dedup_copies: Vec<(usize, usize, u64)> = Vec::new();
    collect_data_files_dfs(
        &tree,
        tree.root,
        &mut data_files,
        &mut dedup_copies,
        &mut hl_data_first,
        &mut dedup_map,
    );

    // Step 2: Parallel compression of all data blocks
    let to_compress: Vec<(usize, &[u8])> = data_files
        .iter()
        .map(|(child_idx, entry)| (*child_idx, entry.data.as_slice()))
        .collect();
    let compressed = compress_files_parallel(&to_compress);

    // Step 3: Sequential write + fragment handling
    for (i, (child_idx, entry)) in data_files.iter().enumerate() {
        let block_size = DATA_BLOCK_SIZE as usize;
        let file_size = entry.data.len() as u64;

        let (start_block, block_sizes) = if entry.has_full_blocks {
            write_compressed_file(&compressed[i], &mut out)?
        } else {
            (0, vec![])
        };

        let tail = &entry.data[entry.full_blocks_len..];
        let (frag_idx, frag_offset) = if !entry.has_full_blocks && !tail.is_empty() {
            frag_table.add_fragment(tail, &mut out)?
        } else {
            (NO_FRAGMENT, 0)
        };

        let sparse = block_sizes
            .iter()
            .enumerate()
            .filter(|&(_, &sz)| sz == 0)
            .map(|(bi, _)| {
                if bi < block_sizes.len() - 1 {
                    block_size as u64
                } else {
                    file_size - (bi as u64 * block_size as u64)
                }
            })
            .sum::<u64>();

        file_data.insert(
            *child_idx,
            FileDataInfo {
                file_size,
                start_block,
                block_sizes,
                frag_idx,
                frag_offset,
                sparse,
            },
        );
    }

    // Resolve content-dedup copies now that originals are written
    for (child_idx, first_idx, file_size) in &dedup_copies {
        let first_info = file_data.get(first_idx).unwrap();
        file_data.insert(
            *child_idx,
            FileDataInfo {
                file_size: *file_size,
                start_block: first_info.start_block,
                block_sizes: first_info.block_sizes.clone(),
                frag_idx: first_info.frag_idx,
                frag_offset: first_info.frag_offset,
                sparse: first_info.sparse,
            },
        );
    }

    frag_table.finish(&mut out)?;

    // Phase 3: Write inode table + directory table in DFS order.
    // For each directory: process children (files write inodes, dirs recurse),
    // then write dir entries, then write dir inode.
    let mut inode_table = InodeTable::new();
    let mut dir_table = DirectoryTable::new();
    let mut export_refs = vec![0u64; total_inodes as usize];
    let mut hl_iref_map: HashMap<(u64, u64), (u32, u64)> = HashMap::new();

    let (_root_inum, root_iref) = write_tables_dfs(
        &tree,
        tree.root,
        &inode_numbers,
        &mut inode_table,
        &mut dir_table,
        &file_data,
        &hl_data_first,
        &mut hl_iref_map,
        0,
        0, // uid_idx, gid_idx (all root)
        &mut export_refs,
    )?;

    sb.root_inode_ref = root_iref;

    // Write inode table to output
    sb.inode_table_start = inode_table.meta.finish(&mut out)?;

    // Write directory table to output
    sb.directory_table_start = dir_table.meta.finish(&mut out)?;

    // Write fragment table (always write, even when empty — matches mksquashfs)
    sb.fragment_table_start = frag_table.write_table(&mut out)?;
    sb.fragment_entry_count = frag_table.count();

    // Write export table (inode_number → inode_ref lookup)
    sb.lookup_table_start = write_export_table(&export_refs, &mut out)?;

    // Write ID table (all entries uid=0/gid=0)
    let id_table = vec![0u32];
    sb.id_table_start = write_id_table(&id_table, &mut out)?;
    sb.id_count = id_table.len() as u16;

    // Finalize superblock
    sb.inode_count = total_inodes;
    sb.flags = FLAG_NO_XATTRS | FLAG_DUPLICATES | FLAG_EXPORTABLE;
    sb.bytes_used = out.stream_position()?;

    // Pad to 4096-byte boundary (mksquashfs does this)
    let pos = sb.bytes_used;
    let padded = (pos + 4095) & !4095;
    if padded > pos {
        let padding = vec![0u8; (padded - pos) as usize];
        out.write_all(&padding)?;
    }

    // Seek back and write final superblock with all offsets
    out.seek(SeekFrom::Start(0))?;
    sb.write_to(&mut out)?;

    out.flush()?;
    drop(out);

    // Compute SHA-256
    sha256_file(output)
}

/// Assign inode numbers in mksquashfs DFS order.
///
/// For each directory's children (sorted by name):
/// - Files and symlinks get the next number immediately
/// - Directories recurse first (subtree numbered), then get their number
///
/// Hard-linked files share the first occurrence's number.
fn assign_inode_numbers_dfs(
    tree: &ScannedTree,
    dir_idx: usize,
    next: &mut u32,
    numbers: &mut HashMap<usize, u32>,
    hl_map: &mut HashMap<(u64, u64), u32>,
) {
    let children = match &tree.nodes[dir_idx].kind {
        NodeKind::Directory { children } => children,
        _ => return,
    };

    for &child_idx in children {
        let child = &tree.nodes[child_idx];
        match &child.kind {
            NodeKind::File { nlink, .. } => {
                if *nlink > 1 {
                    if let Some(&existing) = hl_map.get(&(child.host_dev, child.host_ino)) {
                        numbers.insert(child_idx, existing);
                        continue;
                    }
                }
                let inum = *next;
                *next += 1;
                numbers.insert(child_idx, inum);
                if *nlink > 1 {
                    hl_map.insert((child.host_dev, child.host_ino), inum);
                }
            }
            NodeKind::Symlink { .. } => {
                numbers.insert(child_idx, *next);
                *next += 1;
            }
            NodeKind::Directory { .. } => {
                // Directory gets its number BEFORE recursing (matches mksquashfs)
                numbers.insert(child_idx, *next);
                *next += 1;
                assign_inode_numbers_dfs(tree, child_idx, next, numbers, hl_map);
            }
        }
    }
}

/// A file collected during DFS walk, ready for parallel compression.
struct DataFileEntry {
    data: Vec<u8>,
    has_full_blocks: bool,
    full_blocks_len: usize,
}

/// Collect files needing data blocks in mksquashfs DFS order.
///
/// Same traversal order as inode number assignment. Hard-linked files
/// only appear once. Content-identical files are deduplicated — duplicates
/// are recorded in `dedup_copies` for resolution after writing.
fn collect_data_files_dfs(
    tree: &ScannedTree,
    dir_idx: usize,
    data_files: &mut Vec<(usize, DataFileEntry)>,
    dedup_copies: &mut Vec<(usize, usize, u64)>, // (child_idx, first_idx, file_size)
    hl_first: &mut HashMap<(u64, u64), usize>,
    dedup_map: &mut HashMap<(u64, [u8; 32]), usize>,
) {
    let children = match &tree.nodes[dir_idx].kind {
        NodeKind::Directory { children } => children,
        _ => return,
    };

    for &child_idx in children {
        let child = &tree.nodes[child_idx];
        match &child.kind {
            NodeKind::File { data, nlink } => {
                // Hard link dedup: skip data for duplicates
                if *nlink > 1 {
                    if hl_first.contains_key(&(child.host_dev, child.host_ino)) {
                        continue;
                    }
                    hl_first.insert((child.host_dev, child.host_ino), child_idx);
                }

                let file_size = data.len() as u64;

                // Content dedup: compute hash for non-empty files
                let content_hash = if !data.is_empty() {
                    let mut hasher = Sha256::new();
                    hasher.update(data);
                    let result = hasher.finalize();
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&result);
                    Some(hash)
                } else {
                    None
                };

                // Check for duplicate content
                if let Some(hash) = content_hash {
                    let dedup_key = (file_size, hash);
                    if let Some(&first_idx) = dedup_map.get(&dedup_key) {
                        dedup_copies.push((child_idx, first_idx, file_size));
                        continue;
                    }
                    dedup_map.insert(dedup_key, child_idx);
                }

                let block_size = DATA_BLOCK_SIZE as usize;
                let full_blocks_len = if file_size == 0 {
                    0
                } else {
                    (data.len() / block_size) * block_size
                };
                let has_full_blocks = full_blocks_len > 0;

                data_files.push((
                    child_idx,
                    DataFileEntry {
                        data: data.clone(),
                        has_full_blocks,
                        full_blocks_len,
                    },
                ));
            }
            NodeKind::Directory { .. } => {
                collect_data_files_dfs(
                    tree,
                    child_idx,
                    data_files,
                    dedup_copies,
                    hl_first,
                    dedup_map,
                );
            }
            NodeKind::Symlink { .. } => {}
        }
    }
}

/// Write inode table and directory table in mksquashfs DFS order.
///
/// For each directory:
/// 1. Process children in name-sorted order:
///    - Files/symlinks: write inode to inode table
///    - Subdirectories: recurse (writes entire subtree first)
/// 2. Write directory entries to directory table
/// 3. Write directory inode to inode table
///
/// Returns (inode_number, inode_ref) for the directory.
#[allow(clippy::too_many_arguments)]
fn write_tables_dfs(
    tree: &ScannedTree,
    dir_idx: usize,
    inode_numbers: &HashMap<usize, u32>,
    inode_table: &mut InodeTable,
    dir_table: &mut DirectoryTable,
    file_data: &HashMap<usize, FileDataInfo>,
    hl_data_first: &HashMap<(u64, u64), usize>,
    hl_iref_map: &mut HashMap<(u64, u64), (u32, u64)>,
    uid_idx: u16,
    gid_idx: u16,
    export_refs: &mut [u64],
) -> Result<(u32, u64)> {
    let node = &tree.nodes[dir_idx];
    let children = match &node.kind {
        NodeKind::Directory { children } => children,
        _ => anyhow::bail!("expected directory node"),
    };

    let mut dir_children: Vec<DirChild> = Vec::new();

    for &child_idx in children {
        let child = &tree.nodes[child_idx];
        match &child.kind {
            NodeKind::File { nlink, .. } => {
                let nlink = *nlink;

                // Hard link: reuse existing inode
                if nlink > 1 {
                    if let Some(&(existing_inum, existing_iref)) =
                        hl_iref_map.get(&(child.host_dev, child.host_ino))
                    {
                        dir_children.push(DirChild {
                            name: child.name.clone().into_bytes(),
                            inode_number: existing_inum,
                            inode_ref: existing_iref,
                            entry_type: DIR_TYPE_FILE,
                        });
                        continue;
                    }
                }

                // Get file data info (from first occurrence for hardlinks)
                let data_idx = if nlink > 1 {
                    *hl_data_first
                        .get(&(child.host_dev, child.host_ino))
                        .unwrap()
                } else {
                    child_idx
                };
                let info = file_data.get(&data_idx).unwrap();
                let pre_inum = inode_numbers[&child_idx];

                let (inum, iref) = inode_table.add_file(
                    pre_inum,
                    child.permissions,
                    uid_idx,
                    gid_idx,
                    info.file_size,
                    info.start_block,
                    &info.block_sizes,
                    info.frag_idx,
                    info.frag_offset,
                    nlink,
                    info.sparse,
                );

                export_refs[(inum - 1) as usize] = iref;

                if nlink > 1 {
                    hl_iref_map.insert((child.host_dev, child.host_ino), (inum, iref));
                }

                dir_children.push(DirChild {
                    name: child.name.clone().into_bytes(),
                    inode_number: inum,
                    inode_ref: iref,
                    entry_type: DIR_TYPE_FILE,
                });
            }
            NodeKind::Symlink { target } => {
                let pre_inum = inode_numbers[&child_idx];
                let (inum, iref) = inode_table.add_symlink(
                    pre_inum,
                    child.permissions,
                    uid_idx,
                    gid_idx,
                    target.as_bytes(),
                    1,
                );

                export_refs[(inum - 1) as usize] = iref;

                dir_children.push(DirChild {
                    name: child.name.clone().into_bytes(),
                    inode_number: inum,
                    inode_ref: iref,
                    entry_type: DIR_TYPE_SYMLINK,
                });
            }
            NodeKind::Directory { .. } => {
                // Recurse: write entire subtree first
                let (child_inum, child_iref) = write_tables_dfs(
                    tree,
                    child_idx,
                    inode_numbers,
                    inode_table,
                    dir_table,
                    file_data,
                    hl_data_first,
                    hl_iref_map,
                    uid_idx,
                    gid_idx,
                    export_refs,
                )?;

                dir_children.push(DirChild {
                    name: child.name.clone().into_bytes(),
                    inode_number: child_inum,
                    inode_ref: child_iref,
                    entry_type: DIR_TYPE_DIR,
                });
            }
        }
    }

    // Write directory entries for this dir
    let (dir_blk, dir_off, dir_size, dir_index, dir_index_names) =
        dir_table.write_directory(&dir_children);

    // Compute mksquashfs-compatible metrics for LDIR decision:
    // child_count = total entries, entry_byte_count = sum(8 + name.len()) without headers
    let child_count = dir_children.len() as u32;
    let entry_byte_count: u32 = dir_children.iter().map(|c| 8 + c.name.len() as u32).sum();

    // Count subdirectories for nlink (2 + number of immediate subdirs)
    let subdir_count = children
        .iter()
        .filter(|&&ci| matches!(tree.nodes[ci].kind, NodeKind::Directory { .. }))
        .count() as u32;
    let nlink = 2 + subdir_count;

    // Parent inode number (pre-assigned).
    // mksquashfs sets root's parent to total_inodes + 1.
    let parent_inode = if dir_idx == tree.root {
        export_refs.len() as u32 + 1
    } else {
        inode_numbers[&node.parent_idx]
    };

    // Write directory inode
    let dir_inum = inode_numbers[&dir_idx];
    let (inum, iref) = inode_table.add_dir(
        dir_inum,
        node.permissions,
        uid_idx,
        gid_idx,
        dir_blk,
        dir_off,
        dir_size + 3, // kernel expects file_size = actual_bytes + 3
        nlink,
        parent_inode,
        child_count,
        entry_byte_count,
        &dir_index,
        &dir_index_names,
    );

    export_refs[(inum - 1) as usize] = iref;

    Ok((inum, iref))
}

/// Write the export/lookup table (inode_number → inode_ref).
///
/// Two-level structure:
/// 1. Export entries (u64 inode_refs) packed into metadata blocks
/// 2. Lookup table of u64 offsets to each metadata block
fn write_export_table<W: Write + Seek>(refs: &[u64], output: &mut W) -> std::io::Result<u64> {
    if refs.is_empty() {
        return output.stream_position();
    }

    // Serialize all export entries
    let mut entry_bytes = Vec::with_capacity(refs.len() * 8);
    for &r in refs {
        entry_bytes.extend_from_slice(&r.to_le_bytes());
    }

    // Write as metadata blocks
    let mut block_offsets: Vec<u64> = Vec::new();
    let mut pos = 0;

    while pos < entry_bytes.len() {
        let end = (pos + METADATA_BLOCK_SIZE).min(entry_bytes.len());
        let chunk = &entry_bytes[pos..end];

        let block_start = output.stream_position()?;
        block_offsets.push(block_start);

        let compressed = zstd::bulk::compress(chunk, ZSTD_LEVEL).ok();
        match compressed {
            Some(ref c) if c.len() < chunk.len() => {
                let header = c.len() as u16;
                output.write_all(&header.to_le_bytes())?;
                output.write_all(c)?;
            }
            _ => {
                let header = chunk.len() as u16 | META_BLOCK_UNCOMPRESSED;
                output.write_all(&header.to_le_bytes())?;
                output.write_all(chunk)?;
            }
        }

        pos = end;
    }

    // Write lookup table: array of u64 offsets
    let table_start = output.stream_position()?;
    for offset in &block_offsets {
        output.write_all(&offset.to_le_bytes())?;
    }

    Ok(table_start)
}

/// Write the ID table (uid/gid lookup).
///
/// Two-level structure like the fragment table:
/// 1. ID entries (u32 each) packed into metadata blocks
/// 2. Lookup table of u64 offsets to each metadata block
fn write_id_table<W: Write + Seek>(ids: &[u32], output: &mut W) -> std::io::Result<u64> {
    if ids.is_empty() {
        return output.stream_position();
    }

    let mut entry_bytes = Vec::with_capacity(ids.len() * 4);
    for &id in ids {
        entry_bytes.extend_from_slice(&id.to_le_bytes());
    }

    let mut block_offsets: Vec<u64> = Vec::new();
    let mut pos = 0;

    while pos < entry_bytes.len() {
        let end = (pos + METADATA_BLOCK_SIZE).min(entry_bytes.len());
        let chunk = &entry_bytes[pos..end];

        let block_start = output.stream_position()?;
        block_offsets.push(block_start);

        let compressed = zstd::bulk::compress(chunk, ZSTD_LEVEL).ok();
        match compressed {
            Some(ref c) if c.len() < chunk.len() => {
                let header = c.len() as u16;
                output.write_all(&header.to_le_bytes())?;
                output.write_all(c)?;
            }
            _ => {
                let header = chunk.len() as u16 | META_BLOCK_UNCOMPRESSED;
                output.write_all(&header.to_le_bytes())?;
                output.write_all(chunk)?;
            }
        }

        pos = end;
    }

    let table_start = output.stream_position()?;
    for offset in &block_offsets {
        output.write_all(&offset.to_le_bytes())?;
    }

    Ok(table_start)
}

fn sha256_file(path: &Path) -> Result<String> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let result = hasher.finalize();
    Ok(hex_encode(&result))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// -- Tree scanning --

#[derive(Debug)]
struct TreeNode {
    name: String,
    permissions: u16,
    host_dev: u64,
    host_ino: u64,
    parent_idx: usize,
    kind: NodeKind,
}

#[derive(Debug)]
enum NodeKind {
    File { data: Vec<u8>, nlink: u32 },
    Symlink { target: String },
    Directory { children: Vec<usize> },
}

struct ScannedTree {
    nodes: Vec<TreeNode>,
    root: usize,
}

fn scan_tree(rootfs: &Path) -> Result<ScannedTree> {
    let mut nodes = Vec::new();

    // Create root node
    let root_meta = fs::symlink_metadata(rootfs).context("stat rootfs")?;
    let root_idx = nodes.len();
    nodes.push(TreeNode {
        name: String::new(),
        permissions: (root_meta.mode() & 0o7777) as u16,
        host_dev: root_meta.dev(),
        host_ino: root_meta.ino(),
        parent_idx: 0,
        kind: NodeKind::Directory {
            children: Vec::new(),
        },
    });

    scan_dir_recursive(rootfs, root_idx, &mut nodes)?;

    Ok(ScannedTree {
        nodes,
        root: root_idx,
    })
}

fn scan_dir_recursive(dir_path: &Path, dir_idx: usize, nodes: &mut Vec<TreeNode>) -> Result<()> {
    let mut entries: Vec<(String, PathBuf)> = Vec::new();

    for entry in
        fs::read_dir(dir_path).with_context(|| format!("read_dir {}", dir_path.display()))?
    {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .unwrap_or_else(|os| os.to_string_lossy().into_owned());
        entries.push((name, entry.path()));
    }

    // Sort by name for deterministic output (matches mksquashfs strcmp order)
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, path) in entries {
        let meta =
            fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        let ft = meta.file_type();
        let permissions = (meta.mode() & 0o7777) as u16;
        let host_dev = meta.dev();
        let host_ino = meta.ino();

        if ft.is_file() {
            let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let nlink = meta.nlink() as u32;
            let child_idx = nodes.len();
            nodes.push(TreeNode {
                name,
                permissions,
                host_dev,
                host_ino,
                parent_idx: dir_idx,
                kind: NodeKind::File { data, nlink },
            });
            if let NodeKind::Directory { children } = &mut nodes[dir_idx].kind {
                children.push(child_idx);
            }
        } else if ft.is_symlink() {
            let target =
                fs::read_link(&path).with_context(|| format!("readlink {}", path.display()))?;
            let target_str = target.to_string_lossy().into_owned();
            let child_idx = nodes.len();
            nodes.push(TreeNode {
                name,
                permissions,
                host_dev,
                host_ino,
                parent_idx: dir_idx,
                kind: NodeKind::Symlink { target: target_str },
            });
            if let NodeKind::Directory { children } = &mut nodes[dir_idx].kind {
                children.push(child_idx);
            }
        } else if ft.is_dir() {
            let child_idx = nodes.len();
            nodes.push(TreeNode {
                name,
                permissions,
                host_dev,
                host_ino,
                parent_idx: dir_idx,
                kind: NodeKind::Directory {
                    children: Vec::new(),
                },
            });
            if let NodeKind::Directory { children } = &mut nodes[dir_idx].kind {
                children.push(child_idx);
            }
            // Recurse
            scan_dir_recursive(&path, child_idx, nodes)?;
        }
        // Skip other types (devices, fifos, sockets)
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn make_test_rootfs() -> TempDir {
        let dir = TempDir::new().unwrap();
        let root = dir.path();

        // Create some files
        fs::write(root.join("hello.txt"), "Hello, world!").unwrap();
        fs::write(root.join("empty"), "").unwrap();
        fs::create_dir(root.join("subdir")).unwrap();
        fs::write(root.join("subdir").join("nested.txt"), "nested content").unwrap();

        // Create a symlink
        symlink("hello.txt", root.join("link.txt")).unwrap();

        dir
    }

    #[test]
    fn basic_creation() {
        let rootfs = make_test_rootfs();
        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");

        let hash = create_squashfs(rootfs.path(), &output).unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 hex

        let meta = fs::metadata(&output).unwrap();
        assert!(meta.len() > Superblock::SIZE as u64);

        // Verify magic
        let data = fs::read(&output).unwrap();
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(magic, format::SQUASHFS_MAGIC);
    }

    #[test]
    fn reproducibility() {
        let rootfs = make_test_rootfs();
        let out_dir = TempDir::new().unwrap();

        let output1 = out_dir.path().join("test1.squashfs");
        let output2 = out_dir.path().join("test2.squashfs");

        let hash1 = create_squashfs(rootfs.path(), &output1).unwrap();
        let hash2 = create_squashfs(rootfs.path(), &output2).unwrap();

        assert_eq!(hash1, hash2, "builds must be reproducible");
    }

    #[test]
    fn empty_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("empty1"), "").unwrap();
        fs::write(dir.path().join("empty2"), "").unwrap();

        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        let hash = create_squashfs(dir.path(), &output).unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn large_file() {
        let dir = TempDir::new().unwrap();
        // Create a file larger than one data block (128 KiB)
        let big = vec![0x42u8; DATA_BLOCK_SIZE as usize * 2 + 5000];
        fs::write(dir.path().join("big.bin"), &big).unwrap();

        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        let hash = create_squashfs(dir.path(), &output).unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn symlinks() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("target"), "data").unwrap();
        symlink("target", dir.path().join("link")).unwrap();
        symlink("/absolute/path", dir.path().join("abs_link")).unwrap();

        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        let hash = create_squashfs(dir.path(), &output).unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn hardlinks() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("original");
        fs::write(&file_path, "shared data").unwrap();
        fs::hard_link(&file_path, dir.path().join("link1")).unwrap();
        fs::hard_link(&file_path, dir.path().join("link2")).unwrap();

        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        let hash = create_squashfs(dir.path(), &output).unwrap();
        assert_eq!(hash.len(), 64);

        // Verify that we used extended inodes (nlink > 1) but only wrote data once.
        let data = fs::read(&output).unwrap();
        let bytes_used = u64::from_le_bytes(data[40..48].try_into().unwrap());
        assert!(
            bytes_used < 1024,
            "hardlinks should share data, got bytes_used={bytes_used}"
        );
    }

    #[test]
    fn nested_directories() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("a/b/c")).unwrap();
        fs::write(root.join("a/b/c/deep.txt"), "deep").unwrap();
        fs::create_dir(root.join("a/sibling")).unwrap();
        fs::write(root.join("a/sibling/file"), "sibling content").unwrap();

        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        let hash = create_squashfs(root, &output).unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn superblock_fields() {
        let rootfs = make_test_rootfs();
        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        create_squashfs(rootfs.path(), &output).unwrap();

        let r = reader::SquashfsReader::open(&output).unwrap();
        assert!(r.sb.inode_count > 0);
        assert_eq!(r.sb.modification_time, 0);
        assert_eq!(r.sb.block_size, DATA_BLOCK_SIZE);
        assert_eq!(r.sb.compression_id, format::ZSTD_COMPRESSION);
        assert_eq!(r.sb.block_log, format::DATA_BLOCK_LOG);
    }

    #[test]
    fn roundtrip_basic() {
        let rootfs = make_test_rootfs();
        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        create_squashfs(rootfs.path(), &output).unwrap();

        let r = reader::SquashfsReader::open(&output).unwrap();

        // Verify root inode
        let root = r.root_inode().unwrap();
        match &root {
            reader::Inode::Dir(d) => {
                // Root parent = total_inodes + 1 (mksquashfs convention)
                assert_eq!(d.parent_inode, r.sb.inode_count + 1);
                assert!(d.nlink >= 2);
            }
            _ => panic!("root must be a directory"),
        }

        // Verify all files can be read
        let count = r.verify().unwrap();
        assert!(count > 0, "should have found some files");
    }

    #[test]
    fn roundtrip_file_contents() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        fs::write(root.join("hello.txt"), "Hello, world!").unwrap();
        fs::write(root.join("empty"), "").unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub/nested"), "nested data").unwrap();

        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        create_squashfs(root, &output).unwrap();

        let r = reader::SquashfsReader::open(&output).unwrap();

        // Walk and collect files
        let mut files: std::collections::HashMap<String, Vec<u8>> =
            std::collections::HashMap::new();
        r.walk(|path, inode| {
            if let reader::Inode::File(f) = inode {
                let data = r.read_file(f)?;
                files.insert(path.to_string(), data);
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(
            files.get("/hello.txt").map(|v| v.as_slice()),
            Some(b"Hello, world!" as &[u8])
        );
        assert_eq!(
            files.get("/empty").map(|v| v.as_slice()),
            Some(b"" as &[u8])
        );
        assert_eq!(
            files.get("/sub/nested").map(|v| v.as_slice()),
            Some(b"nested data" as &[u8])
        );
    }

    #[test]
    fn roundtrip_symlinks() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("target"), "data").unwrap();
        symlink("target", dir.path().join("link")).unwrap();
        symlink("/absolute/path", dir.path().join("abs_link")).unwrap();

        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        create_squashfs(dir.path(), &output).unwrap();

        let r = reader::SquashfsReader::open(&output).unwrap();
        let mut symlinks: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        r.walk(|path, inode| {
            if let reader::Inode::Symlink(s) = inode {
                symlinks.insert(path.to_string(), s.target.clone());
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(symlinks.get("/link").map(String::as_str), Some("target"));
        assert_eq!(
            symlinks.get("/abs_link").map(String::as_str),
            Some("/absolute/path")
        );
    }

    #[test]
    fn roundtrip_large_file() {
        let dir = TempDir::new().unwrap();
        // Multi-block file: 2 full blocks + tail
        let big = vec![0x42u8; DATA_BLOCK_SIZE as usize * 2 + 5000];
        fs::write(dir.path().join("big.bin"), &big).unwrap();

        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        create_squashfs(dir.path(), &output).unwrap();

        let r = reader::SquashfsReader::open(&output).unwrap();
        let mut found = false;
        r.walk(|path, inode| {
            if let reader::Inode::File(f) = inode {
                if path == "/big.bin" {
                    let data = r.read_file(f)?;
                    assert_eq!(data.len(), big.len());
                    assert_eq!(data, big);
                    found = true;
                }
            }
            Ok(())
        })
        .unwrap();
        assert!(found, "big.bin not found");
    }

    #[test]
    fn roundtrip_hardlinks() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("original"), "shared data").unwrap();
        fs::hard_link(dir.path().join("original"), dir.path().join("link1")).unwrap();
        fs::hard_link(dir.path().join("original"), dir.path().join("link2")).unwrap();

        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        create_squashfs(dir.path(), &output).unwrap();

        let r = reader::SquashfsReader::open(&output).unwrap();
        let mut inode_numbers: Vec<(String, u32)> = Vec::new();
        let mut contents: Vec<(String, Vec<u8>)> = Vec::new();
        r.walk(|path, inode| {
            if let reader::Inode::File(f) = inode {
                inode_numbers.push((path.to_string(), f.inode_number));
                let data = r.read_file(f)?;
                contents.push((path.to_string(), data));
            }
            Ok(())
        })
        .unwrap();

        // All three should have the same inode number (hard links share inodes)
        let inums: Vec<u32> = inode_numbers.iter().map(|(_, n)| *n).collect();
        assert_eq!(
            inums.iter().collect::<std::collections::HashSet<_>>().len(),
            1,
            "hardlinks should share inode number, got {inode_numbers:?}"
        );

        // All should have same content
        for (path, data) in &contents {
            assert_eq!(data.as_slice(), b"shared data", "wrong content for {path}");
        }
    }

    #[test]
    fn roundtrip_empty_dir() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("empty_dir")).unwrap();
        fs::write(dir.path().join("file.txt"), "hello").unwrap();

        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        create_squashfs(dir.path(), &output).unwrap();

        let r = reader::SquashfsReader::open(&output).unwrap();
        let mut found_empty_dir = false;
        r.walk(|path, inode| {
            if path == "/empty_dir" {
                match inode {
                    reader::Inode::Dir(d) => {
                        let entries = r.read_dir(d)?;
                        assert!(entries.is_empty(), "empty dir should have no entries");
                        found_empty_dir = true;
                    }
                    _ => panic!("empty_dir should be a directory"),
                }
            }
            Ok(())
        })
        .unwrap();
        assert!(found_empty_dir, "empty_dir not found");
    }

    #[test]
    fn roundtrip_list_all() {
        let rootfs = make_test_rootfs();
        let out_dir = TempDir::new().unwrap();
        let output = out_dir.path().join("test.squashfs");
        create_squashfs(rootfs.path(), &output).unwrap();

        let r = reader::SquashfsReader::open(&output).unwrap();
        let listing = r.list_all().unwrap();

        // Should have root + files + dirs + symlinks
        assert!(
            listing.len() >= 5,
            "expected at least 5 entries, got {}",
            listing.len()
        );

        // Check types
        let types: Vec<&str> = listing.iter().map(|(_, t, _)| *t).collect();
        assert!(types.contains(&"file"));
        assert!(types.contains(&"dir"));
        assert!(types.contains(&"symlink"));
    }

    #[test]
    fn reader_reads_mksquashfs_output() {
        use std::process::Command;

        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("hello"), "world").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/file"), "content").unwrap();

        let out_dir = TempDir::new().unwrap();
        let ref_path = out_dir.path().join("ref.squashfs");

        // Check if mksquashfs is available
        let has_mksquashfs = Command::new("mksquashfs").arg("--help").output().is_ok();

        if !has_mksquashfs {
            return;
        }

        let status = Command::new("mksquashfs")
            .args([
                dir.path().to_str().unwrap(),
                ref_path.to_str().unwrap(),
                "-comp",
                "zstd",
                "-b",
                "131072",
                "-all-root",
                "-noappend",
                "-no-xattrs",
            ])
            .env_remove("SOURCE_DATE_EPOCH")
            .output()
            .unwrap();
        assert!(status.status.success(), "mksquashfs failed");

        let r = reader::SquashfsReader::open(&ref_path).unwrap();
        let count = r.verify().unwrap();
        assert!(
            count >= 2,
            "should read at least 2 files from mksquashfs output"
        );

        // Verify contents
        let mut files: std::collections::HashMap<String, Vec<u8>> =
            std::collections::HashMap::new();
        r.walk(|path, inode| {
            if let reader::Inode::File(f) = inode {
                files.insert(path.to_string(), r.read_file(f)?);
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(files["/hello"].as_slice(), b"world");
        assert_eq!(files["/sub/file"].as_slice(), b"content");
    }
}
