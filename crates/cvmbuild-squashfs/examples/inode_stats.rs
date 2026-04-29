//! Count inode types across the full inode table of a squashfs image.

fn read_u16(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(d[off..off + 2].try_into().unwrap())
}
fn read_u32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(d[off..off + 4].try_into().unwrap())
}
fn read_u64(d: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

fn decompress_meta_block(data: &[u8], offset: usize) -> (Vec<u8>, usize) {
    if offset + 2 > data.len() {
        return (vec![], 0);
    }
    let hdr = read_u16(data, offset);
    let is_uncomp = hdr & 0x8000 != 0;
    let blen = (hdr & 0x7fff) as usize;
    if blen == 0 || offset + 2 + blen > data.len() {
        return (vec![], 0);
    }
    let raw = &data[offset + 2..offset + 2 + blen];
    let decompressed = if is_uncomp {
        raw.to_vec()
    } else {
        zstd::bulk::decompress(raw, 8192).unwrap()
    };
    (decompressed, 2 + blen)
}

/// Decompress the full inode table (all metadata blocks).
fn decompress_inode_table(data: &[u8], inode_tbl: usize, dir_tbl: usize) -> Vec<u8> {
    let mut result = Vec::new();
    let mut offset = inode_tbl;
    let mut nblocks = 0;
    while offset < dir_tbl {
        let (block, consumed) = decompress_meta_block(data, offset);
        if consumed == 0 {
            break;
        }
        result.extend_from_slice(&block);
        offset += consumed;
        nblocks += 1;
    }
    eprintln!(
        "  decompressed {nblocks} metadata blocks, {} total bytes",
        result.len()
    );
    result
}

struct InodeStats {
    basic_file: u32,
    ext_file: u32,
    basic_dir: u32,
    ext_dir: u32,
    basic_symlink: u32,
    ext_symlink: u32,
    other: u32,
    // Track which inodes are ext_file and why
    ext_file_reasons: Vec<(u32, u64, u64, u32, u64)>, // (inum, file_size, sparse, nlink, start_block)
    ext_dir_details: Vec<(u32, u32, u16)>,            // (inum, file_size, i_count)
}

fn parse_inodes(inode_data: &[u8]) -> InodeStats {
    let mut stats = InodeStats {
        basic_file: 0,
        ext_file: 0,
        basic_dir: 0,
        ext_dir: 0,
        basic_symlink: 0,
        ext_symlink: 0,
        other: 0,
        ext_file_reasons: Vec::new(),
        ext_dir_details: Vec::new(),
    };
    let block_size: u64 = 131072;
    let mut off = 0;

    while off + 16 <= inode_data.len() {
        let itype = read_u16(inode_data, off);
        let inum = read_u32(inode_data, off + 12);
        let prev_off = off;

        match itype {
            2 => {
                // Basic file: header(16) + start_block(4) + fragment(4) + offset(4) + file_size(4) = 32
                if off + 32 > inode_data.len() {
                    break;
                }
                stats.basic_file += 1;
                let fsize = read_u32(inode_data, off + 28) as u64;
                let frag = read_u32(inode_data, off + 20);
                let nblocks = if fsize == 0 {
                    0
                } else if frag != 0xFFFFFFFF {
                    // Has fragment: only full blocks count
                    fsize / block_size
                } else {
                    // No fragment: ceil division
                    fsize.div_ceil(block_size)
                };
                off += 32 + nblocks as usize * 4;
            }
            9 => {
                // Extended file: header(16) + start(8) + size(8) + sparse(8) + nlink(4) + frag(4) + off(4) + xattr(4) = 56
                if off + 56 > inode_data.len() {
                    break;
                }
                stats.ext_file += 1;
                let fsize = read_u64(inode_data, off + 24);
                let sparse = read_u64(inode_data, off + 32);
                let nlink = read_u32(inode_data, off + 40);
                let frag = read_u32(inode_data, off + 44);
                let start = read_u64(inode_data, off + 16);
                stats
                    .ext_file_reasons
                    .push((inum, fsize, sparse, nlink, start));
                let nblocks = if fsize == 0 {
                    0
                } else if frag != 0xFFFFFFFF {
                    fsize / block_size
                } else {
                    fsize.div_ceil(block_size)
                };
                off += 56 + nblocks as usize * 4;
            }
            1 => {
                // Basic dir: header(16) + start_block(4) + nlink(4) + file_size(2) + offset(2) + parent(4) = 32
                if off + 32 > inode_data.len() {
                    break;
                }
                stats.basic_dir += 1;
                off += 32;
            }
            8 => {
                // Extended dir: header(16) + nlink(4) + file_size(4) + start_block(4) + parent(4) + i_count(2) + offset(2) + xattr(4) = 40
                if off + 40 > inode_data.len() {
                    break;
                }
                stats.ext_dir += 1;
                let dir_fsize = read_u32(inode_data, off + 20);
                let i_count = read_u16(inode_data, off + 32) as usize;
                stats
                    .ext_dir_details
                    .push((inum, dir_fsize, i_count as u16));
                off += 40;
                for _ in 0..i_count {
                    if off + 12 > inode_data.len() {
                        break;
                    }
                    let name_size = read_u32(inode_data, off + 8) as usize;
                    off += 12 + name_size + 1;
                }
            }
            3 => {
                // Basic symlink: header(16) + nlink(4) + symlink_size(4) + target_bytes
                if off + 24 > inode_data.len() {
                    break;
                }
                stats.basic_symlink += 1;
                let tlen = read_u32(inode_data, off + 20) as usize;
                off += 24 + tlen;
            }
            10 => {
                // Extended symlink: header(16) + nlink(4) + symlink_size(4) + target_bytes + xattr(4)
                if off + 24 > inode_data.len() {
                    break;
                }
                stats.ext_symlink += 1;
                let tlen = read_u32(inode_data, off + 20) as usize;
                off += 24 + tlen + 4;
            }
            _ => {
                stats.other += 1;
                eprintln!("Unknown inode type {itype} at offset {off}, inum={inum}");
                // Try to show context
                let end = (off + 32).min(inode_data.len());
                eprint!("  bytes: ");
                for b in &inode_data[off..end] {
                    eprint!("{b:02x} ");
                }
                eprintln!();
                break;
            }
        }
        if off <= prev_off {
            eprintln!("Parser stuck at offset {off}");
            break;
        }
    }
    stats
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: inode_stats <image1.squashfs> [image2.squashfs]");
        std::process::exit(1);
    }

    for path in &args[1..] {
        println!("=== {path} ===");
        let d = std::fs::read(path).unwrap();
        let inode_tbl = read_u64(&d, 64) as usize;
        let dir_tbl = read_u64(&d, 72) as usize;
        let inode_count = read_u32(&d, 4);

        let inode_data = decompress_inode_table(&d, inode_tbl, dir_tbl);
        println!(
            "  inode table: {} compressed bytes, {} uncompressed bytes",
            dir_tbl - inode_tbl,
            inode_data.len()
        );
        println!("  declared inode_count: {inode_count}");

        let stats = parse_inodes(&inode_data);
        let total = stats.basic_file
            + stats.ext_file
            + stats.basic_dir
            + stats.ext_dir
            + stats.basic_symlink
            + stats.ext_symlink
            + stats.other;
        println!("  parsed: {total} inodes");
        println!("  basic_file:    {}", stats.basic_file);
        println!("  ext_file:      {}", stats.ext_file);
        println!("  basic_dir:     {}", stats.basic_dir);
        println!("  ext_dir:       {}", stats.ext_dir);
        println!("  basic_symlink: {}", stats.basic_symlink);
        println!("  ext_symlink:   {}", stats.ext_symlink);
        println!("  other:         {}", stats.other);

        if !stats.ext_file_reasons.is_empty() {
            println!("\n  Extended file reasons (first 20):");
            for (_i, (inum, fsize, sparse, nlink, start)) in
                stats.ext_file_reasons.iter().enumerate().take(20)
            {
                let reason = if *nlink > 1 {
                    "nlink"
                } else if *fsize >= (1u64 << 32) {
                    "size"
                } else if *start >= (1u64 << 32) {
                    "start>4G"
                } else if *sparse > 0 {
                    "sparse"
                } else {
                    "???"
                };
                println!("    inode#{inum}: size={fsize} sparse={sparse} nlink={nlink} start=0x{start:x} reason={reason}");
            }
            if stats.ext_file_reasons.len() > 20 {
                println!("    ... and {} more", stats.ext_file_reasons.len() - 20);
            }
            // Count reasons
            let n_nlink = stats
                .ext_file_reasons
                .iter()
                .filter(|(_, _, _, n, _)| *n > 1)
                .count();
            let n_sparse = stats
                .ext_file_reasons
                .iter()
                .filter(|(_, _, s, n, _)| *s > 0 && *n <= 1)
                .count();
            let n_size = stats
                .ext_file_reasons
                .iter()
                .filter(|(_, f, _, _, _)| *f >= (1u64 << 32))
                .count();
            let n_start = stats
                .ext_file_reasons
                .iter()
                .filter(|(_, _, _, _, st)| *st >= (1u64 << 32))
                .count();
            let n_unknown = stats
                .ext_file_reasons
                .iter()
                .filter(|(_, f, s, n, st)| {
                    *n <= 1 && *s == 0 && *f < (1u64 << 32) && *st < (1u64 << 32)
                })
                .count();
            println!("\n  Reason summary: nlink={n_nlink} sparse={n_sparse} size={n_size} start>4G={n_start} unknown={n_unknown}");
        }

        if !stats.ext_dir_details.is_empty() {
            println!("\n  Extended dir details:");
            for (inum, fsize, i_count) in &stats.ext_dir_details {
                let reason = if *fsize > 65535 {
                    "size>64K"
                } else if *i_count > 0 {
                    "has_index"
                } else {
                    "???"
                };
                println!("    inode#{inum}: file_size={fsize} i_count={i_count} reason={reason}");
            }
        }
        println!();
    }
}
