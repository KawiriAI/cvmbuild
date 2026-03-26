/// Compare two squashfs images by decompressing their inode and directory tables.

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
    let hdr = read_u16(data, offset);
    let is_uncomp = hdr & 0x8000 != 0;
    let blen = (hdr & 0x7fff) as usize;
    let raw = &data[offset + 2..offset + 2 + blen];
    let decompressed = if is_uncomp {
        raw.to_vec()
    } else {
        zstd::bulk::decompress(raw, 8192 * 4).unwrap()
    };
    (decompressed, 2 + blen)
}

fn dump_image(path: &str, label: &str) -> (Vec<u8>, Vec<u8>) {
    let d = std::fs::read(path).unwrap();
    let inode_tbl = read_u64(&d, 64) as usize;
    let dir_tbl = read_u64(&d, 72) as usize;
    let frag_tbl = read_u64(&d, 80) as usize;
    let lookup_tbl = read_u64(&d, 88) as usize;
    let root_ref = read_u64(&d, 32);
    let bytes_used = read_u64(&d, 40);

    println!("{label}: root_ref=0x{root_ref:x} bytes_used={bytes_used}");
    println!("  inode_tbl=0x{inode_tbl:x} dir_tbl=0x{dir_tbl:x} frag_tbl=0x{frag_tbl:x} lookup_tbl=0x{lookup_tbl:x}");

    // Decompress inode table
    let (inode_data, inode_block_size) = decompress_meta_block(&d, inode_tbl);
    println!(
        "  inode meta: compressed={inode_block_size} uncompressed={}",
        inode_data.len()
    );
    println!("  inode hex: {}", hex(&inode_data));

    // Parse inodes
    let mut off = 0;
    while off < inode_data.len() {
        let itype = read_u16(&inode_data, off);
        let perms = read_u16(&inode_data, off + 2);
        let uid = read_u16(&inode_data, off + 4);
        let gid = read_u16(&inode_data, off + 6);
        let mtime = read_u32(&inode_data, off + 8);
        let inum = read_u32(&inode_data, off + 12);
        print!("  inode#{inum} type={itype} perms=0o{perms:o} uid={uid} gid={gid} mtime={mtime}");

        match itype {
            2 => {
                // Basic file
                let start = read_u32(&inode_data, off + 16);
                let frag = read_u32(&inode_data, off + 20);
                let frag_off = read_u32(&inode_data, off + 24);
                let fsize = read_u32(&inode_data, off + 28);
                println!(" FILE start=0x{start:x} frag={frag} frag_off={frag_off} size={fsize}");
                off += 32;
            }
            1 => {
                // Basic dir
                let start = read_u32(&inode_data, off + 16);
                let nlink = read_u32(&inode_data, off + 20);
                let fsize = read_u16(&inode_data, off + 24);
                let doff = read_u16(&inode_data, off + 26);
                let parent = read_u32(&inode_data, off + 28);
                println!(" DIR start=0x{start:x} nlink={nlink} size={fsize} offset={doff} parent={parent}");
                off += 32;
            }
            9 => {
                // Extended file
                let start = read_u64(&inode_data, off + 16);
                let fsize = read_u64(&inode_data, off + 24);
                let sparse = read_u64(&inode_data, off + 32);
                let nlink = read_u32(&inode_data, off + 40);
                let frag = read_u32(&inode_data, off + 44);
                let frag_off = read_u32(&inode_data, off + 48);
                let xattr = read_u32(&inode_data, off + 52);
                println!(" EXT_FILE start=0x{start:x} size={fsize} sparse={sparse} nlink={nlink} frag={frag} frag_off={frag_off} xattr=0x{xattr:x}");
                off += 56;
            }
            _ => {
                println!(" UNKNOWN type={itype}");
                break;
            }
        }
    }

    // Decompress directory table
    let (dir_data, dir_block_size) = decompress_meta_block(&d, dir_tbl);
    println!(
        "  dir meta: compressed={dir_block_size} uncompressed={}",
        dir_data.len()
    );
    println!("  dir hex: {}", hex(&dir_data));

    (inode_data, dir_data)
}

fn hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: compare <ours.squashfs> <ref.squashfs>");
        std::process::exit(1);
    }

    println!("=== OURS ===");
    let (inode1, dir1) = dump_image(&args[1], "OURS");
    println!();
    println!("=== REF ===");
    let (inode2, dir2) = dump_image(&args[2], "REF");
    println!();

    if inode1 == inode2 {
        println!("INODE TABLES: MATCH");
    } else {
        println!(
            "INODE TABLES: DIFFER ({} vs {} bytes)",
            inode1.len(),
            inode2.len()
        );
        for i in 0..inode1.len().min(inode2.len()) {
            if inode1[i] != inode2[i] {
                println!(
                    "  first diff at byte {i}: ours=0x{:02x} ref=0x{:02x}",
                    inode1[i], inode2[i]
                );
                break;
            }
        }
    }

    if dir1 == dir2 {
        println!("DIR TABLES: MATCH");
    } else {
        println!(
            "DIR TABLES: DIFFER ({} vs {} bytes)",
            dir1.len(),
            dir2.len()
        );
    }
}
