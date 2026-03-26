/// Create a squashfs image from a directory using our writer.
/// Usage: mkfs <rootfs_dir> <output.squashfs>
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: mkfs <rootfs_dir> <output.squashfs>");
        std::process::exit(1);
    }

    let rootfs = Path::new(&args[1]);
    let output = Path::new(&args[2]);

    match cvmbuild_squashfs::create_squashfs(rootfs, output) {
        Ok(hash) => println!("SHA256: {hash}"),
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
    }
}
