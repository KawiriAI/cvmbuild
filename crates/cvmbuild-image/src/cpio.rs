//! Pure Rust CPIO newc archive builder.
//!
//! Implements the SVR4 "newc" CPIO format used by the Linux kernel for initramfs.
//! Reference: <https://man7.org/linux/man-pages/man5/cpio.5.html>

const MAGIC: &[u8; 6] = b"070701";
const HEADER_SIZE: usize = 110;

/// Builder for CPIO newc archives.
pub struct CpioBuilder {
    entries: Vec<CpioEntry>,
    ino_counter: u32,
}

enum EntryKind {
    File(Vec<u8>),
    Directory,
    Symlink(String),
}

struct CpioEntry {
    path: String,
    mode: u32,
    kind: EntryKind,
    ino: u32,
}

impl Default for CpioBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CpioBuilder {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            ino_counter: 1,
        }
    }

    /// Add a regular file.
    pub fn add_file(&mut self, path: &str, mode: u32, data: Vec<u8>) {
        let ino = self.next_ino();
        self.entries.push(CpioEntry {
            path: path.to_string(),
            mode: 0o100000 | (mode & 0o7777), // S_IFREG
            kind: EntryKind::File(data),
            ino,
        });
    }

    /// Add a directory.
    pub fn add_dir(&mut self, path: &str, mode: u32) {
        let ino = self.next_ino();
        self.entries.push(CpioEntry {
            path: path.to_string(),
            mode: 0o040000 | (mode & 0o7777), // S_IFDIR
            kind: EntryKind::Directory,
            ino,
        });
    }

    /// Add a symbolic link.
    pub fn add_symlink(&mut self, path: &str, target: &str) {
        let ino = self.next_ino();
        self.entries.push(CpioEntry {
            path: path.to_string(),
            mode: 0o120000 | 0o777, // S_IFLNK | rwxrwxrwx
            kind: EntryKind::Symlink(target.to_string()),
            ino,
        });
    }

    /// Finalize the archive and return the raw CPIO bytes.
    pub fn finish(self) -> Vec<u8> {
        let mut out = Vec::new();

        for entry in &self.entries {
            let (file_data, filesize) = match &entry.kind {
                EntryKind::File(data) => (data.as_slice(), data.len() as u32),
                EntryKind::Directory => (&[][..], 0u32),
                EntryKind::Symlink(target) => (target.as_bytes(), target.len() as u32),
            };

            let namesize = entry.path.len() + 1; // include NUL terminator

            write_header(&mut out, entry.ino, entry.mode, filesize, namesize as u32);

            // Write filename + NUL
            out.extend_from_slice(entry.path.as_bytes());
            out.push(0);

            // Pad filename to 4-byte boundary (header + name must be aligned)
            pad4(&mut out, HEADER_SIZE + namesize);

            // Write file data
            out.extend_from_slice(file_data);

            // Pad data to 4-byte boundary
            pad4(&mut out, file_data.len());
        }

        // Write trailer
        let trailer = b"TRAILER!!!";
        let namesize = trailer.len() + 1;
        write_header(&mut out, 0, 0, 0, namesize as u32);
        out.extend_from_slice(trailer);
        out.push(0);
        pad4(&mut out, HEADER_SIZE + namesize);

        out
    }

    fn next_ino(&mut self) -> u32 {
        let ino = self.ino_counter;
        self.ino_counter += 1;
        ino
    }
}

fn write_header(out: &mut Vec<u8>, ino: u32, mode: u32, filesize: u32, namesize: u32) {
    // newc header: all fields are 8-char hex ASCII
    out.extend_from_slice(MAGIC);
    write_hex8(out, ino); // c_ino
    write_hex8(out, mode); // c_mode
    write_hex8(out, 0); // c_uid
    write_hex8(out, 0); // c_gid
    write_hex8(out, 1); // c_nlink
    write_hex8(out, 0); // c_mtime
    write_hex8(out, filesize); // c_filesize
    write_hex8(out, 0); // c_devmajor
    write_hex8(out, 0); // c_devminor
    write_hex8(out, 0); // c_rdevmajor
    write_hex8(out, 0); // c_rdevminor
    write_hex8(out, namesize); // c_namesize
    write_hex8(out, 0); // c_check
}

fn write_hex8(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08X}").as_bytes());
}

/// Pad output to 4-byte boundary based on the total bytes written so far.
fn pad4(out: &mut Vec<u8>, unaligned_len: usize) {
    let remainder = unaligned_len % 4;
    if remainder != 0 {
        let padding = 4 - remainder;
        out.extend(std::iter::repeat_n(0u8, padding));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_archive_has_trailer() {
        let archive = CpioBuilder::new().finish();
        // Should start with magic
        assert_eq!(&archive[..6], b"070701");
        // Should contain TRAILER!!!
        let s = String::from_utf8_lossy(&archive);
        assert!(s.contains("TRAILER!!!"));
    }

    #[test]
    fn archive_with_file() {
        let mut builder = CpioBuilder::new();
        builder.add_file("hello.txt", 0o644, b"Hello, world!".to_vec());
        let archive = builder.finish();

        // Magic at start
        assert_eq!(&archive[..6], b"070701");
        // Should contain filename
        assert!(archive.windows(9).any(|w| w == b"hello.txt"));
        // Should contain data
        assert!(archive.windows(13).any(|w| w == b"Hello, world!"));
    }

    #[test]
    fn archive_with_dir_and_symlink() {
        let mut builder = CpioBuilder::new();
        builder.add_dir("etc", 0o755);
        builder.add_dir("etc/systemd", 0o755);
        builder.add_symlink("etc/systemd/system/masked.service", "/dev/null");
        builder.add_file("etc/hostname", 0o644, b"cvm\n".to_vec());
        let archive = builder.finish();

        // Verify all entries are present
        let s = String::from_utf8_lossy(&archive);
        assert!(s.contains("etc/systemd"));
        assert!(s.contains("masked.service"));
        assert!(s.contains("/dev/null"));
        assert!(s.contains("etc/hostname"));
        assert!(s.contains("TRAILER!!!"));
    }

    #[test]
    fn archive_alignment() {
        // Every header+name and data section must be 4-byte aligned
        let mut builder = CpioBuilder::new();
        // Odd-length filename and data to test alignment
        builder.add_file("a", 0o644, vec![1, 2, 3]);
        builder.add_file("abc", 0o644, vec![1]);
        let archive = builder.finish();

        // Check that total size is 4-byte aligned
        assert_eq!(archive.len() % 4, 0, "archive size must be 4-byte aligned");
    }
}
