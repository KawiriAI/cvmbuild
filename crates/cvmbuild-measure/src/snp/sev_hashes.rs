//! SEV hash table construction for kernel/initrd/cmdline.
//!
//! Must produce identical binary layout to QEMU's implementation.

use sha2::{Digest, Sha256};

use crate::common::buf::StructBuffer;
use crate::common::guid::guid_to_le_bytes;

const SHA256_DIGEST_SIZE: usize = 32;
const GUID_SIZE: usize = 16;
const LENGTH_SIZE: usize = 2;

/// Entry: GUID (16) + length (2) + hash (32) = 50 bytes
const ENTRY_SIZE: usize = GUID_SIZE + LENGTH_SIZE + SHA256_DIGEST_SIZE;

/// Table: GUID (16) + length (2) + 3 entries = 168 bytes
const TABLE_SIZE: usize = GUID_SIZE + LENGTH_SIZE + 3 * ENTRY_SIZE;

/// Padded to 16-byte alignment = 176 bytes
const PADDED_TABLE_SIZE: usize = (TABLE_SIZE + 15) & !15;

const SEV_HASH_TABLE_HEADER_GUID: &str = "9438d606-4f22-4cc9-b479-a793d411fd21";
const SEV_KERNEL_ENTRY_GUID: &str = "4de79437-abd2-427f-b835-d5b172d2045b";
const SEV_INITRD_ENTRY_GUID: &str = "44baf731-3a2f-4bd7-9af1-41e29169781d";
const SEV_CMDLINE_ENTRY_GUID: &str = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a";

fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; SHA256_DIGEST_SIZE];
    out.copy_from_slice(&result);
    out
}

fn write_entry(
    buf: &mut StructBuffer,
    offset: usize,
    guid: &str,
    hash_value: &[u8; SHA256_DIGEST_SIZE],
) -> usize {
    let guid_bytes = guid_to_le_bytes(guid).expect("invalid GUID in SEV hashes table");
    buf.set_bytes(offset, &guid_bytes);
    let offset = offset + GUID_SIZE;
    buf.set_u16(offset, ENTRY_SIZE as u16);
    let offset = offset + LENGTH_SIZE;
    buf.set_bytes(offset, hash_value);
    offset + SHA256_DIGEST_SIZE
}

/// SEV hash table containing SHA-256 hashes of kernel, initrd, and cmdline.
pub struct SevHashes {
    cmdline_hash: [u8; SHA256_DIGEST_SIZE],
    initrd_hash: [u8; SHA256_DIGEST_SIZE],
    kernel_hash: [u8; SHA256_DIGEST_SIZE],
}

impl SevHashes {
    /// Create from raw data bytes (kernel bytes, initrd bytes, cmdline string).
    pub fn new(kernel_data: &[u8], initrd_data: &[u8], append: Option<&str>) -> Self {
        let kernel_hash = sha256(kernel_data);
        let initrd_hash = sha256(initrd_data);

        let cmdline_bytes = match append {
            Some(s) => {
                let mut v = s.as_bytes().to_vec();
                v.push(0);
                v
            }
            None => vec![0],
        };
        let cmdline_hash = sha256(&cmdline_bytes);

        Self {
            cmdline_hash,
            initrd_hash,
            kernel_hash,
        }
    }

    /// Build the padded SEV hash table (176 bytes).
    pub fn construct_table(&self) -> Vec<u8> {
        let mut buf = StructBuffer::new(PADDED_TABLE_SIZE);
        let mut offset = 0;

        // Table header: GUID + length
        let header_guid =
            guid_to_le_bytes(SEV_HASH_TABLE_HEADER_GUID).expect("invalid header GUID");
        buf.set_bytes(offset, &header_guid);
        offset += GUID_SIZE;
        buf.set_u16(offset, TABLE_SIZE as u16);
        offset += LENGTH_SIZE;

        // Entry order must match: cmdline, initrd, kernel
        offset = write_entry(&mut buf, offset, SEV_CMDLINE_ENTRY_GUID, &self.cmdline_hash);
        offset = write_entry(&mut buf, offset, SEV_INITRD_ENTRY_GUID, &self.initrd_hash);
        write_entry(&mut buf, offset, SEV_KERNEL_ENTRY_GUID, &self.kernel_hash);

        buf.to_vec()
    }

    /// Build a 4096-byte page containing the hash table at the given offset.
    pub fn construct_page(&self, offset: usize) -> Vec<u8> {
        assert!(offset < 4096, "offset {offset} exceeds page size");
        let table = self.construct_table();
        let mut page = vec![0u8; 4096];
        page[offset..offset + table.len()].copy_from_slice(&table);
        page
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_176_bytes() {
        let hashes = SevHashes::new(b"", b"", None);
        assert_eq!(hashes.construct_table().len(), 176);
    }

    #[test]
    fn page_is_4096_bytes() {
        let hashes = SevHashes::new(b"", b"", None);
        assert_eq!(hashes.construct_page(0).len(), 4096);
    }
}
