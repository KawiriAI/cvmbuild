//! OVMF firmware binary parser.
//!
//! Parses the OVMF footer table and SEV metadata sections.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::common::guid::{guid_to_le_bytes, le_bytes_to_guid};

pub const FOUR_GB: u64 = 0x100000000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SectionType {
    SnpSecMem = 1,
    SnpSecrets = 2,
    Cpuid = 3,
    SvsmCaa = 4,
    SnpKernelHashes = 0x10,
}

impl SectionType {
    fn from_u32(v: u32) -> Result<Self> {
        match v {
            1 => Ok(Self::SnpSecMem),
            2 => Ok(Self::SnpSecrets),
            3 => Ok(Self::Cpuid),
            4 => Ok(Self::SvsmCaa),
            0x10 => Ok(Self::SnpKernelHashes),
            _ => anyhow::bail!("unknown SEV metadata section type: {v}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetadataSection {
    pub gpa: u32,
    pub size: u32,
    pub section_type: SectionType,
}

const OVMF_TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const SEV_HASH_TABLE_RV_GUID: &str = "7255371f-3a3b-4b04-927b-1da6efa8d454";
const SEV_ES_RESET_BLOCK_GUID: &str = "00f771de-1a7e-4fcb-890e-68c77e2fb44e";
const OVMF_SEV_META_DATA_GUID: &str = "dc886566-984a-4798-a75e-5585a7bf67cc";

pub struct Ovmf {
    data: Vec<u8>,
    table: HashMap<String, Vec<u8>>,
    metadata: Vec<MetadataSection>,
    gpa: u64,
}

impl Ovmf {
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_end(path, FOUR_GB)
    }

    pub fn load_with_end(path: &Path, end_at: u64) -> Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_bytes(data, end_at)
    }

    pub fn from_bytes(data: Vec<u8>, end_at: u64) -> Result<Self> {
        let mut ovmf = Self {
            gpa: end_at - data.len() as u64,
            data,
            table: HashMap::new(),
            metadata: Vec::new(),
        };
        ovmf.parse_footer_table()?;
        ovmf.parse_sev_metadata()?;
        Ok(ovmf)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn gpa(&self) -> u64 {
        self.gpa
    }

    pub fn metadata_items(&self) -> &[MetadataSection] {
        &self.metadata
    }

    pub fn has_metadata_section(&self, st: SectionType) -> bool {
        self.metadata.iter().any(|s| s.section_type == st)
    }

    pub fn is_sev_hashes_table_supported(&self) -> bool {
        self.table.contains_key(SEV_HASH_TABLE_RV_GUID)
            && self.sev_hashes_table_gpa().unwrap_or(0) != 0
    }

    pub fn sev_hashes_table_gpa(&self) -> Result<u32> {
        let entry = self
            .table
            .get(SEV_HASH_TABLE_RV_GUID)
            .context("SEV_HASH_TABLE_RV_GUID not found in OVMF table")?;
        Ok(u32::from_le_bytes(entry[..4].try_into().unwrap()))
    }

    pub fn sev_es_reset_eip(&self) -> Result<u32> {
        let entry = self
            .table
            .get(SEV_ES_RESET_BLOCK_GUID)
            .context("SEV_ES_RESET_BLOCK_GUID not found in OVMF table")?;
        Ok(u32::from_le_bytes(entry[..4].try_into().unwrap()))
    }

    fn parse_footer_table(&mut self) -> Result<()> {
        let size = self.data.len();
        let entry_header_size = 18; // 2 (size) + 16 (guid)

        if size < 32 + entry_header_size {
            return Ok(());
        }

        let start = size - 32 - entry_header_size;
        let footer_guid = &self.data[start + 2..start + 18];
        let footer_size = u16::from_le_bytes(self.data[start..start + 2].try_into().unwrap());

        let expected_guid = guid_to_le_bytes(OVMF_TABLE_FOOTER_GUID)?;
        if footer_guid != expected_guid {
            return Ok(()); // no footer table
        }

        let table_size = footer_size as usize - entry_header_size;
        if start < table_size {
            return Ok(());
        }

        let table_bytes = &self.data[start - table_size..start];
        let mut pos = table_bytes.len();

        while pos >= entry_header_size {
            let entry_offset = pos - entry_header_size;
            let entry_size = u16::from_le_bytes(
                table_bytes[entry_offset..entry_offset + 2]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let entry_guid_bytes: [u8; 16] = table_bytes[entry_offset + 2..entry_offset + 18]
                .try_into()
                .unwrap();

            if entry_size < entry_header_size {
                anyhow::bail!("invalid entry size in OVMF footer table");
            }

            let guid_str = le_bytes_to_guid(&entry_guid_bytes);
            let data_start = entry_offset - (entry_size - entry_header_size);
            let entry_data = table_bytes[data_start..entry_offset].to_vec();
            self.table.insert(guid_str, entry_data);

            pos -= entry_size;
        }

        Ok(())
    }

    fn parse_sev_metadata(&mut self) -> Result<()> {
        let entry = match self.table.get(OVMF_SEV_META_DATA_GUID) {
            Some(e) => e.clone(),
            None => return Ok(()),
        };

        let offset_from_end = u32::from_le_bytes(entry[..4].try_into().unwrap()) as usize;
        let start = self.data.len() - offset_from_end;

        let sig = &self.data[start..start + 4];
        if sig != b"ASEV" {
            anyhow::bail!("wrong SEV metadata signature");
        }

        let header_size = u32::from_le_bytes(self.data[start + 4..start + 8].try_into().unwrap());
        let version = u32::from_le_bytes(self.data[start + 8..start + 12].try_into().unwrap());
        if version != 1 {
            anyhow::bail!("wrong SEV metadata version: {version}");
        }

        let num_items = u32::from_le_bytes(self.data[start + 12..start + 16].try_into().unwrap());
        let items_start = start + 16;

        for i in 0..num_items as usize {
            let item_off = items_start + i * 12;
            if item_off + 12 > start + header_size as usize {
                break;
            }

            let gpa = u32::from_le_bytes(self.data[item_off..item_off + 4].try_into().unwrap());
            let sz = u32::from_le_bytes(self.data[item_off + 4..item_off + 8].try_into().unwrap());
            let st = u32::from_le_bytes(self.data[item_off + 8..item_off + 12].try_into().unwrap());

            self.metadata.push(MetadataSection {
                gpa,
                size: sz,
                section_type: SectionType::from_u32(st)?,
            });
        }

        Ok(())
    }
}

/// SVSM firmware binary — extends OVMF with different reset EIP logic.
pub struct Svsm {
    inner: Ovmf,
}

const SVSM_INFO_GUID: &str = "a789a612-0597-4c4b-a49f-cbb1fe9d1ddd";

impl Svsm {
    pub fn load(path: &Path, end_at: u64) -> Result<Self> {
        let inner = Ovmf::load_with_end(path, end_at)?;
        Ok(Self { inner })
    }

    pub fn from_bytes(data: Vec<u8>, end_at: u64) -> Result<Self> {
        let inner = Ovmf::from_bytes(data, end_at)?;
        Ok(Self { inner })
    }

    pub fn data(&self) -> &[u8] {
        self.inner.data()
    }

    pub fn gpa(&self) -> u64 {
        self.inner.gpa()
    }

    pub fn metadata_items(&self) -> &[MetadataSection] {
        self.inner.metadata_items()
    }

    pub fn has_metadata_section(&self, st: SectionType) -> bool {
        self.inner.has_metadata_section(st)
    }

    pub fn sev_es_reset_eip(&self) -> Result<u32> {
        let entry = self
            .inner
            .table
            .get(SVSM_INFO_GUID)
            .context("SVSM_INFO_GUID not found in SVSM table")?;
        let offset = u32::from_le_bytes(entry[..4].try_into().unwrap());
        Ok(offset + self.inner.gpa as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    #[test]
    fn parse_amdsev_suffix() {
        let ovmf = Ovmf::load(&fixtures().join("ovmf_AmdSev_suffix.bin")).unwrap();
        assert!(!ovmf.metadata_items().is_empty());
        assert!(ovmf.sev_es_reset_eip().is_ok());
        assert!(ovmf.has_metadata_section(SectionType::SnpKernelHashes));
    }

    #[test]
    fn parse_ovmfx64_suffix() {
        let ovmf = Ovmf::load(&fixtures().join("ovmf_OvmfX64_suffix.bin")).unwrap();
        // OvmfX64 should NOT have SNP_KERNEL_HASHES
        assert!(!ovmf.has_metadata_section(SectionType::SnpKernelHashes));
    }
}
