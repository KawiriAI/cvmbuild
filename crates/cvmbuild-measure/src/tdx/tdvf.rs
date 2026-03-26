//! TDVF (TDX Virtual Firmware) parser.
//!
//! Parses firmware files following the Intel TDX Virtual Firmware Design Guide,
//! Sections 11.1 (Metadata Location) and 11.2 (TDVF Descriptor).

use anyhow::{bail, ensure, Result};

use super::mrtd::LaunchContext;
use super::types::{TdvfSectionType, MR_EXTEND};

/// GUID bytes (mixed-endian) for the OVMF/TDVF table footer.
/// GUID: 96b582de-1fb2-45f7-baea-a366c55a082d
const TABLE_FOOTER_GUID: [u8; 16] = [
    0xDE, 0x82, 0xB5, 0x96, 0xB2, 0x1F, 0xF7, 0x45, 0xBA, 0xEA, 0xA3, 0x66, 0xC5, 0x5A, 0x08, 0x2D,
];

/// GUID bytes for the TDX metadata offset entry.
/// GUID: e47a6535-984a-4798-865e-4685a7bf8ec2
const TDX_METADATA_OFFSET_GUID: [u8; 16] = [
    0x35, 0x65, 0x7A, 0xE4, 0x4A, 0x98, 0x98, 0x47, 0x86, 0x5E, 0x46, 0x85, 0xA7, 0xBF, 0x8E, 0xC2,
];

const METADATA_SIGNATURE: &[u8; 4] = b"TDVF";

/// A TDVF section descriptor.
#[derive(Debug, Clone)]
pub struct TdvfSection {
    pub data_offset: u32,
    pub raw_data_size: u32,
    pub memory_address: u64,
    pub memory_data_size: u64,
    pub section_type: TdvfSectionType,
    pub attributes: u32,
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Find the offset to TDVF metadata by walking the GUID footer table.
fn find_tdvf_metadata_offset(firmware: &[u8]) -> Result<u32> {
    let length = firmware.len();

    // Footer GUID is at firmware[len-48..len-32]
    let footer_guid = &firmware[length - 48..length - 32];
    ensure!(
        footer_guid == TABLE_FOOTER_GUID,
        "can't find table footer GUID in firmware"
    );

    // Table length at firmware[len-50..len-48]
    let table_length = read_u16_le(firmware, length - 50) as usize;

    let end_offset = length - 32 - table_length;
    let mut offset = length - 50;

    while end_offset < offset {
        let entry_guid = &firmware[offset - 16..offset];
        let entry_length = read_u16_le(firmware, offset - 18) as usize;

        if entry_guid == TDX_METADATA_OFFSET_GUID {
            return Ok(read_u32_le(firmware, offset - 22));
        }

        offset -= entry_length;
    }

    bail!("can't find TDX metadata offset block entry")
}

/// Parse TDVF section descriptors from the firmware metadata.
pub fn parse_tdvf_sections(firmware: &[u8]) -> Result<Vec<TdvfSection>> {
    let metadata_offset = find_tdvf_metadata_offset(firmware)?;
    let start = firmware.len() - metadata_offset as usize;

    let sig = &firmware[start..start + 4];
    ensure!(
        sig == METADATA_SIGNATURE,
        "expected TDVF signature, got {:?}",
        std::str::from_utf8(sig).unwrap_or("<invalid>")
    );

    let version = read_u32_le(firmware, start + 8);
    ensure!(version == 1, "expected TDVF version 1, got {version}");

    let num_sections = read_u32_le(firmware, start + 12);
    let mut sections = Vec::new();

    for i in 0..num_sections as usize {
        let entry_offset = start + 16 + i * 32;
        let data_offset = read_u32_le(firmware, entry_offset);
        let raw_data_size = read_u32_le(firmware, entry_offset + 4);
        let memory_address = read_u64_le(firmware, entry_offset + 8);
        let memory_data_size = read_u64_le(firmware, entry_offset + 16);
        let section_type_raw = read_u32_le(firmware, entry_offset + 24);
        let attributes = read_u32_le(firmware, entry_offset + 28);

        let section_type = TdvfSectionType::from_u32(section_type_raw)
            .ok_or_else(|| anyhow::anyhow!("unknown TDVF section type: {section_type_raw}"))?;

        sections.push(TdvfSection {
            data_offset,
            raw_data_size,
            memory_address,
            memory_data_size,
            section_type,
            attributes,
        });
    }

    Ok(sections)
}

/// Calculate the MRTD for a TDVF-conformant firmware binary.
pub fn calculate_mrtd(firmware: &[u8]) -> Result<Vec<u8>> {
    let mut ctx = LaunchContext::new();
    let sections = parse_tdvf_sections(firmware)?;

    for section in &sections {
        let data = &firmware
            [section.data_offset as usize..(section.data_offset + section.raw_data_size) as usize];
        let should_extend = (section.attributes & MR_EXTEND) != 0;

        ctx.write_region(
            section.memory_address,
            data,
            section.memory_data_size as usize,
            should_extend,
        )?;
    }

    Ok(ctx.finalize())
}

/// Find the Configuration Firmware Volume (CFV) section data.
pub fn find_cfv(firmware: &[u8]) -> Result<Vec<u8>> {
    let sections = parse_tdvf_sections(firmware)?;

    for section in &sections {
        if section.section_type == TdvfSectionType::Cfv {
            return Ok(firmware[section.data_offset as usize
                ..(section.data_offset + section.raw_data_size) as usize]
                .to_vec());
        }
    }

    bail!("can't find CFV section in firmware")
}
