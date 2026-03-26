//! Core types for TDX measurement.

/// TDVF section types (TDX Virtual Firmware Design Guide, 11.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TdvfSectionType {
    Bfv = 0,
    Cfv = 1,
    TdHob = 2,
    TempMem = 3,
}

impl TdvfSectionType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Bfv),
            1 => Some(Self::Cfv),
            2 => Some(Self::TdHob),
            3 => Some(Self::TempMem),
            _ => None,
        }
    }
}

/// Section attribute: content should be measured via MR.EXTEND.
pub const MR_EXTEND: u32 = 1 << 0;

/// Section attribute: page augmentation.
pub const PAGE_AUG: u32 = 1 << 1;

/// GPU model for RTMR0 ACPI hash selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuModel {
    None,
    H100,
    B200,
}

impl GpuModel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "none" => Some(Self::None),
            "h100" => Some(Self::H100),
            "b200" => Some(Self::B200),
            _ => None,
        }
    }
}
