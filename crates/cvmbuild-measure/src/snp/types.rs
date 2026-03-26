//! Core enums and type definitions for SEV measurement.

/// SEV operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevMode {
    Sev,
    SevEs,
    SevSnp,
    SevSnpSvsm,
}

impl SevMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sev" => Some(Self::Sev),
            "seves" | "sev-es" => Some(Self::SevEs),
            "snp" | "sev-snp" => Some(Self::SevSnp),
            "snp:svsm" | "sev-snp:svsm" => Some(Self::SevSnpSvsm),
            _ => None,
        }
    }
}

/// Virtual Machine Monitor type — affects VMSA register values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmmType {
    Qemu,
    Ec2,
    Gce,
}

impl VmmType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "QEMU" => Some(Self::Qemu),
            "ec2" => Some(Self::Ec2),
            "gce" => Some(Self::Gce),
            _ => None,
        }
    }
}

/// Compute the 32-bit CPUID signature from family, model, and stepping.
///
/// See AMD CPUID Specification, publication #25481.
pub fn cpu_sig(family: u32, model: u32, stepping: u32) -> u32 {
    let (family_low, family_high) = if family > 0xF {
        (0xF, (family - 0x0F) & 0xFF)
    } else {
        (family, 0)
    };

    let model_low = model & 0xF;
    let model_high = (model >> 4) & 0xF;
    let stepping_low = stepping & 0xF;

    (family_high << 20) | (model_high << 16) | (family_low << 8) | (model_low << 4) | stepping_low
}

/// Known CPU signatures for EPYC processor variants.
pub const CPU_SIGS: &[(&str, u32)] = &[
    ("EPYC", 0x00800F12),
    ("EPYC-v1", 0x00800F12),
    ("EPYC-v2", 0x00800F12),
    ("EPYC-IBPB", 0x00800F12),
    ("EPYC-v3", 0x00800F12),
    ("EPYC-v4", 0x00800F12),
    ("EPYC-v5", 0x00800F12),
    ("EPYC-Rome", 0x00830F10),
    ("EPYC-Rome-v1", 0x00830F10),
    ("EPYC-Rome-v2", 0x00830F10),
    ("EPYC-Rome-v3", 0x00830F10),
    ("EPYC-Milan", 0x00A00F11),
    ("EPYC-Milan-v1", 0x00A00F11),
    ("EPYC-Milan-v2", 0x00A00F11),
    ("EPYC-Genoa", 0x00A10F10),
    ("EPYC-Genoa-v1", 0x00A10F10),
];

/// Look up a CPU signature by name.
pub fn lookup_cpu_sig(name: &str) -> Option<u32> {
    CPU_SIGS.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_sig_epyc_v4() {
        assert_eq!(cpu_sig(23, 1, 2), 0x00800F12);
    }

    #[test]
    fn cpu_sig_milan() {
        assert_eq!(cpu_sig(25, 1, 1), 0x00A00F11);
    }

    #[test]
    fn cpu_sig_genoa() {
        assert_eq!(cpu_sig(25, 17, 0), 0x00A10F10);
    }

    #[test]
    fn lookup_known_cpu() {
        assert_eq!(lookup_cpu_sig("EPYC-Milan"), Some(0x00A00F11));
        assert_eq!(lookup_cpu_sig("nonexistent"), None);
    }
}
