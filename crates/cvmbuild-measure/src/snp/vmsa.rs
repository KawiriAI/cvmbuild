//! VMSA (Virtual Machine Save Area) page builder.
//!
//! Constructs 4096-byte VMSA pages matching the SevEsSaveArea structure.
//! Field offsets derived from AMD APM Vol 2 Table B-4.

use super::types::VmmType;
use crate::common::buf::StructBuffer;

// SevEsSaveArea field offsets (4096 bytes total).
// Each VmcbSeg is 16 bytes: u16 selector, u16 attrib, u32 limit, u64 base.
const O_ES: usize = 0x000;
const O_CS: usize = 0x010;
const O_SS: usize = 0x020;
const O_DS: usize = 0x030;
const O_FS: usize = 0x040;
const O_GS: usize = 0x050;
const O_GDTR: usize = 0x060;
const O_LDTR: usize = 0x070;
const O_IDTR: usize = 0x080;
const O_TR: usize = 0x090;
const O_EFER: usize = 0x0D0;
const O_CR4: usize = 0x148;
const O_CR0: usize = 0x158;
const O_DR7: usize = 0x160;
const O_DR6: usize = 0x168;
const O_RFLAGS: usize = 0x170;
const O_RIP: usize = 0x178;
const O_RDX: usize = 0x310;
const O_G_PAT: usize = 0x268;
const O_SEV_FEATURES: usize = 0x3B0;
const O_XCR0: usize = 0x3E8;
const O_MXCSR: usize = 0x408;
const O_X87_FCW: usize = 0x410;

const BSP_EIP: u64 = 0xFFFFFFF0;

fn write_vmcb_seg(
    buf: &mut StructBuffer,
    offset: usize,
    selector: u16,
    attrib: u16,
    limit: u32,
    base: u64,
) {
    buf.set_u16(offset, selector);
    buf.set_u16(offset + 2, attrib);
    buf.set_u32(offset + 4, limit);
    buf.set_u64(offset + 8, base);
}

/// Build a standard VMSA page (for SEV-ES and SEV-SNP modes).
pub fn build_save_area(eip: u64, sev_features: u64, vcpu_sig: u32, vmm_type: VmmType) -> Vec<u8> {
    let mut g_pat: u64 = 0x7040600070406;

    let (cs_flags, ss_flags, tr_flags, rdx, mxcsr, fcw): (u16, u16, u16, u64, u32, u16) =
        match vmm_type {
            VmmType::Qemu => (0x9B, 0x93, 0x8B, vcpu_sig as u64, 0x1F80, 0x37F),
            VmmType::Ec2 => {
                let cs = if eip == 0xFFFFFFF0 { 0x9A } else { 0x9B };
                (cs, 0x92, 0x83, 0, 0, 0)
            }
            VmmType::Gce => {
                g_pat = 0x00070106;
                (0x9B, 0x93, 0x8B, 0x600, 0, 0)
            }
        };

    let mut buf = StructBuffer::new(4096);

    write_vmcb_seg(&mut buf, O_ES, 0, 0x93, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_CS, 0xF000, cs_flags, 0xFFFF, eip & 0xFFFF0000);
    write_vmcb_seg(&mut buf, O_SS, 0, ss_flags, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_DS, 0, 0x93, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_FS, 0, 0x93, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_GS, 0, 0x93, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_GDTR, 0, 0, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_IDTR, 0, 0, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_LDTR, 0, 0x82, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_TR, 0, tr_flags, 0xFFFF, 0);

    buf.set_u64(O_EFER, 0x1000);
    buf.set_u64(O_CR4, 0x40);
    buf.set_u64(O_CR0, 0x10);
    buf.set_u64(O_DR7, 0x400);
    buf.set_u64(O_DR6, 0xFFFF0FF0);
    buf.set_u64(O_RFLAGS, 0x2);
    buf.set_u64(O_RIP, eip & 0xFFFF);
    buf.set_u64(O_G_PAT, g_pat);
    buf.set_u64(O_RDX, rdx);
    buf.set_u64(O_SEV_FEATURES, sev_features);
    buf.set_u64(O_XCR0, 0x1);
    buf.set_u32(O_MXCSR, mxcsr);
    buf.set_u16(O_X87_FCW, fcw);

    buf.to_vec()
}

/// Build an SVSM VMSA page (for SEV-SNP-SVSM mode).
pub fn build_svsm_save_area(
    eip: u64,
    sev_features: u64,
    vcpu_sig: u32,
    vmm_type: VmmType,
) -> Vec<u8> {
    let mxcsr: u32 = if vmm_type == VmmType::Qemu { 0x1F80 } else { 0 };

    let mut buf = StructBuffer::new(4096);

    write_vmcb_seg(&mut buf, O_ES, 16, 0xC93, 0xFFFFFFFF, 0);
    write_vmcb_seg(&mut buf, O_CS, 8, 0xC9B, 0xFFFFFFFF, 0);
    write_vmcb_seg(&mut buf, O_SS, 16, 0xC93, 0xFFFFFFFF, 0);
    write_vmcb_seg(&mut buf, O_DS, 16, 0xC93, 0xFFFFFFFF, 0);
    write_vmcb_seg(&mut buf, O_FS, 16, 0xC93, 0xFFFFFFFF, 0);
    write_vmcb_seg(&mut buf, O_GS, 0, 0x093, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_GDTR, 0, 0, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_IDTR, 0, 0, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_LDTR, 0, 0x82, 0xFFFF, 0);
    write_vmcb_seg(&mut buf, O_TR, 0, 0x8B, 0xFFFF, 0);

    buf.set_u64(O_EFER, 0x1000);
    buf.set_u64(O_CR4, 0x40);
    buf.set_u64(O_CR0, 0x11);
    buf.set_u64(O_DR7, 0x400);
    buf.set_u64(O_DR6, 0xFFFF0FF0);
    buf.set_u64(O_RFLAGS, 0x2);
    buf.set_u64(O_RIP, eip);
    buf.set_u64(O_G_PAT, 0x7040600070406);
    buf.set_u64(O_RDX, vcpu_sig as u64);
    buf.set_u64(O_SEV_FEATURES, sev_features);
    buf.set_u64(O_XCR0, 0x1);
    buf.set_u32(O_MXCSR, mxcsr);
    // NOTE: x87_fcw is intentionally NOT set, matching the Python original

    buf.to_vec()
}

/// Generate VMSA pages for all vCPUs (standard SEV-ES/SEV-SNP).
///
/// vCPU 0 is the BSP (uses BSP_EIP), others are APs (use ap_eip).
pub fn vmsa_pages(
    ap_eip: u32,
    vcpu_sig: u32,
    guest_features: u64,
    vmm_type: VmmType,
    vcpus: u32,
) -> Vec<Vec<u8>> {
    let bsp = build_save_area(BSP_EIP, guest_features, vcpu_sig, vmm_type);
    let ap = if ap_eip != 0 {
        build_save_area(ap_eip as u64, guest_features, vcpu_sig, vmm_type)
    } else {
        bsp.clone()
    };

    (0..vcpus)
        .map(|i| if i == 0 { bsp.clone() } else { ap.clone() })
        .collect()
}

/// Generate VMSA pages for all vCPUs (SVSM mode).
pub fn svsm_vmsa_pages(ap_eip: u32, vcpu_sig: u32, vcpus: u32, vmm_type: VmmType) -> Vec<Vec<u8>> {
    let sev_features: u64 = 0x1;
    let page = build_svsm_save_area(ap_eip as u64, sev_features, vcpu_sig, vmm_type);

    (0..vcpus).map(|_| page.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_save_area_produces_4096_bytes() {
        let page = build_save_area(0xFFFFFFF0, 0x21, 0x00800F12, VmmType::Qemu);
        assert_eq!(page.len(), 4096);
    }

    #[test]
    fn build_svsm_save_area_produces_4096_bytes() {
        let page = build_svsm_save_area(0x8000, 0x1, 0x00800F12, VmmType::Qemu);
        assert_eq!(page.len(), 4096);
    }

    #[test]
    fn vmsa_pages_bsp_differs_from_ap() {
        let pages = vmsa_pages(0x1234, 0x00800F12, 0x21, VmmType::Qemu, 2);
        assert_eq!(pages.len(), 2);
        assert_ne!(pages[0], pages[1]);
    }
}
