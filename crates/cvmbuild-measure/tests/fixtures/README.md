# Test Fixtures

Binary fixtures used to verify launch measurement calculations. All files are copied from [virtee/sev-snp-measure/tests/fixtures](https://github.com/virtee/sev-snp-measure/tree/main/tests/fixtures) (Apache 2.0).

## Files

| File | Description | Source |
|---|---|---|
| `ovmf_AmdSev_suffix.bin` | Last 4KB of OVMF built from `OvmfPkg/AmdSev/AmdSevX64.dsc` (contains GUID footer table with SEV metadata) | edk2 `edk2-stable202405` |
| `ovmf_OvmfX64_suffix.bin` | Last 4KB of OVMF built from `OvmfPkg/OvmfPkgX64.dsc` | edk2 `edk2-stable202405` |
| `svsm.bin` | Coconut SVSM binary | [coconut-svsm/svsm@bebb485a](https://github.com/coconut-svsm/svsm/commit/bebb485aa94b84e59aca905f62414db885efc419) |
| `svsm_ovmf.fd` | OVMF built for use with SVSM (boots at VMPL1) | [coconut-svsm/edk2@e824edbc](https://github.com/coconut-svsm/edk2/commit/e824edbc98303a1de73f233aca25ea6512d3a29b) |

## Purpose

The expected test hashes in `snp/guest.rs` and `snp/ovmf.rs` were ported from the upstream Python project's test suite. These fixtures exist solely to verify that our Rust port produces identical launch digests.
