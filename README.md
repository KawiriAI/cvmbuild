# cvmbuild

Declarative CVM (Confidential Virtual Machine) image builder. Takes a directory with a `cvm.toml` config and an optional `Dockerfile`, produces a sealed, dm-verity-protected disk image with pre-computed TEE attestation measurements.

## Install

```bash
# Build from source (requires Rust 1.70+)
cargo build --release
sudo cp target/release/cvmbuild /usr/local/bin/
```

### Requirements

- **Rust 1.70+** (to build the binary)
- **Docker** with [buildx](https://docs.docker.com/build/buildx/) (needed at runtime for building CVM images)

## Quick Start

```bash
# Build a CVM image
cvmbuild build ./my-cvm-image/

# Or run from inside the directory (uses cwd)
cd my-cvm-image && cvmbuild build

# Validate config against security assertions
cvmbuild validate ./my-cvm-image/

# Dry run — show what would be built
cvmbuild build ./my-cvm-image/ --dry-run
```

## Image Definition Directory

An image definition is a directory containing at minimum a `cvm.toml`:

```
my-cvm-image/
  cvm.toml        # required — image configuration
  Dockerfile      # optional — if present, docker buildx build is run
  overlay/        # optional — files to overlay onto rootfs
  build/          # created by cvmbuild — output artifacts
```

If `Dockerfile` is present, cvmbuild builds it with `docker buildx` and extracts the rootfs directly. If no Dockerfile exists, the `base` image is pulled directly.

## cvm.toml Reference

```toml
[image]
id = "my-cvm"              # image identifier (used in output filenames)
version = "0.1.0"          # version string
base = "Dockerfile"        # Dockerfile path or OCI image ref
context = "../.."          # docker build context (relative to image dir)
base_image = "cvm-base:latest"  # base image tag for Dockerfile FROM

[kernel]
cmdline = "root=/dev/mapper/root lockdown=confidentiality iommu=pt"
initrd_modules = ["dm-verity", "dm-mod", "squashfs", "virtio-blk", "virtio-pci"]

[verity]
enabled = true
panic_on_corruption = true

[security]
remove = ["bash", "sh", "dash", "apt", "dpkg", "pip", "dmsetup"]
remove_dirs = ["/usr/lib/apt", "/var/lib/apt", "/var/lib/dpkg"]
lock_modules = true

[firewall]
inbound = [{ port = 8443, proto = "tcp" }]
outbound = "deny"

# Optional verity-protected data disks
[[verity_disks]]
name = "models"
device = "vdb"
mountpoint = "/mnt/models"
description = "model weights disk"

# Runtime environment variables (written to config verity disk)
[config_env]
UPSTREAM_URL = "http://127.0.0.1:8080"

# Models — auto-downloaded from HuggingFace during build
[[models]]
repo = "ggml-org/Qwen3-0.6B-GGUF"
include = ["*Q4_0*"]

# Optional service definitions (generates systemd units)
[services]
# ...

[manifest]

[manifest.snp]
ovmf_file = "OVMF.fd"     # resolved relative to OVMF_DIR
guest_features = 1         # SEV_FEATURES bitmask (0x1 = SnpActive)

[manifest.tdx]
ovmf_file = "OVMF_TDX.fd" # resolved relative to OVMF_DIR
```

## Commands

| Command | Description |
|---|---|
| `cvmbuild build <dir>` | Full pipeline: validate, build container, extract, overlay, seal |
| `cvmbuild validate <dir>` | Validate config against security assertions |
| `cvmbuild checks` | List all available assertion checks |
| `cvmbuild extract --base <ref>` | Extract rootfs from an OCI image |
| `cvmbuild seal --rootfs <path>` | Seal a rootfs into a CVM disk image |
| `cvmbuild verity-disk --source <dir> -o <path>` | Create an ext4+verity disk from a directory |
| `cvmbuild measure` | Compute TEE measurements from built artifacts |
| `cvmbuild download-models` | Download models specified in `[[models]]` |
| `cvmbuild boot-cmd` | Print QEMU boot command from built artifacts |

### Build Options

```
cvmbuild [OPTIONS] <image_dir> build [BUILD_OPTIONS]

Options:
  --ovmf-dir <dir>  OVMF firmware directory (or set OVMF_DIR env)
  -v, --verbose     Debug-level output

Build Options:
  --skip-container    Skip container build, use existing image
  --no-download       Skip model downloads (fail if missing)
  -o, --output <dir>  Output directory (default: build)
  --dry-run           Show what would be built
```

## Output Artifacts

After `cvmbuild build`, the output directory contains:

```
build/
  {id}_{version}.raw       # GPT disk image (squashfs + dm-verity)
  {id}_{version}.vmlinuz   # extracted kernel
  {id}_{version}.initrd    # initrd with verity activation
  {id}_{version}.roothash  # dm-verity root hash
  manifest.json            # attestation manifest with TEE measurements
```

## TEE Measurements

The manifest includes pre-computed measurements for:

**AMD SEV-SNP** — `LAUNCH_DIGEST` per CPU generation (EPYC-v4, Rome, Milan, Genoa).

**Intel TDX** — `MRTD` (firmware), `RTMR0` (firmware config), `RTMR1` (kernel), `RTMR2` (cmdline + initrd), `RTMR3` (reserved).

Measurements are printed after a successful build and written to `manifest.json`.

Requires `[manifest.snp]` and/or `[manifest.tdx]` with `ovmf_file` set in `cvm.toml`. The firmware path is resolved relative to `OVMF_DIR` (passed via `--ovmf-dir` or environment variable).

## Container Runtime

cvmbuild uses **docker buildx** for container builds and rootfs extraction.
