# cvmbuild

Build and package confidential-VM disk images. Reads a directory with a `cvm.toml`
and a `Dockerfile`, runs the Dockerfile through `docker buildx`, then extracts,
overlays, hardens, squashfses, dm-verity-wraps, GPT-packs, and computes
SNP/TDX attestation measurements over the result.

cvmbuild is intentionally distro-agnostic: nothing inside the tool knows
about apt, dnf, pacman, or any specific Linux distribution. The Dockerfile
is the source of truth for everything inside the image. cvmbuild's job is
*build it (via Docker) and package it*. A Fedora image works the same way
as a Debian image works the same way as an Alpine image — provided the
result has a kernel in `/boot` and a workable rootfs.

## Binaries

| Binary | Role |
|---|---|
| `cvmbuild` | Main CLI: build, package, measure, verify, diff, etc. |
| `cvmbuild-measure` | Standalone CLI for SNP/TDX measurement computation from raw inputs (kernel + initrd + OVMF + cmdline). Useful in audit/CI pipelines that want to re-derive expected measurements without running the full builder. |

For the apt-cache proxy that used to live here as `cvmbuild-aptcache`, see
**teehost** — it's now an in-process subsystem of teehost on a kawiri host.
Operators on a laptop don't need a proxy; the Dockerfile defaults route apt
direct to `snapshot.ubuntu.com`.

## Install

```bash
cargo build --release
sudo cp target/release/cvmbuild target/release/cvmbuild-measure /usr/local/bin/
```

### Requirements

- Rust 1.70+ (build only)
- Docker with [buildx](https://docs.docker.com/build/buildx/) (runtime)
- e2fsprogs (`mke2fs`) for verity-disk creation
- `cryptsetup` is **not** required on the host — verity is computed in pure Rust

## Quick start

```bash
# 1. (kawiri host only — laptops can skip) ensure teehost's apt cache is running.
#    teehost auto-starts it when [aptcache].enabled = true in teehost.toml.
#    Set APT_MIRROR so cvmbuild forwards it to docker buildx; cvmbuild also
#    auto-injects the env var if you set it.
export APT_MIRROR=http://127.0.0.1:19479

# 2. Build any base images your Dockerfile FROMs. cvmbuild does NOT do this
#    for you — it builds exactly the Dockerfile you point it at.
docker buildx build --network=host \
  --build-arg APT_MIRROR=$APT_MIRROR \
  -t cvm-base:latest \
  -f base-image/Dockerfile base-image/

# 3. Build the CVM image.
cvmbuild build ./my-cvm-image/

# 4. Verify the build matches what manifest.json claims.
cvmbuild verify -o ./my-cvm-image/build/

# 5. (CI) Verify the build matches a checked-in expected manifest.
cvmbuild verify -o ./my-cvm-image/build/ --against ./my-cvm-image/manifest.expected.json
```

## Image definition directory

```
my-cvm-image/
  cvm.toml        # required — image config
  Dockerfile      # optional — built with `docker buildx` if present
  overlay/        # optional — files copied onto rootfs
  build/          # created by cvmbuild — output artifacts (gitignore this)
  disks/          # created by cvmbuild — model + config disk source dirs (gitignore this)
```

If `Dockerfile` is present, cvmbuild builds it with `docker buildx` and
extracts the resulting rootfs. If no Dockerfile, `[image].base` is pulled
directly as an OCI ref.

## cvm.toml reference

```toml
[image]
id = "my-cvm"
version = "0.1.0"
base = "Dockerfile"            # path to Dockerfile, or OCI image ref
context = "../.."              # docker build context (relative to image dir; defaults to Dockerfile parent)

# Generic Docker passthroughs. cvmbuild does NOT interpret these — it just
# forwards them to `docker buildx build`. Use them to thread an apt mirror,
# kawa version, registry token, or whatever your Dockerfile expects.
build_args = { APT_MIRROR = "http://127.0.0.1:19479", KAWA_VERSION = "0.1.1" }
build_secrets = [
  { id = "registry_token", src = "secrets/registry.txt" },
]

[kernel]
cmdline = "root=/dev/mapper/root lockdown=confidentiality iommu=pt"
initrd_modules = ["dm-verity", "dm-mod", "squashfs", "virtio-blk", "virtio-pci"]

[verity]
enabled = true
panic_on_corruption = true

[security]
# Lists are deliberately distro-flavored at the cvm.toml level. cvmbuild's
# mechanism (rm files / dirs from the rootfs after Docker build) is generic;
# the *contents* below presume Debian-family. For Fedora override with dnf
# paths, etc.
remove = ["bash", "sh", "dash", "apt", "dpkg", "pip", "dmsetup"]
remove_dirs = ["/usr/lib/apt", "/var/lib/apt", "/var/lib/dpkg"]
lock_modules = true

[firewall]
inbound = [{ port = 8443, proto = "tcp" }]
outbound = "deny"

# Verity-protected data disks (separate raw images alongside the rootfs)
[[verity_disks]]
name = "models"
device = "vdb"
mountpoint = "/mnt/models"
description = "model weights disk"
source = "disks/models"

# Auto-downloaded HuggingFace models (lay down into disks/models/)
[[models]]
repo = "ggml-org/Qwen3-0.6B-GGUF"
include = ["*Q4_0*"]

# Runtime env vars — generated as config.env on the config verity disk
[config_env]
UPSTREAM_URL = "http://127.0.0.1:8080"

[services]
network = { ntp_servers = ["162.159.200.1"] }

[[services.units]]
name = "kawa"
description = "kawa gateway"
exec = "/usr/local/bin/kawa"
hardening = "full"

[manifest.snp]
ovmf_file = "OVMF.fd"        # resolved relative to --ovmf-dir
guest_features = 1            # SEV_FEATURES bitmask (0x1 = SnpActive)

[manifest.tdx]
ovmf_file = "OVMF_TDX.fd"    # resolved relative to --ovmf-dir

[assert]
profile = "production"        # production | standard | minimal
```

### What cvmbuild does NOT do

A few common expectations that *are not* in scope, by design:

- **It does not download or stage `kawa`, OVMF, or any other binaries.**
  Whatever the Dockerfile fetches, the Dockerfile fetches.
- **It does not auto-build base images.** If your Dockerfile says
  `FROM cvm-base:latest`, you build that yourself first.
- **It does not modify the Dockerfile.** Earlier versions used to
  pre-process Dockerfiles to inject apt-mirror secret mounts; that's
  gone. Use `[image].build_args` or `[image].build_secrets` to pass
  things through, and your Dockerfile uses them with normal Docker
  syntax.
- **It does not start the aptcache proxy.** That moved to teehost — see
  teehost's `[aptcache]` config.

## Commands

| Command | Description |
|---|---|
| `cvmbuild build` | Full pipeline: validate → docker buildx → extract rootfs → apply overlay → harden → squashfs → dm-verity → GPT → measure → manifest.json |
| `cvmbuild validate` | Validate cvm.toml against the active assertion profile |
| `cvmbuild checks` | List all available assertion checks |
| `cvmbuild extract --base <ref>` | Extract rootfs from an OCI image (no seal) |
| `cvmbuild seal --rootfs <path>` | Seal an existing rootfs (squashfs → verity → GPT) |
| `cvmbuild verity-disk --source <dir> -o <path>` | Create a standalone ext4+verity disk |
| `cvmbuild measure` | Recompute TEE measurements from built artifacts; diffs against manifest.json |
| `cvmbuild verify` | Re-derive every hash + measurement from artifacts and assert match. Returns non-zero on drift |
| `cvmbuild verify --against <manifest>` | Verify against a checked-in expected-manifest file (CI gate) |
| `cvmbuild diff <a> <b>` | Compare two build output dirs at manifest level + walk-level squashfs diff if rootfs_roothash differs |
| `cvmbuild download-models` | Pre-download all `[[models]]` (does not build the image) |
| `cvmbuild boot-cmd` | Print a QEMU boot command for the built artifacts |

### Build options

```
cvmbuild [GLOBAL] [<image_dir>] build [BUILD_OPTIONS]

Global:
  --ovmf-dir <dir>     OVMF firmware directory (or OVMF_DIR env)
  -v, --verbose        Debug-level output

Build:
  --skip-container     Skip container build, reuse existing rootfs
  --no-download        Don't fetch missing models — fail instead
  -o, --output <dir>   Output directory (default: build)
  --dry-run            Print plan, do nothing
```

## Output artifacts

```
build/
  <id>_<version>.raw       # GPT disk image (squashfs partition + verity hash partition)
  <id>_<version>.vmlinuz   # kernel extracted from rootfs /boot/
  <id>_<version>.initrd    # initrd extracted from rootfs /boot/
  <id>_<version>.roothash  # dm-verity root hash
  models.img / config.img  # per-disk verity images (one per [[verity_disks]])
  models.roothash, models.hashoffset
  manifest.json            # SNP/TDX measurements + recorded inputs
```

When run under `sudo`, cvmbuild chowns `build/` back to `$SUDO_USER` on
success. `disks/` is intentionally left alone because `mke2fs -d` bakes
source-file ownership into the verity disk; chowning would silently drift
the next rebuild's verity-disk roothash. Both are gitignored anyway.

## TEE measurements

The manifest includes pre-computed measurements for:

- **AMD SEV-SNP** — `LAUNCH_DIGEST` for EPYC-v4, Rome, Milan, Genoa.
- **Intel TDX** — `MRTD` (firmware), `RTMR0` (firmware config + DSDT),
  `RTMR1` (kernel), `RTMR2` (cmdline + initrd), `RTMR3` (reserved).

Requires `[manifest.snp]` and/or `[manifest.tdx]` with `ovmf_file` set.
Firmware path resolves relative to `--ovmf-dir` (or `OVMF_DIR` env).

For audit/CI pipelines that want to recompute measurements outside the
full build flow:

```bash
cvmbuild-measure snp \
  --ovmf OVMF.fd --kernel vmlinuz --initrd initrd \
  --cmdline "root=/dev/mapper/root …" \
  --vcpus 1 --guest-features 1

cvmbuild-measure tdx \
  --ovmf OVMF_TDX.fd --kernel vmlinuz --initrd initrd \
  --cmdline "…" --dsdt CvmDsdt.aml
```

## Container runtime

cvmbuild shells out to `docker buildx` for builds and rootfs extraction. It
does not interact with the Docker daemon API directly. Any BuildKit-supported
backend works (local, registry-cached, etc.) — set `BUILDX_CACHE` to enable
cache-from/to plumbing.

## Workspace

```
crates/
  cvmbuild-cli/        Main binary
  cvmbuild-config/     cvm.toml schema + assertion catalog (used as a git-dep by teehost)
  cvmbuild-oci/        docker buildx wrapper + rootfs extraction
  cvmbuild-rootfs/     overlay, hardening, service synthesis, binary stripping
  cvmbuild-image/      squashfs + dm-verity + GPT + manifest assembly
  cvmbuild-squashfs/   pure-Rust squashfs reader/writer
  cvmbuild-measure/    pure SNP/TDX measurement computation (also a binary; used as a git-dep by teehost)
  # cvmbuild-aptcache/  ← removed, lives in teehost now
```

`cvmbuild-config` and `cvmbuild-measure` are deliberately small public
crates — teehost depends on them as git-deps to validate cvm.tomls and
recompute measurements server-side without pulling in the full builder.
