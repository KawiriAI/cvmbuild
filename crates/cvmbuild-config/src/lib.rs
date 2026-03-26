use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

pub mod assert;

/// Top-level CVM build configuration.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub image: ImageConfig,
    pub kernel: KernelConfig,
    pub verity: VerityConfig,
    #[serde(default)]
    pub overlay: OverlayConfig,
    pub security: SecurityConfig,
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub verity_disks: Vec<VerityDiskConfig>,
    #[serde(default)]
    pub services: ServicesConfig,
    #[serde(default)]
    pub manifest: ManifestConfig,
    #[serde(default)]
    pub models: Vec<ModelConfig>,
    /// Environment variables to write as config.env on the config verity disk.
    /// If set, cvmbuild generates `disks/config/config.env` automatically —
    /// no need for a separate file.
    #[serde(default)]
    pub config_env: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub assert: assert::AssertConfig,
}

/// HuggingFace model repository to download.
#[derive(Debug, Deserialize)]
pub struct ModelConfig {
    /// HuggingFace repo ID (e.g. "ggml-org/Qwen3-0.6B-GGUF")
    pub repo: String,
    /// Glob patterns of files to include (default: all files)
    #[serde(default)]
    pub include: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImageConfig {
    pub id: String,
    pub version: String,
    /// OCI base image ref. If set, the image is pulled directly.
    /// If omitted, a Dockerfile must exist in the image directory.
    #[serde(default)]
    pub base: Option<String>,
    /// Docker build context directory (relative to image dir).
    /// If omitted, defaults to the Dockerfile's parent directory.
    #[serde(default)]
    pub context: Option<String>,
    /// Docker image tag that this image depends on (e.g. "cvm-base:latest").
    /// If set, cvmbuild checks whether the image exists before building.
    /// If missing, it is auto-built from `base_image_dockerfile`.
    #[serde(default)]
    pub base_image: Option<String>,
    /// Dockerfile to build `base_image` from (relative to context dir).
    /// Required when `base_image` is set.
    #[serde(default)]
    pub base_image_dockerfile: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KernelConfig {
    pub cmdline: String,
    #[serde(default)]
    pub initrd_modules: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerityConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub panic_on_corruption: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct OverlayConfig {
    #[serde(default)]
    pub files: Vec<OverlayFile>,
}

#[derive(Debug, Deserialize)]
pub struct OverlayFile {
    pub src: String,
    pub dst: String,
}

#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub remove_dirs: Vec<String>,
    #[serde(default)]
    pub lock_modules: bool,
    #[serde(default)]
    pub verify_hashes: Vec<HashVerification>,
}

/// Binary hash verification entry.
#[derive(Debug, Deserialize)]
pub struct HashVerification {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
pub struct FirewallConfig {
    #[serde(default)]
    pub inbound: Vec<FirewallRule>,
    #[serde(default = "default_deny")]
    pub outbound: String,
}

#[derive(Debug, Deserialize)]
pub struct FirewallRule {
    pub port: u16,
    pub proto: String,
}

/// Verity disk configuration (for models, config, etc.)
#[derive(Debug, Deserialize)]
pub struct VerityDiskConfig {
    pub name: String,
    pub device: String,
    pub mountpoint: String,
    pub description: String,
    /// Source directory to build the disk from. If omitted, the disk is built externally.
    /// Path is relative to the image directory, or absolute.
    #[serde(default)]
    pub source: Option<String>,
    /// Filesystem UUID (for reproducibility). If omitted, a deterministic UUID is derived from the name.
    #[serde(default)]
    pub uuid: Option<String>,
}

/// A user-defined systemd service to install in the CVM.
#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub description: String,
    pub exec: String,
    #[serde(default = "default_service_type")]
    pub service_type: String,
    #[serde(default)]
    pub after: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub wants: Vec<String>,
    #[serde(default)]
    pub environment_file: Option<String>,
    #[serde(default)]
    pub environment: Vec<String>,
    #[serde(default)]
    pub unset_environment: Vec<String>,
    #[serde(default = "default_hardening")]
    pub hardening: String,
    #[serde(default)]
    pub dynamic_user: Option<bool>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub supplementary_groups: Vec<String>,
    #[serde(default)]
    pub read_write_paths: Vec<String>,
    #[serde(default)]
    pub device_allow: Vec<String>,
    #[serde(default)]
    pub extra_options: Vec<String>,
}

fn default_service_type() -> String {
    "simple".to_string()
}

fn default_hardening() -> String {
    "full".to_string()
}

/// Network configuration.
#[derive(Debug, Default, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub ntp_servers: Vec<String>,
}

/// Groups to create via sysusers.d.
#[derive(Debug, Deserialize)]
pub struct SysGroup {
    pub name: String,
}

/// Services-level config (replaces the old vllm/kawa-specific config).
#[derive(Debug, Default, Deserialize)]
pub struct ServicesConfig {
    #[serde(default)]
    pub units: Vec<ServiceConfig>,
    #[serde(default)]
    pub groups: Vec<SysGroup>,
    #[serde(default)]
    pub mounts: Vec<MountConfig>,
    #[serde(default)]
    pub network: NetworkConfig,
}

/// A systemd mount unit.
#[derive(Debug, Deserialize)]
pub struct MountConfig {
    pub what: String,
    #[serde(rename = "where")]
    pub where_: String,
    #[serde(rename = "type")]
    pub fs_type: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub condition_path_exists: Option<String>,
}

/// Manifest generation configuration.
#[derive(Debug, Default, Deserialize)]
pub struct ManifestConfig {
    /// AMD SEV-SNP measurement parameters.
    #[serde(default)]
    pub snp: SnpManifestConfig,
    /// Intel TDX measurement parameters.
    #[serde(default)]
    pub tdx: TdxManifestConfig,
}

/// AMD SEV-SNP specific manifest configuration.
#[derive(Debug, Deserialize)]
pub struct SnpManifestConfig {
    /// OVMF firmware filename (e.g. "OVMF.fd"). Resolved against --ovmf-dir at build time.
    /// For backwards compatibility, full paths are also accepted.
    #[serde(default, alias = "ovmf_path")]
    pub ovmf_file: Option<String>,
    /// SEV_FEATURES value for VMSA (0x1 = SnpActive, 0x21 = SnpActive + RestrictedInjection).
    /// Defaults to 0x1 (matches QEMU default for SNP guests).
    #[serde(default = "default_guest_features")]
    pub guest_features: u64,
}

impl Default for SnpManifestConfig {
    fn default() -> Self {
        Self {
            ovmf_file: None,
            guest_features: default_guest_features(),
        }
    }
}

/// Intel TDX specific manifest configuration.
#[derive(Debug, Default, Deserialize)]
pub struct TdxManifestConfig {
    /// OVMF/TDVF firmware filename (e.g. "OVMF-TDX.fd"). Resolved against --ovmf-dir at build time.
    /// For backwards compatibility, full paths are also accepted.
    #[serde(default, alias = "ovmf_path")]
    pub ovmf_file: Option<String>,
}

fn default_guest_features() -> u64 {
    0x1
}

fn default_true() -> bool {
    true
}

fn default_deny() -> String {
    "deny".to_string()
}

impl Config {
    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config = Self::parse(&content)?;
        Ok(config)
    }

    /// Parse config from a TOML string.
    pub fn parse(s: &str) -> Result<Self> {
        toml::from_str(s).context("parsing config TOML")
    }

    /// Resolve OVMF filenames against a directory.
    /// If ovmf_file is already an absolute path, it's used as-is (backwards compat).
    /// If ovmf_file is a filename (e.g. "OVMF.fd"), it's joined with ovmf_dir.
    pub fn resolve_ovmf(&mut self, ovmf_dir: &Path) {
        fn resolve(opt: &mut Option<String>, dir: &Path) {
            if let Some(ref f) = *opt {
                if !Path::new(f).is_absolute() {
                    *opt = Some(dir.join(f).to_string_lossy().to_string());
                }
            }
        }
        resolve(&mut self.manifest.snp.ovmf_file, ovmf_dir);
        resolve(&mut self.manifest.tdx.ovmf_file, ovmf_dir);
    }

    /// Validate the config against security assertions.
    /// Returns errors only (no warnings). Uses the [assert] config to determine
    /// which catalog checks are active (defaults to "production" profile).
    pub fn validate(&self) -> Vec<ValidationError> {
        self.validate_full()
            .into_iter()
            .filter(|r| r.severity == assert::Severity::Error)
            .map(|r| ValidationError {
                field: r.field,
                message: format!("[{}] {}", r.check_name, r.message),
            })
            .collect()
    }

    /// Full validation including warnings.
    pub fn validate_full(&self) -> Vec<assert::AssertionResult> {
        assert::validate(self)
    }
}

#[derive(Debug)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.field, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
[image]
id = "my-cvm"
version = "0.1.0"
base = "localhost/my-base:24.04"

[kernel]
cmdline = "root=/dev/mapper/root lockdown=confidentiality intel_iommu=on amd_iommu=on iommu=pt systemd.verity_root_options=panic-on-corruption"
initrd_modules = ["dm-verity", "dm-mod", "squashfs", "virtio-blk", "virtio-net"]

[verity]
enabled = true
panic_on_corruption = true

[overlay]
files = [
  { src = "overlay/kawa.service", dst = "/etc/systemd/system/" },
]

[security]
remove = ["bash", "sh", "dash", "csh", "tcsh", "zsh", "fish", "ksh", "rbash", "busybox", "apt", "dpkg", "pip", "apt-get", "apt-cache", "apt-config", "apt-key", "apt-mark", "dpkg-deb", "dpkg-query", "pip3", "dmsetup"]
remove_dirs = ["/usr/lib/apt", "/var/lib/apt", "/var/lib/dpkg"]
lock_modules = true

[firewall]
inbound = [{ port = 8443, proto = "tcp" }]
outbound = "deny"

[[verity_disks]]
name = "models"
device = "vdb"
mountpoint = "/mnt/models"
description = "model weights disk"

[[verity_disks]]
name = "config"
device = "vdc"
mountpoint = "/mnt/config"
description = "configuration disk"

[services]
network = { ntp_servers = ["162.159.200.1"] }

[[services.groups]]
name = "vllm-ipc"

[[services.units]]
name = "vllm"
description = "vLLM inference engine"
exec = "/usr/local/bin/vllm-launcher"
after = ["mnt-config.mount", "mnt-models.mount", "lock-modules.service"]
requires = ["mnt-config.mount", "mnt-models.mount"]
environment_file = "/mnt/config/config.env"

[[services.units]]
name = "kawa"
description = "Kawa Noise_XX TLS proxy"
exec = "/usr/local/bin/kawa"
after = ["vllm.service", "mnt-config.mount"]
requires = ["mnt-config.mount"]
environment_file = "/mnt/config/config.env"

[manifest]
"#;

    #[test]
    fn parse_valid_config() {
        let config = Config::parse(VALID_CONFIG).unwrap();
        assert_eq!(config.image.id, "my-cvm");
        assert_eq!(
            config.image.base.as_deref(),
            Some("localhost/my-base:24.04")
        );
        assert!(config.verity.enabled);
        assert_eq!(config.security.remove.len(), 22);
        assert_eq!(config.firewall.inbound[0].port, 8443);
        assert_eq!(config.verity_disks.len(), 2);
        assert_eq!(config.verity_disks[0].name, "models");
        assert_eq!(config.verity_disks[1].device, "vdc");
        assert_eq!(config.services.units.len(), 2);
        assert_eq!(config.services.units[0].name, "vllm");
        assert_eq!(config.services.units[1].name, "kawa");
        assert_eq!(config.services.groups.len(), 1);
        assert_eq!(config.services.groups[0].name, "vllm-ipc");
    }

    #[test]
    fn valid_config_passes_validation() {
        let config = Config::parse(VALID_CONFIG).unwrap();
        let errors = config.validate();
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
    }

    #[test]
    fn missing_shell_removal_fails() {
        let toml = VALID_CONFIG.replace(
            r#"remove = ["bash", "sh", "dash", "csh", "tcsh", "zsh", "fish", "ksh", "rbash", "busybox", "apt", "dpkg", "pip", "apt-get", "apt-cache", "apt-config", "apt-key", "apt-mark", "dpkg-deb", "dpkg-query", "pip3", "dmsetup"]"#,
            r#"remove = ["apt", "dpkg", "pip", "apt-get", "apt-cache", "apt-config", "apt-key", "apt-mark", "dpkg-deb", "dpkg-query", "pip3", "dmsetup"]"#,
        );
        let config = Config::parse(&toml).unwrap();
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.message.contains("bash")));
    }

    #[test]
    fn console_in_cmdline_fails() {
        let toml = VALID_CONFIG.replace(
            "lockdown=confidentiality",
            "console=ttyS0 lockdown=confidentiality",
        );
        let config = Config::parse(&toml).unwrap();
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.message.contains("serial console")));
    }

    #[test]
    fn duplicate_disk_name_fails() {
        let toml = VALID_CONFIG.replace("name = \"config\"", "name = \"models\"");
        let config = Config::parse(&toml).unwrap();
        let errors = config.validate();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("duplicate disk name")));
    }

    #[test]
    fn outbound_allow_fails() {
        let toml = VALID_CONFIG.replace(r#"outbound = "deny""#, r#"outbound = "allow""#);
        let config = Config::parse(&toml).unwrap();
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.message.contains("zero-trust")));
    }
}
