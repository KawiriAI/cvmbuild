use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cvmbuild_config::Config;
use sha2::{Digest, Sha256};

pub mod services;

/// Manipulates an extracted rootfs: applies overlays, removes binaries, hardens.
pub struct RootfsBuilder {
    rootfs: PathBuf,
}

impl RootfsBuilder {
    pub fn new(rootfs: &Path) -> Self {
        Self {
            rootfs: rootfs.to_path_buf(),
        }
    }

    /// Apply all modifications from the config to the rootfs.
    pub fn apply(&self, config: &Config) -> Result<()> {
        self.apply_overlay(config)?;
        // Generate services BEFORE binary removal (services need to be written first)
        services::apply_services(&self.rootfs, config)?;
        self.verify_binary_hashes(config)?;
        self.audit_kernel_config()?;
        self.remove_binaries(config)?;
        self.remove_directories(config)?;
        self.verify_zero_shell(config)?;
        self.strip_suid_sgid()?;
        self.rewrite_shells_to_nologin()?;
        self.write_tee_modules_load()?;
        self.apply_hardening(config)?;
        Ok(())
    }

    /// Copy overlay files into the rootfs.
    fn apply_overlay(&self, config: &Config) -> Result<()> {
        for file in &config.overlay.files {
            let src = Path::new(&file.src);
            let dst = self
                .rootfs
                .join(file.dst.strip_prefix('/').unwrap_or(&file.dst));

            // If dst ends with /, it's a directory — copy file into it
            if file.dst.ends_with('/') {
                std::fs::create_dir_all(&dst)?;
                let filename = src.file_name().context("overlay source has no filename")?;
                let target = dst.join(filename);
                tracing::info!("Overlay: {} → {}", file.src, target.display());
                std::fs::copy(src, &target)
                    .with_context(|| format!("copying {} → {}", src.display(), target.display()))?;
            } else {
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                tracing::info!("Overlay: {} → {}", file.src, dst.display());
                std::fs::copy(src, &dst)
                    .with_context(|| format!("copying {} → {}", src.display(), dst.display()))?;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // #5: Binary hash verification
    // -----------------------------------------------------------------------

    /// Verify SHA256 hashes of critical binaries in the rootfs.
    /// If no hashes are configured, scan /usr/local/bin and print hashes for pinning.
    fn verify_binary_hashes(&self, config: &Config) -> Result<()> {
        if config.security.verify_hashes.is_empty() {
            self.print_binary_hashes();
            return Ok(());
        }

        for entry in &config.security.verify_hashes {
            let full_path = self
                .rootfs
                .join(entry.path.strip_prefix('/').unwrap_or(&entry.path));

            if !full_path.exists() {
                anyhow::bail!("hash verification: {} does not exist in rootfs", entry.path);
            }

            let data = std::fs::read(&full_path)
                .with_context(|| format!("reading {}", full_path.display()))?;
            let hash = hex::encode(Sha256::digest(&data));

            if hash != entry.sha256 {
                anyhow::bail!(
                    "hash verification FAILED for {}: expected {}, got {}",
                    entry.path,
                    entry.sha256,
                    hash
                );
            }
            tracing::info!("Hash verified: {} ✓", entry.path);
        }
        Ok(())
    }

    /// Print SHA256 hashes of binaries in /usr/local/bin for pinning in cvm.toml.
    fn print_binary_hashes(&self) {
        let bin_dir = self.rootfs.join("usr/local/bin");
        let Ok(entries) = std::fs::read_dir(&bin_dir) else {
            return;
        };

        let mut bins: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .collect();
        bins.sort_by_key(|e| e.file_name());

        if bins.is_empty() {
            return;
        }

        tracing::info!("No verify_hashes configured — printing hashes for pinning:");
        for entry in &bins {
            if let Ok(data) = std::fs::read(entry.path()) {
                let hash = hex::encode(Sha256::digest(&data));
                let path = format!("/usr/local/bin/{}", entry.file_name().to_string_lossy());
                tracing::info!("  [[security.verify_hashes]]");
                tracing::info!("  path = \"{}\"", path);
                tracing::info!("  sha256 = \"{}\"", hash);
            }
        }
    }

    // -----------------------------------------------------------------------
    // #2: Kernel config audit
    // -----------------------------------------------------------------------

    /// Audit the kernel config for required security options.
    fn audit_kernel_config(&self) -> Result<()> {
        let boot_dir = self.rootfs.join("boot");
        if !boot_dir.exists() {
            tracing::warn!("No /boot directory — skipping kernel config audit");
            return Ok(());
        }

        // Find config-* file
        let config_path = find_boot_file(&boot_dir, "config-")?;
        let config_path = match config_path {
            Some(p) => p,
            None => {
                tracing::warn!("No kernel config found in /boot — skipping audit");
                return Ok(());
            }
        };

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("reading {}", config_path.display()))?;

        // Required options — fail build if missing
        let required = [
            "CONFIG_SECURITY_LOCKDOWN_LSM",
            "CONFIG_STRICT_KERNEL_RWX",
            "CONFIG_DM_VERITY",
            "CONFIG_SQUASHFS",
            "CONFIG_BLK_DEV_DM",
        ];

        let mut failed = false;
        for opt in required {
            if !kernel_config_enabled(&content, opt) {
                tracing::error!("REQUIRED kernel option missing or disabled: {opt}");
                failed = true;
            }
        }

        if failed {
            anyhow::bail!("kernel config audit failed — required options missing");
        }

        // Recommended options — warn only
        let recommended = [
            "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY",
            "CONFIG_MODULE_SIG_FORCE",
            "CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG",
        ];

        for opt in recommended {
            if !kernel_config_enabled(&content, opt) {
                tracing::warn!("Recommended kernel option not enabled: {opt}");
            }
        }

        tracing::info!("Kernel config audit passed");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Binary removal + #1: Zero-shell verification
    // -----------------------------------------------------------------------

    /// Remove dangerous binaries from the rootfs.
    fn remove_binaries(&self, config: &Config) -> Result<()> {
        let search_paths = ["/bin", "/usr/bin", "/usr/sbin", "/sbin", "/usr/local/bin"];

        for binary in &config.security.remove {
            for search_path in &search_paths {
                let full_path = self
                    .rootfs
                    .join(search_path.strip_prefix('/').unwrap_or(search_path))
                    .join(binary);

                if full_path.exists() {
                    tracing::info!("Removing: {}/{}", search_path, binary);
                    std::fs::remove_file(&full_path)
                        .with_context(|| format!("removing {}", full_path.display()))?;
                }
            }
        }
        Ok(())
    }

    /// Remove dangerous directories from the rootfs.
    fn remove_directories(&self, config: &Config) -> Result<()> {
        for dir in &config.security.remove_dirs {
            let full_path = self.rootfs.join(dir.strip_prefix('/').unwrap_or(dir));

            if full_path.exists() {
                tracing::info!("Removing dir: {}", dir);
                std::fs::remove_dir_all(&full_path)
                    .with_context(|| format!("removing directory {}", full_path.display()))?;
            }
        }
        Ok(())
    }

    /// Verify that no shell binary survived removal (anti-regression).
    fn verify_zero_shell(&self, config: &Config) -> Result<()> {
        let shells = [
            "bash", "sh", "dash", "csh", "tcsh", "zsh", "fish", "ksh", "rbash", "busybox",
        ];
        let search_paths = ["/bin", "/usr/bin", "/usr/sbin", "/sbin", "/usr/local/bin"];

        let mut survivors = Vec::new();
        for shell in shells {
            for search_path in &search_paths {
                let full_path = self
                    .rootfs
                    .join(search_path.strip_prefix('/').unwrap_or(search_path))
                    .join(shell);

                if full_path.exists() {
                    survivors.push(format!("{}/{}", search_path, shell));
                }
            }
        }

        if !survivors.is_empty() {
            // Check if they were supposed to be removed
            let should_remove: Vec<_> = survivors
                .iter()
                .filter(|s| {
                    let name = s.rsplit('/').next().unwrap_or(s);
                    config.security.remove.iter().any(|r| r == name)
                })
                .collect();

            if !should_remove.is_empty() {
                anyhow::bail!(
                    "zero-shell verification FAILED — shells survived removal: {}",
                    should_remove
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            // Shells exist but weren't in the removal list — warn
            tracing::warn!(
                "Shells found but not in security.remove list: {}",
                survivors.join(", ")
            );
        }

        tracing::info!("Zero-shell verification passed");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // #3: SUID/SGID stripping
    // -----------------------------------------------------------------------

    /// Strip setuid and setgid bits from all files in the rootfs.
    fn strip_suid_sgid(&self) -> Result<()> {
        let mut count = 0u32;
        strip_suid_recursive(&self.rootfs, &mut count)?;
        if count > 0 {
            tracing::info!("Stripped SUID/SGID from {count} files");
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // #4: Rewrite user shells to nologin
    // -----------------------------------------------------------------------

    /// Rewrite all login shells in /etc/passwd to /usr/sbin/nologin.
    fn rewrite_shells_to_nologin(&self) -> Result<()> {
        let passwd_path = self.rootfs.join("etc/passwd");
        if !passwd_path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&passwd_path).context("reading /etc/passwd")?;

        let safe_shells = [
            "/usr/sbin/nologin",
            "/bin/false",
            "/usr/bin/false",
            "/sbin/nologin",
        ];
        let mut modified = false;
        let mut output = String::new();

        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() == 7 {
                let shell = fields[6];
                if !safe_shells.contains(&shell) && !shell.is_empty() {
                    tracing::info!(
                        "Rewriting shell for {}: {} → /usr/sbin/nologin",
                        fields[0],
                        shell
                    );
                    let new_line = format!(
                        "{}:{}:{}:{}:{}:{}:/usr/sbin/nologin",
                        fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
                    );
                    output.push_str(&new_line);
                    modified = true;
                } else {
                    output.push_str(line);
                }
            } else {
                output.push_str(line);
            }
            output.push('\n');
        }

        if modified {
            std::fs::write(&passwd_path, &output).context("writing /etc/passwd")?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // #7: TEE modules-load.d
    // -----------------------------------------------------------------------

    /// Write modules-load.d config for TEE attestation modules.
    fn write_tee_modules_load(&self) -> Result<()> {
        let dir = self.rootfs.join("etc/modules-load.d");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("cvmbuild-tee.conf"),
            "# TEE attestation modules — loaded before module lockdown\nsev_guest\ntdx_guest\n",
        )?;
        tracing::info!("Wrote modules-load.d/cvmbuild-tee.conf (sev_guest, tdx_guest)");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Existing hardening
    // -----------------------------------------------------------------------

    /// Apply security hardening: sysctl, journald config, etc.
    fn apply_hardening(&self, config: &Config) -> Result<()> {
        // Write sysctl hardening
        let sysctl_dir = self.rootfs.join("etc/sysctl.d");
        std::fs::create_dir_all(&sysctl_dir)?;
        std::fs::write(
            sysctl_dir.join("99-cvm-hardening.conf"),
            "# CVM hardening — generated by cvmbuild\n\
             fs.suid_dumpable = 0\n\
             kernel.core_pattern = |/bin/false\n\
             kernel.kptr_restrict = 2\n\
             kernel.dmesg_restrict = 1\n",
        )?;

        // Lock kernel modules after init
        if config.security.lock_modules {
            let modules_dir = self.rootfs.join("etc/sysctl.d");
            std::fs::write(
                modules_dir.join("99-lock-modules.conf"),
                "# Lock kernel module loading after init\n\
                 kernel.modules_disabled = 1\n",
            )?;
        }

        // Volatile journald (RAM-only logging)
        let journald_dir = self.rootfs.join("etc/systemd/journald.conf.d");
        std::fs::create_dir_all(&journald_dir)?;
        std::fs::write(
            journald_dir.join("cvm.conf"),
            "[Journal]\n\
             Storage=volatile\n\
             SystemMaxUse=16M\n\
             SystemMaxFileSize=4M\n\
             ForwardToConsole=no\n",
        )?;

        // Validate nftables.conf (generated by services::generate_services)
        let nft_path = self.rootfs.join("etc/nftables.conf");
        if nft_path.exists() {
            let rules = std::fs::read_to_string(&nft_path)?;
            validate_nftables(&rules, config)?;
        }

        tracing::info!("Applied security hardening");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Find a file in /boot matching a prefix.
fn find_boot_file(boot_dir: &Path, prefix: &str) -> Result<Option<PathBuf>> {
    if !boot_dir.exists() {
        return Ok(None);
    }
    for entry in std::fs::read_dir(boot_dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(prefix) {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

/// Check if a kernel config option is set to =y or =m.
fn kernel_config_enabled(content: &str, option: &str) -> bool {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(option) {
            if rest == "=y" || rest == "=m" {
                return true;
            }
        }
    }
    false
}

/// Recursively strip SUID/SGID bits from files.
fn strip_suid_recursive(dir: &Path, count: &mut u32) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()), // permission denied on some dirs is ok
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.is_dir() {
            strip_suid_recursive(&path, count)?;
        } else if meta.is_file() {
            let mode = meta.mode();
            // S_ISUID = 0o4000, S_ISGID = 0o2000
            if mode & 0o6000 != 0 {
                let new_mode = mode & !0o6000;
                std::fs::set_permissions(
                    &path,
                    std::os::unix::fs::PermissionsExt::from_mode(new_mode),
                )?;
                tracing::info!(
                    "Stripped SUID/SGID: {} ({:o} → {:o})",
                    path.display(),
                    mode,
                    new_mode
                );
                *count += 1;
            }
        }
    }
    Ok(())
}

/// Validate generated nftables rules for security.
///
/// The port-22 / port-80 checks are default-secure backstops for chat-only
/// CVMs that should never expose SSH or plain HTTP. Images that legitimately
/// want one or the other (e.g. an SSH-CVM) opt out via the matching catalog
/// check name in `[assert].exclude`:
///   - `firewall_no_ssh`        → skip the port-22 check
///   - `firewall_no_http_plain` → skip the port-80 check
fn validate_nftables(rules: &str, config: &Config) -> Result<()> {
    let mut errors = Vec::new();
    let excluded: &[String] = &config.assert.exclude;

    // All chains must have policy drop
    let chain_count = rules.matches("policy drop").count();
    if chain_count < 3 {
        errors.push("not all chains have 'policy drop'".to_string());
    }

    // No SSH allowed (unless explicitly opted in via [assert].exclude).
    if !excluded.iter().any(|s| s == "firewall_no_ssh")
        && (rules.contains("dport 22 ") || rules.contains("dport 22\n"))
    {
        errors.push("SSH (port 22) must not be allowed in CVM firewall".to_string());
    }

    // No plain HTTP (unless explicitly opted in via [assert].exclude).
    if !excluded.iter().any(|s| s == "firewall_no_http_plain")
        && (rules.contains("dport 80 ") || rules.contains("dport 80\n"))
    {
        errors.push("plain HTTP (port 80) must not be allowed".to_string());
    }

    // Outbound must be deny
    if config.firewall.outbound != "deny" {
        errors.push("outbound firewall policy must be 'deny'".to_string());
    }

    if !errors.is_empty() {
        anyhow::bail!("nftables validation failed:\n  {}", errors.join("\n  "));
    }

    tracing::info!("nftables validation passed");
    Ok(())
}

/// Encode bytes as hex string.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn test_config() -> Config {
        Config::parse(
            r#"
[image]
id = "test"
version = "0.1.0"
base = "test:latest"

[kernel]
cmdline = "root=/dev/mapper/root lockdown=confidentiality iommu=pt"
initrd_modules = ["dm-verity", "dm-mod"]

[verity]
enabled = true
panic_on_corruption = true

[security]
remove = ["bash", "sh", "dash", "apt", "dpkg", "pip", "dmsetup"]
remove_dirs = ["/var/lib/apt"]
lock_modules = true

[firewall]
inbound = [{ port = 8443, proto = "tcp" }]
outbound = "deny"
"#,
        )
        .unwrap()
    }

    #[test]
    fn remove_binaries_deletes_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();

        let bin_dir = rootfs.join("usr/bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("bash"), "fake").unwrap();

        let builder = RootfsBuilder::new(rootfs);
        builder.remove_binaries(&test_config()).unwrap();

        assert!(!bin_dir.join("bash").exists());
    }

    #[test]
    fn zero_shell_verification_passes_when_clean() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        fs::create_dir_all(rootfs.join("usr/bin")).unwrap();

        let builder = RootfsBuilder::new(rootfs);
        builder.verify_zero_shell(&test_config()).unwrap();
    }

    #[test]
    fn zero_shell_verification_fails_when_shell_survives() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        let bin_dir = rootfs.join("usr/bin");
        fs::create_dir_all(&bin_dir).unwrap();
        // bash is in config.security.remove, so it should trigger a failure
        fs::write(bin_dir.join("bash"), "fake shell").unwrap();

        let builder = RootfsBuilder::new(rootfs);
        let result = builder.verify_zero_shell(&test_config());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("zero-shell"));
    }

    #[test]
    fn kernel_config_audit_passes_good_config() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        let boot = rootfs.join("boot");
        fs::create_dir_all(&boot).unwrap();
        fs::write(
            boot.join("config-6.17.0-14-generic"),
            "CONFIG_SECURITY_LOCKDOWN_LSM=y\n\
             CONFIG_STRICT_KERNEL_RWX=y\n\
             CONFIG_DM_VERITY=m\n\
             CONFIG_SQUASHFS=y\n\
             CONFIG_BLK_DEV_DM=y\n",
        )
        .unwrap();

        let builder = RootfsBuilder::new(rootfs);
        builder.audit_kernel_config().unwrap();
    }

    #[test]
    fn kernel_config_audit_fails_missing_option() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        let boot = rootfs.join("boot");
        fs::create_dir_all(&boot).unwrap();
        fs::write(
            boot.join("config-6.17.0-14-generic"),
            "CONFIG_STRICT_KERNEL_RWX=y\n\
             CONFIG_DM_VERITY=m\n\
             CONFIG_SQUASHFS=y\n\
             CONFIG_BLK_DEV_DM=y\n",
            // Missing CONFIG_SECURITY_LOCKDOWN_LSM
        )
        .unwrap();

        let builder = RootfsBuilder::new(rootfs);
        let result = builder.audit_kernel_config();
        assert!(result.is_err());
    }

    #[test]
    fn suid_stripping_works() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        let bin = rootfs.join("usr/bin");
        fs::create_dir_all(&bin).unwrap();

        let path = bin.join("setuid-binary");
        fs::write(&path, "fake").unwrap();
        fs::set_permissions(&path, PermissionsExt::from_mode(0o104755)).unwrap();

        let builder = RootfsBuilder::new(rootfs);
        builder.strip_suid_sgid().unwrap();

        let mode = fs::metadata(&path).unwrap().mode();
        assert_eq!(mode & 0o6000, 0, "SUID/SGID bits should be stripped");
        assert_eq!(
            mode & 0o777,
            0o755,
            "regular permission bits should be preserved"
        );
    }

    #[test]
    fn nologin_rewrite_works() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::write(
            rootfs.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
        )
        .unwrap();

        let builder = RootfsBuilder::new(rootfs);
        builder.rewrite_shells_to_nologin().unwrap();

        let passwd = fs::read_to_string(rootfs.join("etc/passwd")).unwrap();
        assert!(passwd.contains("root:x:0:0:root:/root:/usr/sbin/nologin"));
        assert!(passwd.contains("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"));
    }

    #[test]
    fn tee_modules_load_written() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();

        let builder = RootfsBuilder::new(rootfs);
        builder.write_tee_modules_load().unwrap();

        let content =
            fs::read_to_string(rootfs.join("etc/modules-load.d/cvmbuild-tee.conf")).unwrap();
        assert!(content.contains("sev_guest"));
        assert!(content.contains("tdx_guest"));
    }

    #[test]
    fn binary_hash_verification_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        let bin = rootfs.join("usr/local/bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("kawa"), "fake kawa binary").unwrap();

        // Compute the actual hash
        let hash = super::hex::encode(Sha256::digest(b"fake kawa binary"));

        let config = Config::parse(&format!(
            r#"
[image]
id = "test"
version = "0.1.0"
base = "test:latest"
[kernel]
cmdline = "lockdown=confidentiality iommu=pt"
initrd_modules = ["dm-verity", "dm-mod"]
[verity]
[security]
remove = ["bash", "sh", "dash", "apt", "dpkg", "pip", "dmsetup"]
lock_modules = true
[[security.verify_hashes]]
path = "/usr/local/bin/kawa"
sha256 = "{hash}"
[firewall]
inbound = [{{ port = 8443, proto = "tcp" }}]
outbound = "deny"
"#
        ))
        .unwrap();

        let builder = RootfsBuilder::new(rootfs);
        builder.verify_binary_hashes(&config).unwrap();
    }

    #[test]
    fn binary_hash_verification_fails_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        let bin = rootfs.join("usr/local/bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("kawa"), "tampered binary").unwrap();

        let config = Config::parse(
            r#"
[image]
id = "test"
version = "0.1.0"
base = "test:latest"
[kernel]
cmdline = "lockdown=confidentiality iommu=pt"
initrd_modules = ["dm-verity", "dm-mod"]
[verity]
[security]
remove = ["bash", "sh", "dash", "apt", "dpkg", "pip", "dmsetup"]
lock_modules = true
[[security.verify_hashes]]
path = "/usr/local/bin/kawa"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
[firewall]
inbound = [{ port = 8443, proto = "tcp" }]
outbound = "deny"
"#,
        )
        .unwrap();

        let builder = RootfsBuilder::new(rootfs);
        let result = builder.verify_binary_hashes(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("FAILED"));
    }

    #[test]
    fn nftables_validation_rejects_ssh() {
        let rules = "policy drop;\npolicy drop;\npolicy drop;\ntcp dport 22 accept\n";
        let config = test_config();
        let result = validate_nftables(rules, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("SSH"));
    }

    #[test]
    fn nftables_validation_passes_good_rules() {
        let rules = "policy drop;\npolicy drop;\npolicy drop;\ntcp dport 8443 accept\n";
        let config = test_config();
        validate_nftables(rules, &config).unwrap();
    }

    #[test]
    fn hardening_writes_sysctl() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();

        let builder = RootfsBuilder::new(rootfs);
        builder.apply_hardening(&test_config()).unwrap();

        let sysctl = fs::read_to_string(rootfs.join("etc/sysctl.d/99-cvm-hardening.conf")).unwrap();
        assert!(sysctl.contains("suid_dumpable = 0"));
    }

    #[test]
    fn firewall_validation_checks_existing_nftables() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();

        // Write a valid nftables.conf (normally done by services::generate_services)
        let etc = rootfs.join("etc");
        fs::create_dir_all(&etc).unwrap();
        fs::write(
            etc.join("nftables.conf"),
            "policy drop;\npolicy drop;\npolicy drop;\ntcp dport 8443 accept\n",
        )
        .unwrap();

        let _builder = RootfsBuilder::new(rootfs);
        let config = test_config();
        // apply_hardening reads and validates the nftables.conf
        let nft_path = rootfs.join("etc/nftables.conf");
        let rules = fs::read_to_string(&nft_path).unwrap();
        validate_nftables(&rules, &config).unwrap();
    }
}
