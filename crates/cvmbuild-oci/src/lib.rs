use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Returns buildx cache flags if BUILDX_CACHE is set, None otherwise.
fn cache_flags(name: &str) -> Option<Vec<String>> {
    let addr = std::env::var("BUILDX_CACHE").ok()?;
    if addr.is_empty() {
        return None;
    }
    let (from, to) = if addr.starts_with('/') {
        (
            format!("type=local,src={addr}/{name}"),
            format!("type=local,dest={addr}/{name},mode=max"),
        )
    } else {
        (
            format!("type=registry,ref={addr}/{name}"),
            format!("type=registry,ref={addr}/{name},mode=max"),
        )
    };
    Some(vec!["--cache-from".into(), from, "--cache-to".into(), to])
}

/// Build or pull container images and extract rootfs using Docker BuildKit.
pub struct OciExtractor {
    work_dir: PathBuf,
}

impl OciExtractor {
    pub fn new(work_dir: &Path) -> Self {
        Self {
            work_dir: work_dir.to_path_buf(),
        }
    }

    /// Build a Dockerfile and extract rootfs directly using Docker BuildKit.
    ///
    /// Uses `docker buildx build -o type=tar` to produce the final filesystem,
    /// then extracts the tar. The tar exporter correctly preserves symlinks and
    /// directory structure, unlike `type=local` which drops directories affected
    /// by overlayfs whiteouts (e.g. /usr/sbin on Ubuntu 24.04 usrmerge images).
    pub fn build_rootfs(
        &self,
        dockerfile: &Path,
        context: &Path,
        build_args: &[(&str, &str)],
        secrets: &[(&str, &Path)],
    ) -> Result<PathBuf> {
        let rootfs = self.work_dir.join("rootfs");
        if rootfs.exists() {
            std::fs::remove_dir_all(&rootfs)?;
        }
        std::fs::create_dir_all(&rootfs)?;

        let tar_path = self.work_dir.join("rootfs.tar");

        tracing::info!("Building {} → rootfs (docker buildx)", dockerfile.display());

        let mut cmd = Command::new("docker");
        cmd.args([
            "buildx",
            "build",
            "--network=host",
            "-f",
            &dockerfile.to_string_lossy(),
            "-o",
            &format!("type=tar,dest={}", tar_path.display()),
        ]);

        // Add cache flags from BUILDX_CACHE env (set via teehost config)
        // Use parent dir name as cache key (e.g. "qwen3-0.6b-sglang-cpu")
        // since all image Dockerfiles are just named "Dockerfile"
        let cache_name = dockerfile
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("image");
        if let Some(flags) = cache_flags(cache_name) {
            for flag in flags {
                cmd.arg(flag);
            }
        }

        for (key, val) in build_args {
            cmd.arg("--build-arg");
            cmd.arg(format!("{}={}", key, val));
        }

        // BuildKit secrets — used for the apt mirror URL (random per-run port,
        // and we don't want to bust the layer cache fingerprint each time).
        for (id, src) in secrets {
            cmd.arg("--secret");
            cmd.arg(format!("id={},src={}", id, src.display()));
        }

        cmd.arg(context.to_string_lossy().to_string());

        let status = cmd.status().context("failed to run docker buildx build")?;
        if !status.success() {
            bail!("docker buildx build failed");
        }

        // Extract the tar into the rootfs directory
        tracing::info!("Extracting rootfs tar");
        let tar_status = Command::new("tar")
            .args([
                "xf",
                &tar_path.to_string_lossy(),
                "-C",
                &rootfs.to_string_lossy(),
            ])
            .status()
            .context("failed to extract rootfs tar")?;
        if !tar_status.success() {
            bail!("tar extraction failed");
        }

        // Clean up the tar file (can be multi-GB)
        let _ = std::fs::remove_file(&tar_path);

        Ok(rootfs)
    }

    /// Pull a container image and extract rootfs using Docker BuildKit.
    ///
    /// Creates a temporary `FROM <image>` Dockerfile and builds it
    /// with `-o type=tar` to extract the filesystem (tar preserves symlinks
    /// correctly unlike the local exporter).
    pub fn pull_rootfs(&self, image_ref: &str) -> Result<PathBuf> {
        let rootfs = self.work_dir.join("rootfs");
        if rootfs.exists() {
            std::fs::remove_dir_all(&rootfs)?;
        }
        std::fs::create_dir_all(&rootfs)?;

        let tmp_dir = self.work_dir.join("_pull");
        let tar_path = self.work_dir.join("rootfs.tar");
        std::fs::create_dir_all(&tmp_dir)?;
        std::fs::write(tmp_dir.join("Dockerfile"), format!("FROM {image_ref}\n"))?;

        tracing::info!("Pulling {} → rootfs (docker buildx)", image_ref);

        let mut pull_cmd = Command::new("docker");
        pull_cmd.args([
            "buildx",
            "build",
            "-f",
            &tmp_dir.join("Dockerfile").to_string_lossy(),
            "-o",
            &format!("type=tar,dest={}", tar_path.display()),
        ]);
        if let Some(flags) = cache_flags("pull") {
            for flag in flags {
                pull_cmd.arg(flag);
            }
        }
        pull_cmd.arg(tmp_dir.to_string_lossy().to_string());

        let status = pull_cmd
            .status()
            .context("failed to run docker buildx build")?;

        if !status.success() {
            bail!("docker buildx pull/extract failed");
        }

        // Extract the tar into the rootfs directory
        let tar_status = Command::new("tar")
            .args([
                "xf",
                &tar_path.to_string_lossy(),
                "-C",
                &rootfs.to_string_lossy(),
            ])
            .status()
            .context("failed to extract rootfs tar")?;
        if !tar_status.success() {
            bail!("tar extraction failed");
        }

        let _ = std::fs::remove_file(&tar_path);
        let _ = std::fs::remove_dir_all(&tmp_dir);
        Ok(rootfs)
    }

    /// One-shot: pull image and extract rootfs.
    pub fn pull_and_extract(&self, image_ref: &str) -> Result<PathBuf> {
        self.pull_rootfs(image_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_extractor() {
        let ext = OciExtractor::new(Path::new("/tmp/test"));
        assert_eq!(ext.work_dir, PathBuf::from("/tmp/test"));
    }
}
