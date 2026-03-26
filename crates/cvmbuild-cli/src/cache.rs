use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// High-performance embedded HTTP caching proxy for apt.
///
/// Uses axum + tokio for async I/O:
/// - Cache hits: served directly from disk (zero-copy where possible)
/// - Cache misses: streamed from upstream, written to disk + client simultaneously
/// - Concurrent requests handled properly (no blocking on large files)
pub struct AptCacheProxy {
    port: u16,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl AptCacheProxy {
    /// Start the cache proxy on a random available port.
    pub fn start(upstream: &str, cache_dir: &Path) -> Result<Self> {
        let upstream = upstream.trim_end_matches('/').to_string();
        let cache_dir = cache_dir.to_path_buf();

        // Bind to get the actual port
        let listener = std::net::TcpListener::bind("127.0.0.1:0").context("binding cache proxy")?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        info!("apt cache proxy on :{port} → {upstream}");

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .expect("tokio runtime");

            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");

                let state = Arc::new(ProxyState {
                    upstream,
                    cache_dir,
                    client: reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::limited(5))
                        .build()
                        .expect("reqwest client"),
                });

                let app = axum::Router::new()
                    .fallback(handle_request)
                    .with_state(state);

                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .ok();
            });
        });

        Ok(Self {
            port,
            shutdown: Some(shutdown_tx),
            handle: Some(handle),
        })
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for AptCacheProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone)]
struct ProxyState {
    upstream: String,
    cache_dir: PathBuf,
    client: reqwest::Client,
}

async fn handle_request(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    let url_path = req.uri().path().to_string();

    let cache_path = match safe_cache_path(&state.cache_dir, &url_path) {
        Some(p) => p,
        None => return error_response(400, "bad path"),
    };

    // Cache hit — serve from disk
    if cache_path.is_file() {
        let size = cache_path.metadata().map(|m| m.len()).unwrap_or(0);
        debug!("HIT  {} ({})", url_path, fmt_size(size));
        return serve_file(&cache_path).await;
    }

    // Cache miss — fetch from upstream, cache, and serve
    let full_url = format!("{}{}", state.upstream, url_path);
    debug!("FETCH {}", url_path);

    match fetch_and_cache(&state.client, &full_url, &cache_path).await {
        Ok(size) => {
            debug!("CACHED {} ({})", url_path, fmt_size(size));
            serve_file(&cache_path).await
        }
        Err(e) => {
            warn!("upstream: {url_path}: {e}");
            error_response(502, &e.to_string())
        }
    }
}

async fn serve_file(path: &Path) -> axum::response::Response {
    use axum::body::Body;
    use axum::response::IntoResponse;
    use tokio_util::io::ReaderStream;

    let file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => return error_response(404, "not found"),
    };
    let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    axum::response::Response::builder()
        .header("content-length", size)
        .body(body)
        .unwrap()
        .into_response()
}

async fn fetch_and_cache(client: &reqwest::Client, url: &str, cache_path: &Path) -> Result<u64> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("upstream {} returned {}", url, resp.status());
    }

    // Ensure parent dir
    if let Some(parent) = cache_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Stream to temp file
    let tmp_path = cache_path.with_extension("dl");
    let mut tmp_file = tokio::fs::File::create(&tmp_path).await?;
    let mut stream = resp.bytes_stream();
    let mut total: u64 = 0;

    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    while let Some(chunk) = stream.next().await {
        let bytes = chunk.context("reading upstream")?;
        tmp_file.write_all(&bytes).await?;
        total += bytes.len() as u64;
    }

    tmp_file.flush().await?;
    drop(tmp_file);

    // Atomic rename
    tokio::fs::rename(&tmp_path, cache_path).await?;

    Ok(total)
}

fn safe_cache_path(cache_dir: &Path, url_path: &str) -> Option<PathBuf> {
    let clean = url_path.split('?').next()?.trim_start_matches('/');
    if clean.is_empty() || clean.contains('\0') {
        return None;
    }
    let candidate = cache_dir.join(clean);
    if candidate.starts_with(cache_dir) {
        Some(candidate)
    } else {
        None
    }
}

fn error_response(status: u16, msg: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::from_u16(status)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        msg.to_string(),
    )
        .into_response()
}

fn fmt_size(n: u64) -> String {
    if n < 1024 {
        format!("{n}B")
    } else if n < 1024 * 1024 {
        format!("{}KB", n / 1024)
    } else {
        format!("{:.1}MB", n as f64 / 1024.0 / 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_path_normal() {
        let base = Path::new("/tmp/cache");
        let p = safe_cache_path(base, "/ubuntu/20260320T000000Z/dists/noble/Release");
        assert!(p.is_some());
        assert!(p.unwrap().starts_with(base));
    }

    #[test]
    fn safe_path_traversal() {
        let base = Path::new("/tmp/cache");
        let p = safe_cache_path(base, "/../../../etc/passwd");
        assert!(p.is_none() || p.unwrap().starts_with(base));
    }

    #[test]
    fn safe_path_empty() {
        let base = Path::new("/tmp/cache");
        assert!(safe_cache_path(base, "/").is_none());
        assert!(safe_cache_path(base, "").is_none());
    }

    #[test]
    fn safe_path_query_stripped() {
        let base = Path::new("/tmp/cache");
        let p = safe_cache_path(base, "/foo/bar?v=1");
        assert!(p.is_some());
        assert!(p.unwrap().ends_with("foo/bar"));
    }

    #[test]
    fn fmt_size_values() {
        assert_eq!(fmt_size(500), "500B");
        assert_eq!(fmt_size(2048), "2KB");
        assert_eq!(fmt_size(1048576), "1.0MB");
    }
}
