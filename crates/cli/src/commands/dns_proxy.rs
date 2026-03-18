//! CLI handler for the `sd dns-proxy` command.

use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;

use prx_sd_realtime::dns_proxy::{DnsProxy, DnsProxyConfig};

/// Run the local DNS proxy with adblock + IOC + custom blocklist filtering.
pub async fn run(listen: &str, upstream: &str, log_path: &str, data_dir: &Path) -> Result<()> {
    let listen_addr = listen
        .parse()
        .with_context(|| format!("invalid listen address: {listen}"))?;
    let upstream_addr = upstream
        .parse()
        .with_context(|| format!("invalid upstream address: {upstream}"))?;

    let config = DnsProxyConfig {
        listen_addr,
        upstream_dns: upstream_addr,
        log_path: log_path.into(),
    };

    println!(
        "{} Starting DNS proxy (listen={}, upstream={}, log={})",
        ">>>".cyan().bold(),
        listen,
        upstream,
        log_path,
    );
    println!(
        "{} Filter engines: adblock + dns_blocklist + ioc_domains",
        ">>>".green().bold(),
    );
    println!(
        "{} Press {} to stop.\n",
        ">>>".green().bold(),
        "Ctrl+C".bold(),
    );

    let proxy = DnsProxy::new(config, data_dir).context("failed to initialise DNS proxy")?;

    // Run the blocking event loop on a dedicated thread so tokio can still
    // handle Ctrl+C.
    let handle = tokio::task::spawn_blocking(move || proxy.run());
    handle.await.context("DNS proxy task panicked")?
}
