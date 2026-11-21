//! Outbound target policy (SSRF protection) and IP helpers.
//!
//! The agent chooses the URL of every forwarded request, so without a policy
//! it could point ferrowarden at anything ferrowarden can reach — most
//! importantly bw serve itself (`GET /object/password/<name>` returns a
//! plaintext password) or a cloud metadata endpoint.
//!
//! Rules, applied to every address a target resolves to:
//!   * unspecified, multicast and broadcast addresses are never allowed;
//!   * the bw serve endpoint (host name, and resolved IP + port) is never
//!     allowed, whatever else is configured;
//!   * non-public addresses (loopback, RFC 1918, CGNAT, link-local, ULA, …)
//!     are allowed only when `allow_private_targets = true` or when they match
//!     an `allowed_targets` entry (CIDR, IP, or the request's host name);
//!   * public addresses are allowed.
//!
//! The check runs inside reqwest's DNS resolver, so the addresses checked are
//! exactly the addresses connected to (no DNS-rebinding gap). IP-literal
//! hosts skip the resolver and are checked by [`TargetPolicy::check_url`].

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::Url;

use crate::config::{split_list, Config};
use crate::error::{FerroError, FerroResult};

// ── CIDR ──────────────────────────────────────────────────────────────────────

/// An IP network in CIDR notation. A bare IP parses as a /32 or /128.
#[derive(Debug, Clone, PartialEq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let net: IpAddr = addr.trim_start_matches('[').trim_end_matches(']').parse().ok()?;
        let net = net.to_canonical();
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        Some(Self { net, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.net, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

// ── Address classification ───────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
enum AddrClass {
    /// Never a valid destination.
    Forbidden,
    /// Loopback, private, link-local, etc. — needs explicit permission.
    Internal,
    Public,
}

fn classify(ip: IpAddr) -> AddrClass {
    match ip.to_canonical() {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddrClass {
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return AddrClass::Forbidden;
    }
    let o = ip.octets();
    let internal = ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || o[0] == 0                                   // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (o[1] & 0xc0) == 64)        // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0.0/24 IETF
        || (o[0] == 198 && (o[1] & 0xfe) == 18)        // 198.18.0.0/15 benchmarking
        || o[0] >= 240; // 240.0.0.0/4 reserved
    if internal {
        AddrClass::Internal
    } else {
        AddrClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddrClass {
    if ip.is_unspecified() || ip.is_multicast() {
        return AddrClass::Forbidden;
    }
    let seg0 = ip.segments()[0];
    let internal = ip.is_loopback()
        || (seg0 & 0xfe00) == 0xfc00   // fc00::/7 unique local
        || (seg0 & 0xffc0) == 0xfe80   // fe80::/10 link-local
        || (seg0 & 0xffc0) == 0xfec0   // fec0::/10 site-local (deprecated)
        || seg0 == 0x0064              // 64:ff9b::/96 NAT64 can reach internal v4
        || seg0 == 0x2002; // 2002::/16 6to4 embeds arbitrary v4
    if internal {
        AddrClass::Internal
    } else {
        AddrClass::Public
    }
}

// ── Policy ────────────────────────────────────────────────────────────────────

/// Error carried through reqwest's resolver when every resolved address of a
/// target is disallowed. `forward_request` looks for it in the error chain to
/// return a 403 instead of a generic connection failure.
#[derive(Debug)]
pub struct BlockedTarget(pub String);

impl fmt::Display for BlockedTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StdError for BlockedTarget {}

#[derive(Debug)]
pub struct TargetPolicy {
    allow_private: bool,
    allowed_cidrs: Vec<Cidr>,
    allowed_hosts: Vec<String>,
    /// bw serve host name (lower-cased) and port — never a valid target.
    vault_host: Option<String>,
    vault_port: Option<u16>,
}

impl TargetPolicy {
    pub fn from_config(cfg: &Config) -> Self {
        let mut allowed_cidrs = Vec::new();
        let mut allowed_hosts = Vec::new();
        for entry in split_list(&cfg.allowed_targets) {
            match Cidr::parse(&entry) {
                Some(c) => allowed_cidrs.push(c),
                None => allowed_hosts.push(entry.to_ascii_lowercase()),
            }
        }
        let vault = Url::parse(&cfg.bw_serve_url).ok();
        Self {
            allow_private: cfg.allow_private_targets,
            allowed_cidrs,
            allowed_hosts,
            vault_host: vault
                .as_ref()
                .and_then(|u| u.host_str())
                .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase()),
            vault_port: vault.as_ref().and_then(|u| u.port_or_known_default()),
        }
    }

    fn host_allowed_by_name(&self, host: &str) -> bool {
        self.allowed_hosts.iter().any(|h| h == host)
    }

    /// Resolve the bw serve host to the addresses it is reachable on.
    async fn vault_addrs(&self) -> Vec<IpAddr> {
        let (Some(host), Some(port)) = (&self.vault_host, self.vault_port) else {
            return Vec::new();
        };
        match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(addrs) => addrs.map(|a| a.ip().to_canonical()).collect(),
            Err(_) => host.parse::<IpAddr>().map(|ip| vec![ip.to_canonical()]).unwrap_or_default(),
        }
    }

    /// Decide whether `ip:port`, reached via host name `host`, is allowed.
    fn check_ip(&self, host: &str, ip: IpAddr, port: u16, vault_addrs: &[IpAddr]) -> Result<(), String> {
        let ip = ip.to_canonical();
        if Some(port) == self.vault_port && vault_addrs.contains(&ip) {
            return Err("Target is the vault backend, which agents may not call".to_string());
        }
        match classify(ip) {
            AddrClass::Forbidden => Err(format!("Target address {ip} is not routable")),
            AddrClass::Public => Ok(()),
            AddrClass::Internal => {
                if self.allow_private
                    || self.host_allowed_by_name(host)
                    || self.allowed_cidrs.iter().any(|c| c.contains(&ip))
                {
                    Ok(())
                } else {
                    Err(format!(
                        "Target address {ip} is on a private or internal network; \
                         add it to allowed_targets to permit it"
                    ))
                }
            }
        }
    }

    /// Pre-flight check of a parsed target URL. Checks the scheme, refuses the
    /// vault host by name, and fully checks IP-literal hosts (which bypass the
    /// DNS resolver). Name-based hosts are checked again at resolution time.
    pub async fn check_url(&self, url: &Url) -> FerroResult<()> {
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(FerroError::InvalidTargetUrl(
                "Only http and https targets are allowed".to_string(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| FerroError::InvalidTargetUrl("Target URL has no host".to_string()))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| FerroError::InvalidTargetUrl("Target URL has no port".to_string()))?;

        // A named bw serve host is blocked on every port. An IP-literal one is
        // handled by the IP + port check below, since other services may
        // legitimately share that IP (e.g. 127.0.0.1).
        if self.vault_host.as_deref() == Some(host.as_str()) && host.parse::<IpAddr>().is_err() {
            return Err(FerroError::TargetBlocked(
                "Target is the vault backend, which agents may not call".to_string(),
            ));
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            let vault_addrs = self.vault_addrs().await;
            self.check_ip(&host, ip, port, &vault_addrs)
                .map_err(FerroError::TargetBlocked)?;
        }
        Ok(())
    }

    /// A reqwest DNS resolver enforcing this policy for one request.
    pub fn resolver(self: &Arc<Self>, port: u16) -> Arc<PolicyResolver> {
        Arc::new(PolicyResolver { policy: self.clone(), port })
    }
}

/// reqwest resolver that drops disallowed addresses after resolution.
pub struct PolicyResolver {
    policy: Arc<TargetPolicy>,
    port: u16,
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy.clone();
        let port = self.port;
        let host = name.as_str().to_ascii_lowercase();
        Box::pin(async move {
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| -> Box<dyn StdError + Send + Sync> { Box::new(e) })?
                .collect();
            let vault_addrs = policy.vault_addrs().await;

            let mut allowed = Vec::new();
            let mut last_reason = None;
            for addr in resolved {
                match policy.check_ip(&host, addr.ip(), port, &vault_addrs) {
                    Ok(()) => allowed.push(addr),
                    Err(reason) => last_reason = Some(reason),
                }
            }
            if allowed.is_empty() {
                let reason = last_reason.unwrap_or_else(|| "Target host did not resolve".to_string());
                return Err(Box::new(BlockedTarget(reason)) as Box<dyn StdError + Send + Sync>);
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

// ── Client IP for rate limiting ──────────────────────────────────────────────

/// Determine the client IP for rate limiting. When the TCP peer is a trusted
/// proxy, walk `X-Forwarded-For` from the right and return the first address
/// that is not itself a trusted proxy.
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>, trusted: &[Cidr]) -> IpAddr {
    let peer = peer.to_canonical();
    if !trusted.iter().any(|c| c.contains(&peer)) {
        return peer;
    }
    let Some(xff) = forwarded_for else { return peer };
    let mut candidate = peer;
    for part in xff.rsplit(',') {
        match part.trim().parse::<IpAddr>() {
            Ok(ip) => {
                let ip = ip.to_canonical();
                candidate = ip;
                if !trusted.iter().any(|c| c.contains(&ip)) {
                    return ip;
                }
            }
            Err(_) => break,
        }
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UnlockMode;

    fn cfg(allowed: &str, allow_private: bool) -> Config {
        Config {
            bind_addr: "127.0.0.1:3000".to_string(),
            bw_serve_url: "http://127.0.0.1:8087".to_string(),
            unlock_mode: UnlockMode::Manual,
            unlock_file: None,
            admin_key: "a".repeat(32),
            keys_file: None,
            tls_enabled: false,
            tls_cert_file: None,
            tls_key_file: None,
            allow_private_targets: allow_private,
            allowed_targets: allowed.to_string(),
            enforce_credential_hosts: true,
            refresh_interval_secs: 0,
            max_response_bytes: 1024,
            forward_timeout_secs: 30,
            trusted_proxies: String::new(),
            api_prefix: String::new(),
            agent_rate_limit_per_minute: 120,
            agent_rate_limit_burst: 20,
        }
    }

    #[test]
    fn cidr_parse_and_contains() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains(&"192.168.1.77".parse().unwrap()));
        assert!(!c.contains(&"192.168.2.1".parse().unwrap()));
        let single = Cidr::parse("10.0.0.5").unwrap();
        assert!(single.contains(&"10.0.0.5".parse().unwrap()));
        assert!(!single.contains(&"10.0.0.6".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("nas.lan").is_none());
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains(&"fd12::1".parse().unwrap()));
    }

    #[test]
    fn mapped_ipv4_is_classified_as_ipv4() {
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(classify(ip), AddrClass::Internal);
    }

    #[test]
    fn classification() {
        for s in ["127.0.0.1", "10.1.2.3", "172.20.0.2", "192.168.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "fe80::1"] {
            assert_eq!(classify(s.parse().unwrap()), AddrClass::Internal, "{s}");
        }
        for s in ["0.0.0.0", "255.255.255.255", "224.0.0.1", "::"] {
            assert_eq!(classify(s.parse().unwrap()), AddrClass::Forbidden, "{s}");
        }
        for s in ["1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert_eq!(classify(s.parse().unwrap()), AddrClass::Public, "{s}");
        }
    }

    #[tokio::test]
    async fn blocks_vault_backend_even_when_private_allowed() {
        let p = TargetPolicy::from_config(&cfg("127.0.0.0/8", true));
        let url = Url::parse("http://127.0.0.1:8087/object/password/x").unwrap();
        assert!(matches!(p.check_url(&url).await, Err(FerroError::TargetBlocked(_))));
        // Same IP, different port is a different service and is allowed here.
        let other = Url::parse("http://127.0.0.1:9000/").unwrap();
        assert!(p.check_url(&other).await.is_ok());
    }

    #[tokio::test]
    async fn blocks_vault_backend_by_host_name() {
        let mut c = cfg("", true);
        c.bw_serve_url = "http://bw-serve:8087".to_string();
        let p = TargetPolicy::from_config(&c);
        let url = Url::parse("http://BW-SERVE:8087/object/password/x").unwrap();
        assert!(matches!(p.check_url(&url).await, Err(FerroError::TargetBlocked(_))));
    }

    #[tokio::test]
    async fn private_ip_blocked_by_default_and_allowed_by_cidr() {
        let p = TargetPolicy::from_config(&cfg("", false));
        let url = Url::parse("http://192.168.1.10/api").unwrap();
        assert!(matches!(p.check_url(&url).await, Err(FerroError::TargetBlocked(_))));
        let meta = Url::parse("http://169.254.169.254/latest/meta-data").unwrap();
        assert!(matches!(p.check_url(&meta).await, Err(FerroError::TargetBlocked(_))));

        let p = TargetPolicy::from_config(&cfg("192.168.1.0/24", false));
        assert!(p.check_url(&url).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_non_http_scheme() {
        let p = TargetPolicy::from_config(&cfg("", false));
        let url = Url::parse("file:///etc/passwd").unwrap();
        assert!(matches!(p.check_url(&url).await, Err(FerroError::InvalidTargetUrl(_))));
    }

    #[tokio::test]
    async fn resolver_blocks_localhost_name() {
        let p = Arc::new(TargetPolicy::from_config(&cfg("", false)));
        let r = p.resolver(80);
        let err = match r.resolve("localhost".parse().unwrap()).await {
            Ok(_) => panic!("localhost must be blocked"),
            Err(e) => e,
        };
        assert!(err.downcast_ref::<BlockedTarget>().is_some());
    }

    #[tokio::test]
    async fn resolver_allows_named_internal_host() {
        let p = Arc::new(TargetPolicy::from_config(&cfg("localhost", false)));
        let r = p.resolver(80);
        assert!(r.resolve("localhost".parse().unwrap()).await.is_ok());
    }

    #[test]
    fn client_ip_ignores_xff_from_untrusted_peer() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(client_ip(peer, Some("1.2.3.4"), &[]), peer);
    }

    #[test]
    fn client_ip_uses_xff_from_trusted_proxy() {
        let trusted = vec![Cidr::parse("10.0.0.0/8").unwrap()];
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        // Leftmost entry is client-controlled; take the rightmost untrusted.
        let ip = client_ip(peer, Some("6.6.6.6, 198.51.100.7, 10.0.0.3"), &trusted);
        assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(peer, None, &trusted), peer);
    }
}
