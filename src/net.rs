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
//!   * neither are the notifier endpoints (Gotify, ntfy, webhook URLs): an
//!     agent must not be able to post fake notifications or flood the
//!     operator's phone. A notifier host name is refused on every port, an IP
//!     literal or a resolved address on the notifier's port; an address
//!     reached through a host name the operator listed in `allowed_targets`
//!     is left to that explicit entry, since another service may share the
//!     address;
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
        let net: IpAddr = addr
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .ok()?;
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
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
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

/// Shown to the agent when a request names a notifier. It says no more than
/// the vault message does.
const NOTIFIER_BLOCKED: &str = "Target is a notification endpoint, which agents may not call";

/// The addresses the denied endpoints currently resolve to.
#[derive(Default)]
struct DeniedAddrs {
    vault: Vec<IpAddr>,
    /// `(address, port)` of each notifier endpoint.
    notifiers: Vec<(IpAddr, u16)>,
}

#[derive(Debug)]
pub struct TargetPolicy {
    allow_private: bool,
    allowed_cidrs: Vec<Cidr>,
    allowed_hosts: Vec<String>,
    /// bw serve host name (lower-cased) and port — never a valid target.
    vault_host: Option<String>,
    vault_port: Option<u16>,
    /// Host (lower-cased) and port of every notifier URL — never a valid
    /// target either.
    notifiers: Vec<(String, u16)>,
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
            vault_host: vault.as_ref().and_then(|u| u.host_str()).map(|h| {
                h.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_ascii_lowercase()
            }),
            vault_port: vault.as_ref().and_then(|u| u.port_or_known_default()),
            notifiers: cfg.notify.endpoints(),
        }
    }

    /// Whether `host` (lower-cased, no brackets) is a notifier's host name.
    fn is_notifier_name(&self, host: &str) -> bool {
        host.parse::<IpAddr>().is_err() && self.notifiers.iter().any(|(h, _)| h == host)
    }

    /// Resolve the bw serve host and the notifier hosts.
    async fn denied_addrs(&self) -> DeniedAddrs {
        let mut out = DeniedAddrs {
            vault: self.vault_addrs().await,
            notifiers: Vec::new(),
        };
        for (host, port) in &self.notifiers {
            match tokio::net::lookup_host((host.as_str(), *port)).await {
                Ok(addrs) => out
                    .notifiers
                    .extend(addrs.map(|a| (a.ip().to_canonical(), *port))),
                Err(_) => {
                    if let Ok(ip) = host.parse::<IpAddr>() {
                        out.notifiers.push((ip.to_canonical(), *port));
                    }
                }
            }
        }
        out
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
            Err(_) => host
                .parse::<IpAddr>()
                .map(|ip| vec![ip.to_canonical()])
                .unwrap_or_default(),
        }
    }

    /// Decide whether `ip:port`, reached via host name `host`, is allowed.
    fn check_ip(
        &self,
        host: &str,
        ip: IpAddr,
        port: u16,
        denied: &DeniedAddrs,
    ) -> Result<(), String> {
        let ip = ip.to_canonical();
        if Some(port) == self.vault_port && denied.vault.contains(&ip) {
            return Err("Target is the vault backend, which agents may not call".to_string());
        }
        // A notifier's address on its port. A host name the operator has
        // listed in `allowed_targets` is their explicit decision about that
        // name (the notifier may share an address with a service they allow);
        // everything else, IP literals included, is refused.
        if denied.notifiers.contains(&(ip, port)) && !self.host_allowed_by_name(host) {
            return Err(NOTIFIER_BLOCKED.to_string());
        }
        if self.is_notifier_name(host) {
            return Err(NOTIFIER_BLOCKED.to_string());
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

        // A notifier host name is blocked on every port.
        if self.is_notifier_name(&host) {
            return Err(FerroError::TargetBlocked(NOTIFIER_BLOCKED.to_string()));
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            let denied = self.denied_addrs().await;
            self.check_ip(&host, ip, port, &denied)
                .map_err(FerroError::TargetBlocked)?;
        }
        Ok(())
    }

    /// A reqwest DNS resolver enforcing this policy for one request.
    pub fn resolver(self: &Arc<Self>, port: u16) -> Arc<PolicyResolver> {
        Arc::new(PolicyResolver {
            policy: self.clone(),
            port,
        })
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
            let denied = policy.denied_addrs().await;

            let mut allowed = Vec::new();
            let mut last_reason = None;
            for addr in resolved {
                match policy.check_ip(&host, addr.ip(), port, &denied) {
                    Ok(()) => allowed.push(addr),
                    Err(reason) => last_reason = Some(reason),
                }
            }
            if allowed.is_empty() {
                let reason =
                    last_reason.unwrap_or_else(|| "Target host did not resolve".to_string());
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
    let Some(xff) = forwarded_for else {
        return peer;
    };
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
            admin_key: "a".repeat(32).into(),
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
            admin_rate_limit_per_minute: 30,
            admin_rate_limit_burst: 5,
            events: Default::default(),
            ui: Default::default(),
            notify: Default::default(),
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
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "172.20.0.2",
            "192.168.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
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
        assert!(matches!(
            p.check_url(&url).await,
            Err(FerroError::TargetBlocked(_))
        ));
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
        assert!(matches!(
            p.check_url(&url).await,
            Err(FerroError::TargetBlocked(_))
        ));
    }

    #[tokio::test]
    async fn private_ip_blocked_by_default_and_allowed_by_cidr() {
        let p = TargetPolicy::from_config(&cfg("", false));
        let url = Url::parse("http://192.168.1.10/api").unwrap();
        assert!(matches!(
            p.check_url(&url).await,
            Err(FerroError::TargetBlocked(_))
        ));
        let meta = Url::parse("http://169.254.169.254/latest/meta-data").unwrap();
        assert!(matches!(
            p.check_url(&meta).await,
            Err(FerroError::TargetBlocked(_))
        ));

        let p = TargetPolicy::from_config(&cfg("192.168.1.0/24", false));
        assert!(p.check_url(&url).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_non_http_scheme() {
        let p = TargetPolicy::from_config(&cfg("", false));
        let url = Url::parse("file:///etc/passwd").unwrap();
        assert!(matches!(
            p.check_url(&url).await,
            Err(FerroError::InvalidTargetUrl(_))
        ));
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

    // ── Notifier endpoints are off-limits to agents ───────────────────────────

    fn notify_cfg(allowed: &str, allow_private: bool, urls: [&str; 3]) -> Config {
        let mut c = cfg(allowed, allow_private);
        c.notify.gotify_url = urls[0].to_string();
        c.notify.ntfy_url = urls[1].to_string();
        c.notify.webhook_url = urls[2].to_string();
        c.notify.allow_http = true;
        c
    }

    fn blocked_with(err: FerroResult<()>) -> String {
        match err {
            Err(FerroError::TargetBlocked(m)) => m,
            other => panic!("expected TargetBlocked, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn notifier_host_names_are_refused_on_every_port_even_when_listed_as_allowed() {
        let c = notify_cfg(
            "gotify.lan,ntfy.lan,notify-sink,mock-api",
            true,
            [
                "http://gotify.lan:8080",
                "https://ntfy.lan/ferrowarden",
                "http://notify-sink:7777/notify",
            ],
        );
        let p = TargetPolicy::from_config(&c);
        for url in [
            "http://gotify.lan:8080/message",
            "http://gotify.lan:9999/anything",
            "https://GOTIFY.lan/",
            "https://ntfy.lan/ferrowarden",
            "http://ntfy.lan:80/other",
            "http://notify-sink:7777/notify",
            "http://notify-sink:7777/__requests__",
            "http://notify-sink/",
        ] {
            let m = blocked_with(p.check_url(&Url::parse(url).unwrap()).await);
            assert!(m.contains("notification endpoint"), "{url}: {m}");
            assert!(!m.contains("gotify") && !m.contains("notify-sink"), "{m}");
        }
        // The host next to it (same address, other name) is not affected.
        for url in [
            "http://mock-api:7777/api/check",
            "http://other.example.com/",
        ] {
            assert!(
                p.check_url(&Url::parse(url).unwrap()).await.is_ok(),
                "{url}"
            );
        }
    }

    #[tokio::test]
    async fn the_resolver_path_refuses_notifier_names_too() {
        let c = notify_cfg("localhost", true, ["", "", "http://localhost:9999/notify"]);
        let p = Arc::new(TargetPolicy::from_config(&c));
        for port in [9999, 80] {
            let r = p.resolver(port);
            let err = match r.resolve("LocalHost".parse().unwrap()).await {
                Ok(_) => panic!("the notifier host must be refused"),
                Err(e) => e,
            };
            let blocked = err.downcast_ref::<BlockedTarget>().expect("BlockedTarget");
            assert!(blocked.0.contains("notification endpoint"), "{blocked}");
        }
        // Without the notifier, the same allowed name resolves.
        let p = Arc::new(TargetPolicy::from_config(&cfg("localhost", true)));
        assert!(p
            .resolver(9999)
            .resolve("localhost".parse().unwrap())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn a_notifier_ip_literal_is_refused_on_its_port_only() {
        let c = notify_cfg(
            "",
            true,
            ["", "http://127.0.0.1:9999/topic", "http://[::1]:7777/n"],
        );
        let p = TargetPolicy::from_config(&c);
        for url in ["http://127.0.0.1:9999/message", "http://[::1]:7777/x"] {
            blocked_with(p.check_url(&Url::parse(url).unwrap()).await);
        }
        // Another service on the same address is a different target.
        for url in [
            "http://127.0.0.1:9998/",
            "http://127.0.0.1/",
            "http://[::1]:7778/",
        ] {
            assert!(
                p.check_url(&Url::parse(url).unwrap()).await.is_ok(),
                "{url}"
            );
        }
    }

    #[tokio::test]
    async fn an_ip_literal_that_a_notifier_name_resolves_to_is_refused() {
        // `localhost` resolves to loopback addresses; the notifier is there on 9999.
        let c = notify_cfg("", true, ["", "", "http://localhost:9999/n"]);
        let p = TargetPolicy::from_config(&c);
        let resolved: Vec<IpAddr> = tokio::net::lookup_host(("localhost", 9999))
            .await
            .unwrap()
            .map(|a| a.ip())
            .collect();
        assert!(!resolved.is_empty());
        for ip in resolved {
            let url = match ip {
                IpAddr::V4(v4) => format!("http://{v4}:9999/x"),
                IpAddr::V6(v6) => format!("http://[{v6}]:9999/x"),
            };
            blocked_with(p.check_url(&Url::parse(&url).unwrap()).await);
        }
    }

    #[test]
    fn an_address_shared_with_a_notifier_is_the_operators_call_by_name_only() {
        // notify-sink and mock-api share 10.0.0.5:7777 (compose aliases). The
        // operator listed mock-api, so that name still works; any other way
        // to the same address and port is refused.
        let mut c = notify_cfg("mock-api", true, ["", "", "http://notify-sink:7777/n"]);
        c.allow_private_targets = false;
        let p = TargetPolicy::from_config(&c);
        let shared: IpAddr = "10.0.0.5".parse().unwrap();
        let denied = DeniedAddrs {
            vault: Vec::new(),
            notifiers: vec![(shared, 7777)],
        };
        assert!(p.check_ip("mock-api", shared, 7777, &denied).is_ok());
        assert!(p.check_ip("mock-api", shared, 7778, &denied).is_ok());
        let m = p
            .check_ip("notify-sink", shared, 7777, &denied)
            .unwrap_err();
        assert!(m.contains("notification endpoint"), "{m}");
        let m = p.check_ip("10.0.0.5", shared, 7777, &denied).unwrap_err();
        assert!(m.contains("notification endpoint"), "{m}");
        // A name that is not listed falls to the private-address rule anyway.
        assert!(p.check_ip("evil.example", shared, 7777, &denied).is_err());
        // Even listed, the notifier's own name never passes.
        let c = notify_cfg(
            "mock-api,notify-sink",
            false,
            ["", "", "http://notify-sink:7777/n"],
        );
        let p = TargetPolicy::from_config(&c);
        assert!(p.check_ip("notify-sink", shared, 1234, &denied).is_err());
    }

    #[tokio::test]
    async fn without_a_notifier_nothing_extra_is_denied() {
        let p = TargetPolicy::from_config(&cfg("notify-sink", true));
        assert!(p
            .check_url(&Url::parse("http://notify-sink:7777/").unwrap())
            .await
            .is_ok());
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
