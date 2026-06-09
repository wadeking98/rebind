//! DNS server built on [`hickory_server`]. It answers A and AAAA queries by
//! *decoding the requested IP addresses out of the queried name itself* — the
//! core primitive used in DNS rebinding test harnesses.
//!
//! # Subdomain encoding scheme
//!
//! Every label in the queried name is inspected independently. A label is
//! emitted as an answer record if it matches one of these forms:
//!
//! * **IPv4** — four dash-separated decimal octets, e.g. `192-168-1-1`
//!   produces the A record `192.168.1.1`.
//! * **IPv6** — up to eight dash-separated hex groups, with the token `z`
//!   standing in for the `::` zero-run, e.g. `2001-db8-z-1` → `2001:db8::1`,
//!   or the fully expanded `2001-db8-0-0-0-0-0-1`.
//!
//! Multiple records are returned by stacking labels, e.g.
//! `192-168-1-1.10-0-0-1.rebind.example.com` resolves (for a type-A query) to
//! both `192.168.1.1` and `10.0.0.1`. Labels that don't parse as an IP (the
//! base domain, decorative labels, etc.) are ignored, so the scheme works
//! regardless of which base domain is delegated to this server.
//!
//! Because non-IP labels are skipped, a client can insert a **random label to
//! defeat DNS caching** and force a fresh resolution each time, e.g.
//! `<IP>.<IP>.<random>.example.com` such as
//! `192-168-1-1.10-0-0-1.k3f9zq.example.com`. The `k3f9zq` label simply
//! doesn't parse as an IP and is ignored, while the addresses are still
//! returned.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use rand::seq::SliceRandom;
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::ServerFuture;
use tokio::net::{TcpListener, UdpSocket};

/// The request handler implementing the subdomain-encoding scheme.
pub struct RebindHandler {
    /// TTL placed on every answer. Rebinding wants a very short cache lifetime
    /// so the victim re-resolves quickly; 0 means "do not cache".
    pub ttl: u32,
}

#[async_trait]
impl RequestHandler for RebindHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        match self.respond(request, &mut response_handle).await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("dns response failed: {e}");
                let mut header = Header::response_from_request(request.header());
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}

impl RebindHandler {
    async fn respond<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
    ) -> Result<ResponseInfo, Box<dyn std::error::Error>> {
        let query = request.query();
        let name = query.name().to_string();
        let qtype = query.query_type();
        tracing::info!("query {name} type={qtype}");

        // Decode the matching addresses out of the name (random/base-domain
        // labels are ignored) and turn them into records.
        let mut records: Vec<Record> = decode_addrs(&name, qtype)
            .into_iter()
            .map(|ip| {
                let rdata = match ip {
                    IpAddr::V4(v4) => RData::A(A(v4)),
                    IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
                };
                Record::from_rdata(query.name().into(), self.ttl, rdata)
            })
            .collect();

        // Randomize the answer order. Some browsers/resolvers prioritize the
        // first record returned, so shuffling spreads selection across all
        // encoded addresses (and helps flip between rebinding targets).
        records.shuffle(&mut rand::thread_rng());

        if !records.is_empty() {
            tracing::info!("answering with {} record(s)", records.len());
        }

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(response_handle.send_response(response).await?)
    }
}

/// Run the DNS server (UDP + TCP) on `bind` (e.g. `0.0.0.0:53`) forever.
pub async fn serve(bind: &str, ttl: u32) -> Result<(), Box<dyn std::error::Error>> {
    let handler = RebindHandler { ttl };
    let mut server = ServerFuture::new(handler);

    let udp = UdpSocket::bind(bind).await?;
    server.register_socket(udp);

    let tcp = TcpListener::bind(bind).await?;
    server.register_listener(tcp, std::time::Duration::from_secs(5));

    tracing::info!("dns listening on {bind} (udp+tcp, ttl={ttl})");
    server.block_until_done().await?;
    Ok(())
}

/// Encode an IP address into a single dash-separated DNS label using the same
/// scheme [`decode_addrs`] understands. IPv4 becomes `a-b-c-d`; IPv6 becomes
/// its eight hex groups joined with `-` (no `z` compression on output).
pub fn ip_to_label(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4
            .octets()
            .iter()
            .map(|o| o.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        IpAddr::V6(v6) => v6
            .segments()
            .iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join("-"),
    }
}

/// Decode the addresses encoded in `name` that match the query type. Every
/// label is tried independently; labels that don't parse as an IP — including a
/// random cache-busting label and the base domain — are ignored. A queries
/// yield only IPv4 results; AAAA queries only IPv6.
fn decode_addrs(name: &str, qtype: RecordType) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for label in name.split('.') {
        match qtype {
            RecordType::A => {
                if let Some(ip) = parse_ipv4_label(label) {
                    out.push(IpAddr::V4(ip));
                }
            }
            RecordType::AAAA => {
                if let Some(ip) = parse_ipv6_label(label) {
                    out.push(IpAddr::V6(ip));
                }
            }
            _ => {}
        }
    }
    out
}

/// Parse `a-b-c-d` (four decimal octets) into an IPv4 address.
fn parse_ipv4_label(label: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = label.split('-').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        // Reject non-decimal so e.g. "ff" doesn't masquerade as IPv4.
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        octets[i] = p.parse::<u8>().ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

/// Parse dash-separated hex groups into an IPv6 address. A single `z` token
/// stands in for the `::` zero-run.
fn parse_ipv6_label(label: &str) -> Option<Ipv6Addr> {
    let toks: Vec<&str> = label.split('-').collect();
    let zpos = toks.iter().position(|t| *t == "z");

    // Reject more than one `z`.
    if toks.iter().filter(|t| **t == "z").count() > 1 {
        return None;
    }

    let parse_group = |t: &str| -> Option<u16> {
        if t.is_empty() || t.len() > 4 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u16::from_str_radix(t, 16).ok()
    };

    let mut groups = [0u16; 8];

    match zpos {
        None => {
            if toks.len() != 8 {
                return None;
            }
            for (i, t) in toks.iter().enumerate() {
                groups[i] = parse_group(t)?;
            }
        }
        Some(zi) => {
            let before = &toks[..zi];
            let after = &toks[zi + 1..];
            let fill = 8usize.checked_sub(before.len() + after.len())?;
            if fill == 0 {
                return None; // `z` must compress at least one zero group
            }
            for (i, t) in before.iter().enumerate() {
                groups[i] = parse_group(t)?;
            }
            for (i, t) in after.iter().enumerate() {
                groups[8 - after.len() + i] = parse_group(t)?;
            }
            // middle stays zero
        }
    }

    Some(Ipv6Addr::from(groups))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_label() {
        assert_eq!(parse_ipv4_label("192-168-1-1"), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(parse_ipv4_label("10-0-0-1"), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(parse_ipv4_label("256-0-0-1"), None);
        assert_eq!(parse_ipv4_label("1-2-3"), None);
        assert_eq!(parse_ipv4_label("rebind"), None);
    }

    #[test]
    fn label_roundtrip() {
        let v4: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(ip_to_label(v4), "192-168-1-1");
        assert_eq!(decode_addrs(&format!("{}.x", ip_to_label(v4)), RecordType::A), vec![v4]);

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        // 8 expanded groups, decodes back to the same address.
        assert_eq!(ip_to_label(v6), "2001-db8-0-0-0-0-0-1");
        assert_eq!(decode_addrs(&format!("{}.x", ip_to_label(v6)), RecordType::AAAA), vec![v6]);
    }

    #[test]
    fn ignores_random_and_base_labels() {
        // <IP>.<IP>.<random>.example.com — the random label defeats caching
        // and must be ignored while both IPs are still returned.
        let name = "192-168-1-1.10-0-0-1.k3f9zq.example.com.";
        assert_eq!(
            decode_addrs(name, RecordType::A),
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ]
        );
        // Same name, AAAA query -> no IPv6 labels present -> empty.
        assert!(decode_addrs(name, RecordType::AAAA).is_empty());

        // IPv6 with a trailing random label.
        let v6 = "2001-db8-z-1.9fa2c.example.com.";
        assert_eq!(
            decode_addrs(v6, RecordType::AAAA),
            vec![IpAddr::V6("2001:db8::1".parse().unwrap())]
        );
    }

    #[test]
    fn ipv6_label() {
        assert_eq!(parse_ipv6_label("2001-db8-z-1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(
            parse_ipv6_label("2001-db8-0-0-0-0-0-1"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(parse_ipv6_label("z"), Some(Ipv6Addr::UNSPECIFIED));
        assert_eq!(parse_ipv6_label("2001-db8-z-z-1"), None);
        assert_eq!(parse_ipv6_label("gggg-1-1-1-1-1-1-1"), None);
    }
}
