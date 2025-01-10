use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Is this valid IP source address?
///
/// Mirrors what's specified in
/// IPv4: <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>
/// IPv6: <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>
///
pub const fn is_valid_source_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_valid_source_ip4(ip),
        IpAddr::V6(ip) => is_valid_source_ip6(ip),
    }
}

/// Is this valid IP destination address?
///
/// Mirrors what's specified in
/// IPv4: <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>
/// IPv6: <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>
///
pub const fn is_valid_destination_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_valid_destination_ip4(ip),
        IpAddr::V6(ip) => is_valid_destination_ip6(ip),
    }
}

/// Is this valid IP forwardable address?
///
/// Mirrors what's specified in
/// IPv4: <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>
/// IPv6: <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>
///
pub const fn is_valid_forwardable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_valid_forwardable_ip4(ip),
        IpAddr::V6(ip) => is_valid_forwardable_ip6(ip),
    }
}

/// Is this valid IPv4 source address?
///
/// Mirrors what's specified in
/// <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>
pub const fn is_valid_source_ip4(ip: Ipv4Addr) -> bool {
    // These are not valid:
    //  * 127.0.0.0/8 Loopback [RFC1122] Section 3.2.1.3
    //  * 192.0.0.0/24 IETF Protocol Assignments [RFC6890]
    //  * 192.0.0.170/32, 192.0.0.171/32 NAT64/DNS64 Discovery [RFC8880][RFC7050]
    //  * 192.0.2.0/24 Documentation (TEST-NET-1) [RFC5737]
    //  * 198.51.100.0/24 Documentation (TEST-NET-2) [RFC5737]
    //  * 203.0.113.0/24 Documentation (TEST-NET-3) [RFC5737]
    //  * 240.0.0.0/4 Reserved [RFC1112], Section 4
    //  * 255.255.255.255/32 Limited Broadcast [RFC8190] [RFC919], Section 7
    !ip.is_loopback()
        && !matches!(ip.octets(), [192, 0, 0, _])
        && !ip.is_documentation()
        && ip.octets()[0] & 240 != 240
}

/// Is this valid IPv4 destination address?
///
/// Mirrors what's specified in
/// <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>
pub const fn is_valid_destination_ip4(ip: Ipv4Addr) -> bool {
    // These are not valid:
    //  * 0.0.0.0/32 "This host on this network" [RFC1122], Section 3.2.1.3
    //  * 0.0.0.0/8 "This network" [RFC791], Section 3.2
    //  * 127.0.0.0/8 Loopback [RFC1122], Section 3.2.1.3
    //  * 192.0.0.0/24 [2] IETF Protocol Assignments [RFC6890], Section 2.1
    //  * 192.0.0.170/32, 192.0.0.171/32 NAT64/DNS64 Discovery [RFC8880][RFC7050], Section 2.2
    //  * 192.0.0.8/32 IPv4 dummy address [RFC7600]
    //  * 192.0.2.0/24 Documentation (TEST-NET-1) [RFC5737]
    //  * 198.51.100.0/24 Documentation (TEST-NET-2) [RFC5737]
    //  * 203.0.113.0/24 Documentation (TEST-NET-3) [RFC5737]
    //  * 240.0.0.0/4 Reserved [RFC1112], Section 4
    ip.octets()[0] != 0
        && !ip.is_loopback()
        && !matches!(ip.octets(), [192, 0, 0, _])
        && !ip.is_documentation()
        && (ip.is_broadcast() || ip.octets()[0] & 240 != 240)
}

/// Is this valid IPv4 forwardable address?
///
/// Mirrors what's specified in
/// <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>
pub const fn is_valid_forwardable_ip4(ip: Ipv4Addr) -> bool {
    // These are not valid:
    //  * 0.0.0.0/32 "This host on this network" [RFC1122], Section 3.2.1.3
    //  * 0.0.0.0/8 "This network" [RFC791], Section 3.2
    //  * 127.0.0.0/8 Loopback [RFC1122], Section 3.2.1.3
    //  * 169.254.0.0/16 Link Local [RFC3927]
    //  * 192.0.0.0/24 [2] IETF Protocol Assignments [RFC6890], Section 2.1
    //  * 192.0.0.170/32, 192.0.0.171/32 NAT64/DNS64 Discovery [RFC8880][RFC7050], Section 2.2
    //  * 192.0.0.8/32 IPv4 dummy address [RFC7600]
    //  * 192.0.2.0/24 Documentation (TEST-NET-1) [RFC5737]
    //  * 198.51.100.0/24 Documentation (TEST-NET-2) [RFC5737]
    //  * 203.0.113.0/24 Documentation (TEST-NET-3) [RFC5737]
    //  * 240.0.0.0/4 Reserved [RFC1112], Section 4
    //  * 255.255.255.255/32 Limited Broadcast [RFC8190] [RFC919], Section 7

    // If the value of "Destination" is FALSE, the values of "Forwardable" and
    // "Globally Reachable" must also be false.
    is_valid_destination_ip4(ip) && !matches!(ip.octets(), [169, 254, _, _]) && !ip.is_broadcast()
}

/// Is this valid IPv6 source address?
///
/// Mirrors what's specified in
/// <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>
pub const fn is_valid_source_ip6(ip: Ipv6Addr) -> bool {
    // These are not valid:
    //  * ::1/128 Loopback Address [RFC4291
    //  * ::ffff:0:0/96 IPv4-mapped Address [RFC4291]
    //  * 2001:db8::/32 Documentation [RFC3849]
    //  * 3fff::/20 Documentation [RFC9637]
    //
    // We've skipped handling "2001::/23 IETF Protocol Assignments [RFC2928]"
    // since it's not valid with a footnote of "Unless allowed by a more
    // specific allocation."
    !(ip.is_loopback()
        || matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        || matches!(ip.segments(), [0x2001, 0xdb8, _, _, _, _, _, _])
        || (ip.segments()[0] == 0x3fff && ip.segments()[1] >> 12 == 0))
}

/// Is this valid IPv6 destination address?
///
/// Mirrors what's specified in
/// <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>
pub const fn is_valid_destination_ip6(ip: Ipv6Addr) -> bool {
    // These are not valid:
    //  * ::/128 Unspecified Address [RFC4291]
    //  * ::1/128 Loopback Address [RFC4291]
    //  * ::ffff:0:0/96 IPv4-mapped Address [RFC4291]
    //  * 2001:db8::/32 Documentation [RFC3849]
    //  * 3fff::/20 Documentation [RFC9637]
    //
    // We've skipped handling "2001::/23 IETF Protocol Assignments [RFC2928]"
    // since it's not valid with a footnote of "Unless allowed by a more
    // specific allocation."
    !(matches!(ip.segments(), [0, 0, 0, 0, 0, 0, 0, 0])
        || ip.is_loopback()
        || matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        || matches!(ip.segments(), [0x2001, 0xdb8, _, _, _, _, _, _])
        || (ip.segments()[0] == 0x3fff && ip.segments()[1] >> 12 == 0))
}

/// Is this valid IPv6 forwardable address?
///
/// Mirrors what's specified in
/// <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>
pub const fn is_valid_forwardable_ip6(ip: Ipv6Addr) -> bool {
    // These are not valid:
    //  * ::/128 Unspecified Address [RFC4291]
    //  * ::1/128 Loopback Address [RFC4291]
    //  * ::ffff:0:0/96 IPv4-mapped Address [RFC4291]
    //  * 2001:db8::/32 Documentation [RFC3849]
    //  * 3fff::/20 Documentation [RFC9637]
    //  * fe80::/10 Link-Local Unicast [RFC4291]

    // If the value of "Destination" is FALSE, the values of "Forwardable" and
    // "Globally Reachable" must also be false.
    !is_valid_destination_ip6(ip) && !(ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // 0.0.0.0/32 "This host on this network" [RFC1122], Section 3.2.1.3
    // 0.0.0.0/8 "This network" [RFC791], Section 3.2
    const V4_THIS_NETWORK: &[Ipv4Addr] =
        &[Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 255, 255, 255)];

    // 127.0.0.0/8 Loopback [RFC1122] Section 3.2.1.3
    const V4_LOOPBACKS: &[Ipv4Addr] = &[
        Ipv4Addr::new(127, 0, 0, 0),
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(127, 255, 255, 255),
    ];

    // 192.0.0.0/24 IETF Protocol Assignments [RFC6890]
    // 192.0.0.170/32, 192.0.0.171/32 NAT64/DNS64 Discovery [RFC8880][RFC7050]
    const V4_IETF_PROTOCOL_ASSIGNMENTS: &[Ipv4Addr] = &[
        Ipv4Addr::new(192, 0, 0, 0),
        Ipv4Addr::new(192, 0, 0, 255),
        Ipv4Addr::new(192, 0, 0, 170),
        Ipv4Addr::new(192, 0, 0, 171),
    ];

    // 192.0.2.0/24 Documentation (TEST-NET-1) [RFC5737]
    // 198.51.100.0/24 Documentation (TEST-NET-2) [RFC5737]
    // 203.0.113.0/24 Documentation (TEST-NET-3) [RFC5737]
    const V4_DOCUMENTATION: &[Ipv4Addr] = &[
        Ipv4Addr::new(192, 0, 2, 0),
        Ipv4Addr::new(192, 0, 2, 255),
        Ipv4Addr::new(198, 51, 100, 0),
        Ipv4Addr::new(198, 51, 100, 255),
        Ipv4Addr::new(203, 0, 113, 0),
        Ipv4Addr::new(203, 0, 113, 255),
    ];

    // 240.0.0.0/4 Reserved [RFC1112], Section 4
    // 255.255.255.255/32 Limited Broadcast [RFC8190] [RFC919], Section 7
    const V4_RESERVED: &[Ipv4Addr] = &[
        Ipv4Addr::new(240, 0, 0, 0),
        Ipv4Addr::new(254, 255, 255, 255),
        Ipv4Addr::new(255, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
    ];

    // ::ffff:0:0/96 IPv4-mapped Address [RFC4291]
    const V6_V4_MAPPED: &[Ipv6Addr] = &[
        Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0),
        Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff),
    ];

    // fe80::/10 Link-Local Unicast [RFC4291]
    const V6_LINK_LOCAL_UNICAST: &[Ipv6Addr] = &[
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(
            0xfebf, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
    ];

    // 2001:db8::/32 Documentation [RFC3849]
    // 3fff::/20 Documentation [RFC9637]
    const V6_DOCUMENTATION: &[Ipv6Addr] = &[
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(
            0x2001, 0x0db8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
        Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(
            0x3fff, 0x0fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
    ];

    fn yield_invalid_source_ip4() -> impl Iterator<Item = Ipv4Addr> {
        V4_LOOPBACKS
            .iter()
            .chain(V4_IETF_PROTOCOL_ASSIGNMENTS)
            .chain(V4_DOCUMENTATION)
            .chain(V4_RESERVED)
            .cloned()
    }

    fn yield_invalid_destination_ip4() -> impl Iterator<Item = Ipv4Addr> {
        V4_THIS_NETWORK
            .iter()
            .chain(V4_LOOPBACKS)
            .chain(V4_IETF_PROTOCOL_ASSIGNMENTS)
            .chain(V4_DOCUMENTATION)
            .chain(V4_RESERVED)
            .filter(|ip| **ip != Ipv4Addr::BROADCAST)
            .cloned()
    }

    fn yield_invalid_forwardable_ip4() -> impl Iterator<Item = Ipv4Addr> {
        const OTHERS: &[Ipv4Addr] = &[
            Ipv4Addr::new(169, 254, 0, 0),
            Ipv4Addr::new(169, 254, 255, 255),
            Ipv4Addr::BROADCAST,
        ];

        // If the value of "Destination" is FALSE, the values of "Forwardable"
        // and "Globally Reachable" must also be false.
        yield_invalid_destination_ip4().chain(OTHERS.iter().cloned())
    }

    fn yield_invalid_source_ip6() -> impl Iterator<Item = Ipv6Addr> {
        const OTHERS: &[Ipv6Addr] = &[Ipv6Addr::LOCALHOST];

        V6_V4_MAPPED
            .iter()
            .chain(V6_DOCUMENTATION)
            .chain(OTHERS)
            .cloned()
    }

    fn yield_invalid_destination_ip6() -> impl Iterator<Item = Ipv6Addr> {
        const OTHERS: &[Ipv6Addr] = &[Ipv6Addr::UNSPECIFIED, Ipv6Addr::LOCALHOST];

        V6_V4_MAPPED
            .iter()
            .chain(V6_DOCUMENTATION)
            .chain(OTHERS)
            .cloned()
    }

    fn yield_invalid_forwardable_ip6() -> impl Iterator<Item = Ipv6Addr> {
        // If the value of "Destination" is FALSE, the values of "Forwardable"
        // and "Globally Reachable" must also be false.
        yield_invalid_destination_ip6().chain(V6_LINK_LOCAL_UNICAST.iter().cloned())
    }

    fn yield_valid_ip4() -> impl Iterator<Item = Ipv4Addr> {
        [
            Ipv4Addr::new(10, 0, 0, 0),   // Private-Use [RFC1918]
            Ipv4Addr::new(100, 64, 0, 0), // Shared Address Space [RFC6598]
            Ipv4Addr::new(198, 18, 0, 0), // Benchmarking [RFC2544]
        ]
        .into_iter()
    }

    fn yield_valid_ip6() -> impl Iterator<Item = Ipv6Addr> {
        [
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), // Unique-Local [RFC4193] [RFC8190]
            Ipv6Addr::new(0x2001, 0x000, 0, 0, 0, 0, 0, 0), // Benchmarking [RFC5180][RFC Errata 1752]
        ]
        .into_iter()
    }

    #[test]
    fn test_is_valid_source_ip4() {
        for ip in yield_invalid_source_ip4() {
            assert!(!is_valid_source_ip4(ip), "invalid ip {ip}");
        }

        for ip in yield_valid_ip4() {
            assert!(is_valid_source_ip4(ip), "invalid valid ip {ip}");
        }
    }

    #[test]
    fn test_is_valid_destination_ip4() {
        for ip in yield_invalid_destination_ip4() {
            assert!(!is_valid_destination_ip4(ip))
        }

        for ip in yield_valid_ip4() {
            assert!(is_valid_destination_ip4(ip), "invalid valid ip {ip}");
        }
    }

    #[test]
    fn test_is_valid_forwardable_ip4() {
        for ip in yield_invalid_forwardable_ip4() {
            assert!(!is_valid_forwardable_ip4(ip), "invalid ip {ip}");
        }

        for ip in yield_valid_ip4() {
            assert!(is_valid_forwardable_ip4(ip), "invalid valid ip {ip}");
        }
    }

    #[test]
    fn test_is_valid_source_ip6() {
        for ip in yield_invalid_source_ip6() {
            assert!(!is_valid_source_ip6(ip), "invalid ip {ip}");
        }

        for ip in yield_valid_ip6() {
            assert!(is_valid_source_ip6(ip), "invalid valid ip {ip}");
        }
    }

    #[test]
    fn test_is_valid_destination_ip6() {
        for ip in yield_invalid_destination_ip6() {
            assert!(!is_valid_destination_ip6(ip), "invalid ip {ip}");
        }

        for ip in yield_valid_ip6() {
            assert!(is_valid_destination_ip6(ip), "invalid valid ip {ip}");
        }
    }

    #[test]
    fn test_is_valid_forwardable_ip6() {
        for ip in yield_invalid_forwardable_ip6() {
            assert!(!is_valid_forwardable_ip6(ip), "invalid ip {ip}");
        }

        for ip in yield_valid_ip6() {
            assert!(is_valid_forwardable_ip6(ip), "invalid valid ip {ip}");
        }
    }

    #[test]
    fn test_is_valid_source_ip() {
        let ips = yield_invalid_source_ip4()
            .map(IpAddr::from)
            .chain(yield_invalid_source_ip6().map(IpAddr::from));

        for ip in ips {
            assert!(!is_valid_source_ip(ip), "invalid ip {ip}");
        }

        let ips = yield_valid_ip4()
            .map(IpAddr::from)
            .chain(yield_valid_ip6().map(IpAddr::from));

        for ip in ips {
            assert!(is_valid_source_ip(ip), "invalid valid ip {ip}");
        }
    }

    #[test]
    fn test_is_valid_destination_ip() {
        let ips = yield_invalid_destination_ip4()
            .map(IpAddr::from)
            .chain(yield_invalid_destination_ip6().map(IpAddr::from));

        for ip in ips {
            assert!(!is_valid_destination_ip(ip), "invalid ip {ip}");
        }

        let ips = yield_valid_ip4()
            .map(IpAddr::from)
            .chain(yield_valid_ip6().map(IpAddr::from));

        for ip in ips {
            assert!(is_valid_destination_ip(ip), "invalid valid ip {ip}");
        }
    }

    #[test]
    fn test_is_valid_forwardable_ip() {
        let ips = yield_invalid_forwardable_ip4()
            .map(IpAddr::from)
            .chain(yield_invalid_forwardable_ip6().map(IpAddr::from));

        for ip in ips {
            assert!(!is_valid_forwardable_ip(ip), "invalid ip {ip}");
        }

        let ips = yield_valid_ip4()
            .map(IpAddr::from)
            .chain(yield_valid_ip6().map(IpAddr::from));

        for ip in ips {
            assert!(is_valid_forwardable_ip(ip), "invalid valid ip {ip}");
        }
    }
}
