//! Prints IP Addresses for all interfaces found

use std::{collections::HashMap, net::IpAddr};

fn main() -> std::io::Result<()> {
    let mut addresses: HashMap<Box<str>, Vec<IpAddr>> = HashMap::new();
    for ifa in luomu_getifaddrs::getifaddrs()? {
        if let Some(a) = ifa.addr().and_then(|a| a.as_ip()) {
            let addrs = addresses.entry(ifa.name().into()).or_default();
            addrs.push(a);
        }
    }
    for (name, addrs) in addresses {
        let addrs_text = addrs
            .into_iter()
            .map(|a| a.to_string())
            .collect::<Box<[String]>>()
            .join(", ");

        println!("{name}: {addrs_text}")
    }

    Ok(())
}
