use std::{collections::HashMap, net::IpAddr};

/// Prints IP Addresses for all interfaces found
fn main() -> std::io::Result<()> {
    let mut addresses: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for ifa in luomu_getifaddrs::getifaddrs()? {
        if let Some(a) = ifa.addr().and_then(|a| a.as_ip()) {
            let addrs = addresses.entry(ifa.name().to_owned()).or_default();
            addrs.push(a);
        }
    }
    for (name, addrs) in addresses {
        let addrs_text = addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
            .join(", ");

        println!("{name}: {addrs_text}")
    }

    Ok(())
}
