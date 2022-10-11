use anyhow::Result;
use std::time::Duration;

use futures_util::TryStreamExt;

use luomu_libpcap::tokio as tokio_capture;
use luomu_libpcap::{Packet, Pcap};

fn main() -> Result<()> {
    env_logger::init();
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async { capture("en0").await })
}

async fn capture(interface: &'static str) -> Result<()> {
    let pcap = Pcap::builder(interface)?
        .set_promiscuous(true)?
        .set_snaplen(65535)?
        .set_timeout(Duration::from_millis(1000))?
        .activate()?;

    tokio::task::spawn(async { ticker().await });

    let mut pcap = tokio_capture::AsyncCapture::new(pcap)?;

    while let Some(packet) = pcap.try_next().await? {
        println!("{:?}", packet.timestamp());
    }

    Ok(())
}

async fn ticker() {
    let mut counter = 0;
    loop {
        println!("tick {}", counter);
        counter += 1;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
