#![allow(missing_docs)]

#[cfg(target_os = "linux")]
mod linux {
    use clap::Parser;
    use luomu_tpacketv3 as tpacketv3;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn packet_consumer(ch: mpsc::Receiver<Vec<u8>>, stop: Arc<AtomicBool>) {
        let mut pkt_count = 0;
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            match ch.recv_timeout(std::time::Duration::from_secs(1)) {
                Err(e) => match e {
                    mpsc::RecvTimeoutError::Timeout => {
                        continue;
                    }
                    _ => {
                        tracing::warn!("Channel closed, stopping");
                        break;
                    }
                },
                Ok(_) => pkt_count += 1,
            }
        }
        tracing::debug!("Stopping, consumer received {pkt_count} packets");
    }

    fn print_stats(reader: &tpacketv3::Reader<'_>) {
        if let Ok((packets, dropped)) = reader.stats() {
            tracing::debug!("Tpacket packets: {packets}, dropped: {dropped}");
        }
    }

    fn packet_producer(mut reader: tpacketv3::Reader<'_>, ch: mpsc::Sender<Vec<u8>>, stop: Arc<AtomicBool>) {
        let mut false_wakes: u128 = 0;
        let mut wakes: u128 = 0;
        let mut packets: u128 = 0;
        loop {
            if stop.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            match reader.wait_block(Duration::from_millis(500)) {
                Err(e) => match e {
                    tpacketv3::WaitError::Timeout => {}
                    tpacketv3::WaitError::BlockNotReady => {
                        wakes += 1;
                        false_wakes += 1;
                    }
                    tpacketv3::WaitError::IoError(err) => {
                        tracing::warn!("Fatal error while reading: {err}");
                        break;
                    }
                },
                Ok(it) => {
                    wakes += 1;
                    for pkt in it {
                        packets += 1;
                        if let Err(e) = ch.send(pkt.packet().to_vec()) {
                            tracing::warn!("Unable to send packet to consumer: {e}");
                            // break out of reading packets, as this means likely
                            // that consumer has closed the channel and we are
                            // going to stop anyway
                            break;
                        }
                    }
                    reader.flush_block();
                }
            }
        }
        print_stats(&reader);
        let thread = thread::current();
        tracing::debug!(
            "Packet producer {} stopping; (wakes: {wakes}/ false wakes: {false_wakes} packets: {packets})",
            thread.name().unwrap_or("N/A"),
        );
    }

    fn worker(
        params: tpacketv3::ReaderParameters,
        interface: &str,
        ch: mpsc::Sender<Vec<u8>>,
        stop: Arc<AtomicBool>,
    ) {
        let thread = thread::current();
        tracing::debug!("starting worker {}", thread.name().unwrap_or("N/A"),);
        match tpacketv3::reader(interface, None, params) {
            Err(e) => tracing::warn!("Unable to create reader: {e}"),
            Ok(rd) => {
                packet_producer(rd, ch, stop);
            }
        }
    }

    #[derive(Parser)]
    struct Args {
        /// Name of the capture interface
        #[arg(short, long)]
        interface: String,

        /// Number of seconds to listen for traffic
        #[arg(short, long, default_value_t = 10)]
        duration: u64,

        /// Number of blocks to allocate for reader
        #[arg(short, long, default_value_t = 32)]
        blocks: u32,

        /// Size of block (needs to be multiple of 4096)
        #[arg(short = 's', long, default_value_t = 2097152)]
        blocksize: u32,

        /// Number of worker threads to run
        #[arg(short, long, default_value_t = 1)]
        workers: u32,

        /// Fanout mode to set
        #[arg(short, long)]
        fanout: Option<String>,

        /// ID of the fanout group
        #[arg(short, long)]
        groupid: Option<u16>,

        /// Do not put the interface into promiscuous mode
        #[arg(long)]
        no_promisc: bool,

        /// Block timeout
        #[arg(long, default_value_t = 100u32)]
        block_timeout_ms: u32,
    }

    pub fn main() {
        // tracing_subscriber::fmt::init();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let cli = Args::parse();

        let read_time: Duration = Duration::from_secs(cli.duration);
        let blocksize: u32 = cli.blocksize;
        let blocks: u32 = cli.blocks;
        let ifname = cli.interface;
        let workers: u32 = cli.workers;
        let groupid: u16 = cli.groupid.unwrap_or(1001);
        let promisc = !cli.no_promisc;
        let block_timeout = Duration::from_millis(cli.block_timeout_ms.into());

        let fanout_mode = if let Some(v) = cli.fanout {
            match &*v {
                "hash" => Some(tpacketv3::FanoutMode::HASH(groupid)),
                "lb" => Some(tpacketv3::FanoutMode::LB(groupid)),
                "qm" => Some(tpacketv3::FanoutMode::QM(groupid)),
                "cpu" => Some(tpacketv3::FanoutMode::CPU(groupid)),
                "rnd" => Some(tpacketv3::FanoutMode::RND(groupid)),
                _ => panic!("Fanout mode {v} not supported"),
            }
        } else {
            None
        };

        let stop = Arc::new(AtomicBool::new(false));
        let c_stop = stop.clone();
        let (tx, rx) = mpsc::channel();

        let consumer_handle = thread::Builder::new()
            .name("consumer".to_owned())
            .spawn(move || packet_consumer(rx, c_stop))
            .unwrap();

        let params = match tpacketv3::ReaderParameters::builder()
            .with_block_count(blocks)
            .with_block_size(blocksize)
            .with_fanout_mode(fanout_mode)
            .with_promiscuous_mode(promisc)
            .with_block_timeout(block_timeout)
            .build()
        {
            Err(err) => {
                println!("Invalid parameters: {err}");
                return;
            }
            Ok(p) => p,
        };

        tracing::debug!("starting workers. Using buffer of {blocks} {blocksize} byte blocks");

        let mut producers = Vec::new();
        for i in 0..workers {
            let flag = stop.clone();
            let tx_chan = tx.clone();
            let p = params;
            let p_ifname = ifname.clone();
            producers.push(
                thread::Builder::new()
                    .name(format!("producer-{}-{}", p_ifname, i))
                    .spawn(move || worker(p, &p_ifname, tx_chan, flag))
                    .unwrap(),
            );
        }
        tracing::debug!("Waiting for {} secons", read_time.as_secs());
        thread::sleep(read_time);
        tracing::debug!("Stopping threads");
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for h in producers {
            h.join().unwrap();
        }
        consumer_handle.join().unwrap();
        tracing::debug!("Done");
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("tpacket only available on linux")
}
