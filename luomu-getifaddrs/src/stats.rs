#[cfg(target_os = "linux")]
pub use RtnlLinkStats as LinkStats;

#[cfg(target_os = "macos")]
pub use libc::if_data as LinkStats;

/// Source: <https://www.kernel.org/doc/html/latest/networking/statistics.html#c.rtnl_link_stats64>
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Hash)]
pub struct RtnlLinkStats {
    pub rx_packets: u32,
    pub tx_packets: u32,
    pub rx_bytes: u32,
    pub tx_bytes: u32,
    pub rx_errors: u32,
    pub tx_errors: u32,
    pub rx_dropped: u32,
    pub tx_dropped: u32,
    pub multicast: u32,
    pub collisions: u32,
    pub rx_length_errors: u32,
    pub rx_over_errors: u32,
    pub rx_crc_errors: u32,
    pub rx_frame_errors: u32,
    pub rx_fifo_errors: u32,
    pub rx_missed_errors: u32,
    pub tx_aborted_errors: u32,
    pub tx_carrier_errors: u32,
    pub tx_fifo_errors: u32,
    pub tx_heartbeat_errors: u32,
    pub tx_window_errors: u32,
    pub rx_compressed: u32,
    pub tx_compressed: u32,
    pub rx_nohandler: u32,
}

/// Trait for accessing most common network interface statistics that are
/// available between operating systems.
pub trait IfStats {
    /// Received packets for interface
    fn rx_packets(&self) -> usize;

    /// Transmitted packets for interface
    fn tx_packets(&self) -> usize;

    /// Received bytes for interface
    fn rx_bytes(&self) -> usize;

    /// Transmitted bytes for interface
    fn tx_bytes(&self) -> usize;
}

#[cfg(target_os = "macos")]
impl IfStats for libc::if_data {
    fn rx_packets(&self) -> usize {
        self.ifi_ipackets as usize
    }

    fn tx_packets(&self) -> usize {
        self.ifi_opackets as usize
    }

    fn rx_bytes(&self) -> usize {
        self.ifi_ibytes as usize
    }

    fn tx_bytes(&self) -> usize {
        self.ifi_obytes as usize
    }
}

#[cfg(target_os = "linux")]
impl IfStats for RtnlLinkStats {
    fn rx_packets(&self) -> usize {
        self.rx_packets as usize
    }

    fn tx_packets(&self) -> usize {
        self.tx_packets as usize
    }

    fn rx_bytes(&self) -> usize {
        self.rx_bytes as usize
    }

    fn tx_bytes(&self) -> usize {
        self.tx_bytes as usize
    }
}
