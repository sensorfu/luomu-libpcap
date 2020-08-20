use std::error;
use std::fmt;

/// Errors produced by luomu-libpcap.
#[derive(Debug)]
pub enum Error {
    /// Loop terminated by pcap_breakloop (PCAP_ERROR_BREAK).
    Break,
    /// The capture needs to be activated (PCAP_ERROR_NOT_ACTIVATED).
    NotActivated,
    /// Capture handle already activated (PCAP_ERROR_ACTIVATED).
    AlreadyActivated,
    /// The capture source specified when the handle was created doesn't exist
    /// (PCAP_ERROR_NO_SUCH_DEVICE).
    NoSuchDevice,
    /// Monitor mode was specified but the capture source doesn't support
    /// monitor mode (PCAP_ERROR_RFMON_NOTSUP).
    MonitorModeNotSupported,
    /// The operation is supported only in monitor mode (PCAP_ERROR_NOT_RFMON).
    OnlySupportedInMonitorMode,
    /// The process doesn't have permission to open the capture source
    /// (PCAP_ERROR_PERM_DENIED).
    PermissionDenied,
    /// The capture source device is not up (PCAP_ERROR_IFACE_NOT_UP).
    InterfaceNotUp,
    /// This device doesn't support setting the time stamp type
    /// (PCAP_ERROR_CANTSET_TSTAMP_TYPE).
    TimestampTypeNotSupported,
    /// The process has permission to open the capture source but doesn't have
    /// permission to put it into promiscuous mode
    /// (PCAP_ERROR_PROMISC_PERM_DENIED).
    PromiscuousPermissionDenied,
    /// The requested time stamp precision is not supported
    /// (PCAP_ERROR_TSTAMP_PRECISION_NOTSUP).
    TimestampPrecisionNotSupported,

    /// Error from `libpcap`
    PcapError(String),
    /// Warning from `libpcap`
    PcapWarning(String),
    /// Unknown error code from `libpcap`.
    PcapErrorCode(i32),

    /// Timeout happened (maybe during live capture)
    Timeout,
    /// Error from Rust <-> C String conversion
    CStringError(Box<dyn error::Error>),
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Break => write!(f, "libpcap: Loop terminated by pcap_breakloop (PCAP_ERROR_BREAK)."),
            Error::NotActivated => write!(f, "libpcap: The capture needs to be activated (PCAP_ERROR_NOT_ACTIVATED)."),
            Error::AlreadyActivated => write!(f, "libpcap: Capture handle already activated (PCAP_ERROR_ACTIVATED)."),
            Error::NoSuchDevice => write!(f, "libpcap: The capture source specified when the handle was created doesn't exist (PCAP_ERROR_NO_SUCH_DEVICE)."),
            Error::MonitorModeNotSupported => write!(f, "libpcap: Monitor mode was specified but the capture source doesn't support monitor mode (PCAP_ERROR_RFMON_NOTSUP)."),
            Error::OnlySupportedInMonitorMode => write!(f, "libpcap: The operation is supported only in monitor mode (PCAP_ERROR_NOT_RFMON)."),
            Error::PermissionDenied => write!(f, "libpcap: The process doesn't have permission to open the capture source (PCAP_ERROR_PERM_DENIED)."),
            Error::InterfaceNotUp => write!(f, "libpcap: The capture source device is not up (PCAP_ERROR_IFACE_NOT_UP)."),
            Error::TimestampTypeNotSupported => write!(f, "libpcap: This device doesn't support setting the time stamp type (PCAP_ERROR_CANTSET_TSTAMP_TYPE)."),
            Error::PromiscuousPermissionDenied => write!(f, "libpcap: The process has permission to open the capture source but doesn't have permission to put it into promiscuous mode (PCAP_ERROR_PROMISC_PERM_DENIED)."),
            Error::TimestampPrecisionNotSupported => write!(f, "libcap: The requested time stamp precision is not supported (PCAP_ERROR_TSTAMP_PRECISION_NOTSUP)."),

            Error::PcapError(err) => write!(f, "libpcap error: {}", err),
            Error::PcapWarning(warn) => write!(f, "libpcap warning: {}", warn),
            Error::PcapErrorCode(code) => write!(f, "libpcap unknown error code: {}", code),

            Error::Timeout => write!(f, "timeout"),
            Error::CStringError(err) => err.fmt(f),
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Error::CStringError(Box::new(err))
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Self {
        Error::CStringError(Box::new(err))
    }
}

impl From<std::ffi::FromBytesWithNulError> for Error {
    fn from(err: std::ffi::FromBytesWithNulError) -> Self {
        Error::CStringError(Box::new(err))
    }
}
