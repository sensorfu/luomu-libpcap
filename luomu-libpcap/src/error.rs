use std::error;
use std::fmt;
use std::io;

/// Errors produced by luomu-libpcap.
#[derive(Debug)]
pub enum Error {
    /// Loop terminated by pcap_breakloop (PCAP_ERROR_BREAK).
    Break,
    /// The capture needs to be activated (PCAP_ERROR_NOT_ACTIVATED).
    NotActivated(String),
    /// Capture handle already activated (PCAP_ERROR_ACTIVATED).
    AlreadyActivated(String),
    /// The capture source specified when the handle was created doesn't exist
    /// (PCAP_ERROR_NO_SUCH_DEVICE).
    NoSuchDevice(String),
    /// Monitor mode was specified but the capture source doesn't support
    /// monitor mode (PCAP_ERROR_RFMON_NOTSUP).
    MonitorModeNotSupported(String),
    /// The operation is supported only in monitor mode (PCAP_ERROR_NOT_RFMON).
    OnlySupportedInMonitorMode,
    /// The process doesn't have permission to open the capture source
    /// (PCAP_ERROR_PERM_DENIED).
    PermissionDenied(String),
    /// The capture source device is not up (PCAP_ERROR_IFACE_NOT_UP).
    InterfaceNotUp(String),
    /// This device doesn't support setting the time stamp type
    /// (PCAP_ERROR_CANTSET_TSTAMP_TYPE).
    TimestampTypeNotSupported(String),
    /// The process has permission to open the capture source but doesn't have
    /// permission to put it into promiscuous mode
    /// (PCAP_ERROR_PROMISC_PERM_DENIED).
    PromiscuousPermissionDenied(String),
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
    CStringError(CStringError),
    /// IO error
    IO(io::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CStringError {
    Utf8(std::str::Utf8Error),
    Nul(std::ffi::NulError),
    FromBytesWithNul(std::ffi::FromBytesWithNulError),
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Break => write!(
                f,
                "libpcap: Loop terminated by pcap_breakloop (PCAP_ERROR_BREAK)."
            ),
            Error::NotActivated(interface) => {
                write!(
                    f,
                    "libpcap: Capture handle for interface {interface} needs to be activated (PCAP_ERROR_NOT_ACTIVATED)."
                )
            }
            Error::AlreadyActivated(interface) => {
                write!(
                    f,
                    "libpcap: Capture handle for interface {interface} is already activated (PCAP_ERROR_ACTIVATED)."
                )
            }
            Error::NoSuchDevice(interface) => {
                write!(
                    f,
                    "libpcap: Capture interface {interface} doesn't exist (PCAP_ERROR_NO_SUCH_DEVICE)."
                )
            }
            Error::MonitorModeNotSupported(interface) => {
                write!(
                    f,
                    "libpcap: Capture interface {interface} doesn't support monitor mode (PCAP_ERROR_RFMON_NOTSUP).",
                )
            }
            Error::OnlySupportedInMonitorMode => {
                write!(
                    f,
                    "libpcap: Operation is supported only in monitor mode (PCAP_ERROR_NOT_RFMON)."
                )
            }
            Error::PermissionDenied(interface) => {
                write!(
                    f,
                    "libpcap: Process doesn't have permission to open the capture interface {interface} (PCAP_ERROR_PERM_DENIED)."
                )
            }
            Error::InterfaceNotUp(interface) => {
                write!(
                    f,
                    "libpcap: Capture interface {interface} is not up (PCAP_ERROR_IFACE_NOT_UP)."
                )
            }
            Error::TimestampTypeNotSupported(interface) => {
                write!(
                    f,
                    "libpcap: Capture interface {interface} doesn't support setting the time stamp type (PCAP_ERROR_CANTSET_TSTAMP_TYPE)."
                )
            }
            Error::PromiscuousPermissionDenied(interface) => {
                write!(
                    f,
                    "libpcap: Process has permission to open the capture interface {interface} but doesn't have permission to put it into promiscuous mode (PCAP_ERROR_PROMISC_PERM_DENIED)."
                )
            }
            Error::TimestampPrecisionNotSupported => {
                write!(
                    f,
                    "libcap: Time stamp precision is not supported (PCAP_ERROR_TSTAMP_PRECISION_NOTSUP)."
                )
            }
            Error::PcapError(err) => write!(f, "libpcap error: {err}"),
            Error::PcapWarning(warn) => write!(f, "libpcap warning: {warn}"),
            Error::PcapErrorCode(code) => write!(f, "libpcap unknown error code: {code}"),

            Error::Timeout => write!(f, "timeout"),
            Error::CStringError(CStringError::FromBytesWithNul(err)) => err.fmt(f),
            Error::CStringError(CStringError::Nul(err)) => err.fmt(f),
            Error::CStringError(CStringError::Utf8(err)) => err.fmt(f),
            Error::IO(err) => err.fmt(f),
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Error::CStringError(CStringError::Utf8(err))
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Self {
        Error::CStringError(CStringError::Nul(err))
    }
}

impl From<std::ffi::FromBytesWithNulError> for Error {
    fn from(err: std::ffi::FromBytesWithNulError) -> Self {
        Error::CStringError(CStringError::FromBytesWithNul(err))
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        match err {
            Error::NoSuchDevice(interface) => {
                io::Error::new(io::ErrorKind::NotFound, format!("{interface} not found"))
            }
            Error::MonitorModeNotSupported(interface) => {
                io::Error::other(format!("interface {interface} doesn't support monitor mode"))
            }
            Error::PermissionDenied(interface) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("could not open {interface}, permission denied"),
            ),
            Error::InterfaceNotUp(interface) => {
                io::Error::other(format!("could not open {interface}, interface not up"))
            }
            Error::PromiscuousPermissionDenied(interface) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("could not set interface {interface} to promiscuous mode, permission denied",),
            ),
            err => io::Error::other(err.to_string()),
        }
    }
}
