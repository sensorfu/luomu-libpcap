use std::error;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Capture handle already activated
    AlreadyActivated,
    /// Invalid address
    InvalidAddress,
    /// Timeout happened (maybe during live capture)
    Timeout,
    /// No more packets available
    NoMorePackets,
    /// Error from Rust <-> C String conversion
    CStringError(Box<dyn error::Error>),
    /// Error from `libpcap`
    PcapError(String),
    /// Warning from `libpcap`
    PcapWarning(String),
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlreadyActivated => write!(f, "libpcap capture handler already activated"),
            Error::InvalidAddress => write!(f, "invalid address"),
            Error::Timeout => write!(f, "timeout"),
            Error::NoMorePackets => write!(f, "no more packets available"),
            Error::CStringError(err) => err.fmt(f),
            Error::PcapError(err) => write!(f, "libpcap error: {}", err),
            Error::PcapWarning(warn) => write!(f, "libpcap warning: {}", warn),
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
