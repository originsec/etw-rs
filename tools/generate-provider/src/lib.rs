//! Provider metadata queries and code generation for the generate-provider tool.

pub mod generate;
pub mod manifest;
pub mod mof;
pub mod release;

use etw::Error::Win32Error;

/// Tool-local error type.
#[derive(Debug)]
pub enum Error {
    /// Error from the etw-rs library (Win32, parse, etc.)
    Etw(etw::Error),
    /// COM / WMI error
    Com(windows::core::Error),
}

/// Tool-local result type.
pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Etw(e) => write!(f, "{e}"),
            Self::Com(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<etw::Error> for Error {
    fn from(e: etw::Error) -> Self {
        Self::Etw(e)
    }
}

impl From<windows::Win32::Foundation::WIN32_ERROR> for Error {
    fn from(e: windows::Win32::Foundation::WIN32_ERROR) -> Self {
        Self::Etw(Win32Error(e.0))
    }
}

impl From<windows::core::Error> for Error {
    fn from(e: windows::core::Error) -> Self {
        Self::Com(e)
    }
}
