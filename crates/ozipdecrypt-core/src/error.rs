use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OzipError {
    #[error("No valid encryption key found for {0}")]
    KeyNotFound(String),

    #[error("Checksum mismatch for \"{item}\": expected {expected}, calculated {calculated}")]
    ChecksumMismatch {
        item: String,
        expected: String,
        calculated: String,
    },

    #[error("Unsupported or unknown container format for {0}")]
    UnsupportedContainer(PathBuf),

    #[error("Truncated or corrupt container: {0}")]
    Truncated(String),

    #[error("Path traversal rejected for security: {0}")]
    PathRejected(String),

    #[error("Output file already exists: {0}")]
    FileExists(PathBuf),

    #[error("Extraction was cancelled by user")]
    Cancelled,

    #[error("Format error in {format}: {message}")]
    Format { format: String, message: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("XML parsing error: {0}")]
    Xml(#[from] quick_xml::Error),

    #[error("ZIP archive error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("TOML decode error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, OzipError>;
