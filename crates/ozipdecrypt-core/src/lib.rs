//! # ozipdecrypt-core
//!
//! A pure-Rust, high-performance cryptographic and container-extraction library
//! for decrypting Oppo, Realme, and OnePlus proprietary firmware packages.
//!
//! ## Supported Formats
//!
//! - **Oppo / Realme `.ozip`**: Decrypts both Standalone (AES-128-ECB/CBC chunked)
//!   and Zip-wrapped Mode 1 / Mode 2 OTA recovery archives. Supports selective partition
//!   extraction (e.g. modem, boot) without unpacking entire multi-gigabyte archives.
//! - **Qualcomm Snapdragon `.ofp`**: Decrypts factory flash packages using AES-128-CFB
//!   key triplets, XML partition parsing (`ProFile.xml`), and sha256 integrity verification.
//! - **MediaTek `.ofp`**: Decrypts factory packages using keytables, custom byte shuffling,
//!   and 0x6C trailer metadata extraction.
//! - **OnePlus `.ops`**: Decrypts emergency unbrick containers using the proprietary
//!   CFB-128 stream cipher, S-box expansion schedules, and custom MBox round-keys.
//!
//! ## Quick Example
//!
//! ```no_run
//! use std::path::Path;
//! use ozipdecrypt_core::{detect, ozip, crypto::KeyConfig};
//!
//! fn main() -> anyhow::Result<()> {
//!     let file = Path::new("firmware.ozip");
//!     let container_type = detect::detect_container(file)?;
//!     println!("Detected container: {}", container_type);
//!
//!     let keys = KeyConfig::default();
//!     // Selectively extract modem partition in seconds:
//!     ozip::extract_ozip_partition(file, Path::new("./extracted"), "modem", &keys)?;
//!     Ok(())
//! }
//! ```

pub mod crypto;
pub mod detect;
pub mod error;
pub mod extract;
pub mod info;
pub mod ofp;
pub mod ofp_mtk;
pub mod ops;
pub mod ozip;
pub mod reporter;

pub use crypto::KeyConfig;
pub use detect::{
    describe_container, describe_container_with_keys, detect_container, ContainerType,
};
pub use error::{OzipError, Result};
pub use extract::{extract, ExtractItemSummary, ExtractRequest, ExtractSummary};
pub use info::{ContainerInfo, PartitionMeta, VerificationLevel};
pub use reporter::{ChecksumStatus, NoopReporter, ProgressEvent, ProgressReporter};
