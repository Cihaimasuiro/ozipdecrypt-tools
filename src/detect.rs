use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerType {
    Ozip,
    OfpQualcomm,
    OfpMediaTek,
    OnePlusOps,
    StandardZip,
    Unknown,
}

impl std::fmt::Display for ContainerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerType::Ozip => write!(f, "Oppo/Realme Encrypted OZIP"),
            ContainerType::OfpQualcomm => write!(f, "Qualcomm OFP Stock Firmware"),
            ContainerType::OfpMediaTek => write!(f, "MediaTek OFP Stock Firmware"),
            ContainerType::OnePlusOps => write!(f, "OnePlus OPS Unbrick Container"),
            ContainerType::StandardZip => write!(f, "Standard ZIP Archive (Unencrypted)"),
            ContainerType::Unknown => write!(f, "Unknown Container / Unsupported Format"),
        }
    }
}

pub struct ContainerInfo {
    pub container_type: ContainerType,
    pub file_size: u64,
    pub details: String,
}

pub fn detect_container(path: &Path) -> Result<ContainerType> {
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open file for detection: {}", path.display()))?;
    let file_size = file.metadata()?.len();

    if file_size < 128 {
        return Ok(ContainerType::Unknown);
    }

    // 1. Check for Standalone OZIP Header
    let mut head16 = [0u8; 16];
    file.seek(SeekFrom::Start(0))?;
    if file.read_exact(&mut head16).is_ok() && &head16[0..12] == b"OPPOENCRYPT!" {
        return Ok(ContainerType::Ozip);
    }

    // 2. Check for Standard ZIP / OZIP Mode 1 or 2
    if &head16[0..4] == b"PK\x03\x04" {
        // Inspect ZIP structure for OZIP markers
        if is_zip_ozip(&mut file)? {
            return Ok(ContainerType::Ozip);
        } else {
            return Ok(ContainerType::StandardZip);
        }
    }

    // 3. Check for OnePlus OPS Container
    if file_size > 0x200 {
        file.seek(SeekFrom::End(-0x200))?;
        let mut ops_tail = [0u8; 0x200];
        if file.read_exact(&mut ops_tail).is_ok() {
            let magic = u32::from_le_bytes(ops_tail[0x1fc..0x200].try_into().unwrap());
            if magic == 0x9EE3B5D1 || check_ops_manifest(&ops_tail) {
                return Ok(ContainerType::OnePlusOps);
            }
        }
    }

    // 4. Check for MediaTek OFP Container (Trailer at filesize - 0x6C)
    if file_size > 0x6C {
        file.seek(SeekFrom::End(-0x6C))?;
        let mut mtk_trailer = [0u8; 0x6C];
        if file.read_exact(&mut mtk_trailer).is_ok() {
            crate::ofp_mtk::mtk_shuffle(b"geyixue", &mut mtk_trailer);
            let magic = &mtk_trailer[0..4];
            if magic == b"MMM\0" || magic == b"MMM\x01" || magic == b"MMM\x02" || check_mtk_patterns(&mtk_trailer) {
                return Ok(ContainerType::OfpMediaTek);
            }
        }
    }

    // 5. Check for Qualcomm OFP Container
    for &page_size in &[0x1000u64, 0x200u64] {
        if file_size > page_size {
            file.seek(SeekFrom::End(-(page_size as i64)))?;
            let mut page = vec![0u8; page_size as usize];
            if file.read_exact(&mut page).is_ok() && page.len() >= 0x20 {
                let magic = u32::from_le_bytes(page[0x10..0x14].try_into().unwrap());
                if magic == 0x7CEF || magic == 0xCEF7 {
                    return Ok(ContainerType::OfpQualcomm);
                }
            }
        }
    }

    // Fallback based on file extension
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_lowercase();
        match ext_lower.as_str() {
            "ozip" => return Ok(ContainerType::Ozip),
            "ops" => return Ok(ContainerType::OnePlusOps),
            "ofp" => {
                // If extension is OFP, return Qualcomm by default as the primary family
                return Ok(ContainerType::OfpQualcomm);
            }
            "zip" => return Ok(ContainerType::StandardZip),
            _ => {}
        }
    }

    Ok(ContainerType::Unknown)
}

fn is_zip_ozip(file: &mut File) -> Result<bool> {
    file.seek(SeekFrom::Start(0))?;
    let mut zip = match zip::ZipArchive::new(file) {
        Ok(z) => z,
        Err(_) => return Ok(false),
    };

    if zip.by_name("oppo_metadata").is_ok() {
        return Ok(true);
    }

    for i in 0..zip.len() {
        if let Ok(mut zfile) = zip.by_index(i) {
            let mut header = [0u8; 12];
            if zfile.read_exact(&mut header).is_ok() && &header == b"OPPOENCRYPT!" {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn check_ops_manifest(trailer: &[u8]) -> bool {
    // Quick heuristic for OPS trailer
    let sbox = hex::decode(crate::ops::SBOX_HEX).unwrap_or_default();
    if sbox.is_empty() {
        return false;
    }
    // Attempt decrypting the length fields
    let xmllength = u32::from_le_bytes(trailer[0x14..0x18].try_into().unwrap_or_default()) as u64;
    xmllength > 100 && xmllength < 10_000_000
}

fn check_mtk_patterns(trailer: &[u8]) -> bool {
    // MediaTek trailer contains valid u16 partition count and ASCII metadata
    if trailer.len() < 0x6C {
        return false;
    }
    let count = u16::from_le_bytes(trailer[66..68].try_into().unwrap_or_default());
    count > 0 && count < 256
}

pub fn describe_container(path: &Path) -> Result<ContainerInfo> {
    let container_type = detect_container(path)?;
    let metadata = path.metadata()
        .with_context(|| format!("Failed to read metadata for {}", path.display()))?;
    let file_size = metadata.len();

    let details = match container_type {
        ContainerType::Ozip => {
            "Oppo/Realme recovery firmware encrypted with AES-128 (ECB/CBC chunked mode). Extractable to clean ZIP."
                .to_string()
        }
        ContainerType::OfpQualcomm => {
            "Qualcomm Snapdragon stock factory flash package with AES-128-CBC partition encryption and ProFile.xml manifest."
                .to_string()
        }
        ContainerType::OfpMediaTek => {
            "MediaTek Helio/Dimensity factory flash package with custom bitwise deobfuscation and 0x6C trailer."
                .to_string()
        }
        ContainerType::OnePlusOps => {
            "OnePlus unbrick container encrypted with proprietary CFB-128 stream cipher and S-Box expansion schedule."
                .to_string()
        }
        ContainerType::StandardZip => {
            "Standard unencrypted ZIP firmware package. Ready for recovery or fastboot/sideload installation."
                .to_string()
        }
        ContainerType::Unknown => {
            "Unrecognized firmware format or unsupported container."
                .to_string()
        }
    };

    Ok(ContainerInfo {
        container_type,
        file_size,
        details,
    })
}
