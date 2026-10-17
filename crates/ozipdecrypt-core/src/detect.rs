use crate::info::{ContainerInfo, PartitionMeta};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

pub fn detect_container(path: &Path) -> Result<ContainerType> {
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open file for detection: {}", path.display()))?;
    let file_size = file.metadata()?.len();

    if file_size < 128 {
        return Ok(ContainerType::Unknown);
    }

    // 1. Check for Standalone OZIP Header (OPPOENCRYPT! magic)
    let mut head16 = [0u8; 16];
    file.seek(SeekFrom::Start(0))?;
    if file.read_exact(&mut head16).is_ok() && &head16[0..12] == b"OPPOENCRYPT!" {
        return Ok(ContainerType::Ozip);
    }

    // 2. Check for Standard ZIP / OZIP Mode 1 or 2 (starts with PK\x03\x04)
    if &head16[0..4] == b"PK\x03\x04" {
        if is_zip_ozip(&mut file)? {
            return Ok(ContainerType::Ozip);
        } else {
            return Ok(ContainerType::StandardZip);
        }
    }

    // 3. Strict Check for Qualcomm OFP Container (Signature 0x7CEF / 0xCEF7 in trailer)
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

    // 4. Strict Check for MediaTek OFP Container (Trailer at filesize - 0x6C decrypted with 'geyixue')
    if file_size > 0x6C {
        file.seek(SeekFrom::End(-0x6C))?;
        let mut mtk_trailer = [0u8; 0x6C];
        if file.read_exact(&mut mtk_trailer).is_ok() {
            crate::ofp_mtk::mtk_shuffle(b"geyixue", &mut mtk_trailer);
            if check_mtk_patterns(&mtk_trailer) {
                return Ok(ContainerType::OfpMediaTek);
            }
        }
    }

    // 5. Strict Check for OnePlus OPS Container (Trailer at filesize - 0x200)
    if file_size > 0x200 {
        file.seek(SeekFrom::End(-0x200))?;
        let mut ops_tail = [0u8; 0x200];
        if file.read_exact(&mut ops_tail).is_ok() {
            let magic = u32::from_le_bytes(ops_tail[0x1fc..0x200].try_into().unwrap());
            if magic == 0x9EE3B5D1 || check_ops_manifest(&mut file, file_size, &ops_tail) {
                return Ok(ContainerType::OnePlusOps);
            }
        }
    }

    // 6. Fallback based on file extension
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_lowercase();
        match ext_lower.as_str() {
            "ozip" => return Ok(ContainerType::Ozip),
            "ops" => return Ok(ContainerType::OnePlusOps),
            "ofp" => {
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
    let mut zip = match zip::ZipArchive::new(std::io::BufReader::new(file)) {
        Ok(z) => z,
        Err(_) => return Ok(false),
    };

    // Mode 1 OZIP marker
    if zip.by_name("oppo_metadata").is_ok() {
        return Ok(true);
    }

    // Mode 2 OZIP marker
    if let Ok(mut boot) = zip.by_name("boot.img") {
        let mut header = [0u8; 12];
        if boot.read_exact(&mut header).is_ok() && &header == b"OPPOENCRYPT!" {
            return Ok(true);
        }
    }

    Ok(false)
}

#[allow(clippy::manual_is_multiple_of)]
fn check_ops_manifest(file: &mut File, file_size: u64, trailer: &[u8]) -> bool {
    let xmllength = u32::from_le_bytes(trailer[0x18..0x1C].try_into().unwrap_or_default()) as u64;
    if !(100..=10_000_000).contains(&xmllength) {
        return false;
    }
    let xmlpad = if xmllength % 0x200 != 0 {
        0x200 - (xmllength % 0x200)
    } else {
        0
    };
    if file_size < 0x200 + xmllength + xmlpad {
        return false;
    }

    let sbox = hex::decode(crate::ops::SBOX_HEX).unwrap_or_default();
    if sbox.is_empty() {
        return false;
    }

    let xml_offset = file_size - 0x200 - (xmllength + xmlpad);
    if file.seek(SeekFrom::Start(xml_offset)).is_err() {
        return false;
    }

    let mut enc16 = [0u8; 16];
    if file.read_exact(&mut enc16).is_err() {
        return false;
    }

    for mbox in &[&crate::ops::MBOX5, &crate::ops::MBOX6, &crate::ops::MBOX4] {
        let dec = crate::ops::key_custom_decrypt(&enc16, crate::ops::MASTER_KEY, *mbox, &sbox);
        if dec.windows(4).any(|w| w == b"<?xm" || w == b"xml ") {
            return true;
        }
    }

    false
}

fn check_mtk_patterns(trailer: &[u8]) -> bool {
    if trailer.len() < 0x6C {
        return false;
    }
    let count = u16::from_le_bytes(trailer[72..74].try_into().unwrap_or_default());
    if count == 0 || count > 256 {
        return false;
    }
    let name_bytes = &trailer[0..46];
    let valid_ascii = name_bytes
        .iter()
        .take_while(|&&b| b != 0)
        .all(|&b| b.is_ascii_graphic() || b == b' ');
    valid_ascii
}

pub fn describe_container(path: &Path) -> Result<ContainerInfo> {
    let container_type = detect_container(path)?;
    let metadata = path
        .metadata()
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

    let mut partitions = Vec::new();
    let mut chipset = None;

    if container_type == ContainerType::Ozip || container_type == ContainerType::StandardZip {
        if let Ok(file) = File::open(path) {
            if let Ok(mut archive) = zip::ZipArchive::new(std::io::BufReader::new(file)) {
                for i in 0..archive.len() {
                    if let Ok(entry) = archive.by_index(i) {
                        if !entry.is_dir() {
                            let name = entry.name().unwrap_or_default().to_string();
                            let size = entry.size();
                            partitions.push(PartitionMeta {
                                name,
                                size,
                                is_encrypted: container_type == ContainerType::Ozip,
                                checksum: None,
                            });
                        }
                    }
                }
            }
        }
    } else if container_type == ContainerType::OfpMediaTek && file_size > 0x6C {
        if let Ok(mut f) = File::open(path) {
            if f.seek(SeekFrom::Start(file_size - 0x6C)).is_ok() {
                let mut hdr = [0u8; 0x6C];
                if f.read_exact(&mut hdr).is_ok() {
                    crate::ofp_mtk::mtk_shuffle(b"geyixue", &mut hdr);
                    let prj = String::from_utf8_lossy(&hdr[0..46])
                        .trim_matches('\0')
                        .trim()
                        .to_string();
                    let cpu = String::from_utf8_lossy(&hdr[60..67])
                        .trim_matches('\0')
                        .trim()
                        .to_string();
                    if !cpu.is_empty() {
                        chipset = Some(if !prj.is_empty() {
                            format!("{} (Project: {})", cpu, prj)
                        } else {
                            cpu
                        });
                    }
                }
            }
        }
    }

    Ok(ContainerInfo {
        container_type,
        file_size,
        details,
        chipset,
        partitions,
    })
}
