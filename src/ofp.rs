use crate::crypto::{derive_ofp_qc_key_iv, KeyConfig};
use aes::Aes128;
use anyhow::{bail, Context, Result};
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

type Aes128Cfb = cfb_mode::Decryptor<Aes128>;

pub fn extract_ofp_partition(
    ofp_path: &Path,
    out_dir: &Path,
    target_partition: Option<&str>,
    keys: &KeyConfig,
) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    let mut file = File::open(ofp_path)
        .with_context(|| format!("Failed to open OFP file: {}", ofp_path.display()))?;
    let file_size = file.metadata()?.len();

    if keys.ofp_keysets.is_empty() {
        bail!(
            "No OFP keysets defined in keys.toml.\n\
             Please add an [[ofp_keysets]] entry with (mc, userkey, ivec) to keys.toml."
        );
    }

    // Qualcomm OFP files store trailer metadata near the end of the file (page size 0x200 or 0x1000)
    let page_size = detect_page_size(&mut file, file_size)?;
    println!("[+] Detected OFP page size: {:#x}", page_size);

    // Locate XML offset & length from the trailer
    let xml_offset = file_size.saturating_sub(page_size * 2);
    file.seek(SeekFrom::Start(xml_offset))?;
    let mut encrypted_xml = vec![0u8; page_size as usize];
    file.read_exact(&mut encrypted_xml)?;

    // Test configured key triplets until decrypted payload starts with "<?xml"
    for triplet in &keys.ofp_keysets {
        let (key, iv) = derive_ofp_qc_key_iv(triplet)?;
        let mut candidate = encrypted_xml.clone();
        let cipher = Aes128Cfb::new(&key.into(), &iv.into());
        cipher.decrypt(&mut candidate);

        if candidate.starts_with(b"<?xml") {
            println!("[+] Matched OFP Keyset: {}", triplet.name);
            let xml_path = out_dir.join("ProFile.xml");
            let mut xml_out = File::create(&xml_path)?;
            xml_out.write_all(&candidate)?;
            println!("[+] Saved decrypted partition manifest to {}", xml_path.display());

            if let Some(part_name) = target_partition {
                println!(
                    "[*] Ready to extract target partition '{}' using manifest offsets.",
                    part_name
                );
            }
            return Ok(());
        }
    }

    bail!("Could not decrypt OFP XML manifest with any key triplet in keys.toml.")
}

fn detect_page_size(file: &mut File, file_size: u64) -> Result<u64> {
    for &candidate in &[0x200u64, 0x1000u64] {
        if file_size > candidate {
            file.seek(SeekFrom::Start(file_size - candidate + 0x10))?;
            let mut magic_buf = [0u8; 4];
            file.read_exact(&mut magic_buf)?;
            if u32::from_le_bytes(magic_buf) == 0x7CEF {
                return Ok(candidate);
            }
        }
    }
    Ok(0x200)
}
