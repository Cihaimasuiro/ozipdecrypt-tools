use crate::crypto::{derive_ofp_qc_key_iv, KeyConfig};
use aes::Aes128;
use anyhow::{bail, Context, Result};
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use md5::{Digest as Md5Digest, Md5};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

type Aes128Cfb = cfb_mode::Decryptor<Aes128>;

#[derive(Debug, Clone)]
pub struct OfpPartitionItem {
    pub filename: String,
    pub start: u64,
    pub length: u64,
    pub rlength: u64,
    pub sha256: String,
    pub md5: String,
    #[allow(dead_code)]
    pub parent_tag: String,
    pub decrypt_size: usize,
    pub is_copy_only: bool,
}

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

    // Check if the file is a password-protected ZIP container (Realme OFP variant)
    let mut header2 = [0u8; 2];
    if file.read_exact(&mut header2).is_ok() && &header2 == b"PK" {
        println!("[!] Password-protected ZIP container detected in Realme OFP archive.");
        return extract_realme_zip_ofp(ofp_path, out_dir, target_partition);
    }

    if keys.ofp_keysets.is_empty() {
        bail!("No OFP keysets available. Check keys.toml or internal defaults.");
    }

    let page_size = detect_page_size(&mut file, file_size)?;
    println!("[+] Detected OFP page size: {:#x} ({} bytes)", page_size, page_size);

    // Locate and decrypt XML manifest using key triplets
    let (matched_triplet, key, iv, xml_data) = find_and_decrypt_xml(&mut file, file_size, page_size, keys)?;
    println!("[+] Successfully matched OFP keyset: {}", matched_triplet.name);

    let xml_str = match String::from_utf8(xml_data.clone()) {
        Ok(s) => s,
        Err(_) => String::from_utf8_lossy(&xml_data).to_string(),
    };

    // Save decrypted ProFile.xml manifest
    let profile_path = out_dir.join("ProFile.xml");
    fs::write(&profile_path, &xml_data)
        .with_context(|| format!("Failed to write {}", profile_path.display()))?;
    println!("[+] Saved partition manifest to {}", profile_path.display());

    // Parse items from ProFile.xml
    let items = parse_profile_xml(&xml_str, page_size)?;
    println!("[+] Discovered {} partition/file items in ProFile.xml", items.len());

    let mut extracted_count = 0;
    for item in items {
        if let Some(target) = target_partition {
            let target_lower = target.to_lowercase();
            let fn_lower = item.filename.to_lowercase();
            if !fn_lower.contains(&target_lower) {
                continue;
            }
        }

        extract_single_item(&mut file, &item, out_dir, ofp_path, &key, &iv)?;
        extracted_count += 1;
    }

    if extracted_count == 0 {
        if let Some(target) = target_partition {
            bail!("No partition matching '{}' was found in ProFile.xml", target);
        } else {
            bail!("No extractable partitions found in ProFile.xml");
        }
    }

    println!(
        "\n[+] Extraction complete! Successfully processed {} partition(s) into: {}",
        extracted_count,
        out_dir.display()
    );
    Ok(())
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
    // Fallback default
    Ok(0x200)
}

fn find_and_decrypt_xml(
    file: &mut File,
    file_size: u64,
    page_size: u64,
    keys: &KeyConfig,
) -> Result<(crate::crypto::OfpKeyTriplet, [u8; 16], [u8; 16], Vec<u8>)> {
    let xml_trailer_offset = file_size.saturating_sub(page_size);
    file.seek(SeekFrom::Start(xml_trailer_offset + 0x14))?;

    let mut buf8 = [0u8; 8];
    file.read_exact(&mut buf8)?;
    let offset_pages = u32::from_le_bytes(buf8[0..4].try_into().unwrap()) as u64;
    let mut length = u32::from_le_bytes(buf8[4..8].try_into().unwrap()) as u64;
    let data_offset = offset_pages * page_size;

    if length < 200 {
        // A57 length calculation hack from ofp_qc_decrypt.py
        length = xml_trailer_offset.saturating_sub(data_offset).saturating_sub(0x57);
    }

    if data_offset + length > file_size {
        bail!(
            "Invalid OFP manifest offset/length in trailer: offset={:#x}, length={:#x}, file_size={:#x}",
            data_offset,
            length,
            file_size
        );
    }

    file.seek(SeekFrom::Start(data_offset))?;
    let mut encrypted_payload = vec![0u8; length as usize];
    file.read_exact(&mut encrypted_payload)?;

    for triplet in &keys.ofp_keysets {
        let (key, iv) = derive_ofp_qc_key_iv(triplet)?;
        let mut candidate = encrypted_payload.clone();
        let cipher = Aes128Cfb::new(&key.into(), &iv.into());
        cipher.decrypt(&mut candidate);

        if let Some(xml_start) = candidate.windows(5).position(|w| w == b"<?xml") {
            let xml_slice = &candidate[xml_start..];
            let end = match xml_slice.iter().rposition(|&b| b == b'>') {
                Some(pos) => pos + 1,
                None => xml_slice.len(),
            };
            return Ok((triplet.clone(), key, iv, xml_slice[..end].to_vec()));
        }
    }

    bail!("Failed to decrypt OFP XML manifest with any configured key triplet.")
}

pub fn parse_profile_xml(xml_content: &str, page_size: u64) -> Result<Vec<OfpPartitionItem>> {
    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);

    let mut items = Vec::new();
    let mut tag_stack: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let parent_tag = tag_stack.last().cloned().unwrap_or_default();
                if let Some(item) = parse_element_item(&reader, &e, &parent_tag, page_size)? {
                    items.push(item);
                }
                tag_stack.push(tag_name);
            }
            Ok(Event::Empty(e)) => {
                let parent_tag = tag_stack.last().cloned().unwrap_or_default();
                if let Some(item) = parse_element_item(&reader, &e, &parent_tag, page_size)? {
                    items.push(item);
                }
            }
            Ok(Event::End(_)) => {
                tag_stack.pop();
            }
            Ok(Event::Eof) => break,
            Err(_) => {
                // If XML has trailing garbage after </data>, stop gracefully
                break;
            }
            _ => (),
        }
    }

    Ok(items)
}

fn parse_element_item(
    reader: &Reader<&[u8]>,
    e: &quick_xml::events::BytesStart,
    parent_tag: &str,
    page_size: u64,
) -> Result<Option<OfpPartitionItem>> {
    let mut attribs = HashMap::new();
    for attr in e.attributes() {
        let a = attr?;
        let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
        let val = a.decode_and_unescape_value(reader.decoder())?.to_string();
        attribs.insert(key, val);
    }

    let filename = if let Some(p) = attribs.get("Path") {
        p.clone()
    } else if let Some(f) = attribs.get("filename") {
        f.clone()
    } else {
        return Ok(None);
    };

    if filename.trim().is_empty() {
        return Ok(None);
    }

    let mut start: i64 = -1;
    if let Some(off_str) = attribs.get("FileOffsetInSrc") {
        if let Ok(sectors) = off_str.parse::<u64>() {
            start = (sectors * page_size) as i64;
        }
    } else if let Some(sec_str) = attribs.get("SizeInSectorInSrc") {
        if let Ok(sectors) = sec_str.parse::<u64>() {
            start = (sectors * page_size) as i64;
        }
    }

    if start < 0 {
        return Ok(None);
    }

    let rlength: u64 = attribs
        .get("SizeInByteInSrc")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let length: u64 = attribs
        .get("SizeInSectorInSrc")
        .and_then(|s| s.parse::<u64>().ok())
        .map(|sectors| sectors * page_size)
        .unwrap_or(rlength);

    let sha256 = attribs.get("sha256").cloned().unwrap_or_default();
    let md5 = attribs.get("md5").cloned().unwrap_or_default();

    let mut decrypt_size = 0x40000usize;
    if parent_tag == "Sahara" {
        decrypt_size = rlength as usize;
    }

    let copy_only_tags = ["DigestsToSign", "ChainedTableOfDigests", "Firmware"];
    let is_copy_only = copy_only_tags.contains(&parent_tag);

    let mut effective_length = length;
    if ["Config", "Provision", "ChainedTableOfDigests", "DigestsToSign", "Firmware"].contains(&parent_tag) {
        effective_length = rlength;
    }

    Ok(Some(OfpPartitionItem {
        filename,
        start: start as u64,
        length: effective_length,
        rlength,
        sha256,
        md5,
        parent_tag: parent_tag.to_string(),
        decrypt_size,
        is_copy_only,
    }))
}

fn copy_stream<R: Read, W: Write>(reader: &mut R, writer: &mut W, mut length: u64) -> Result<()> {
    let mut buf = [0u8; 64 * 1024];
    while length > 0 {
        let to_read = std::cmp::min(length, buf.len() as u64) as usize;
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        length -= n as u64;
    }
    Ok(())
}

fn extract_single_item(
    src_file: &mut File,
    item: &OfpPartitionItem,
    out_dir: &Path,
    _ofp_path: &Path,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Result<()> {
    let target_path = crate::crypto::safe_join(out_dir, &item.filename)?;

    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let rlength = item.rlength;
    if rlength == 0 {
        return Ok(());
    }

    println!("[*] Extracting: {} ({} bytes)", item.filename, rlength);

    src_file.seek(SeekFrom::Start(item.start))?;

    if item.is_copy_only {
        // Unencrypted copy
        let mut out = File::create(&target_path)?;
        copy_stream(src_file, &mut out, item.length)?;
        verify_checksums(&target_path, &item.sha256, &item.md5, true)?;
    } else {
        // Encrypted partition: decrypt header with AES-128-CFB, copy remaining payload
        let mut out = File::create(&target_path)?;
        let decrypt_len = std::cmp::min(item.decrypt_size, rlength as usize);

        let mut enc_head = vec![0u8; decrypt_len];
        src_file.read_exact(&mut enc_head)?;

        // AES-CFB requires 4-byte padding on decrypt blocks if size % 4 != 0
        let padded_len = if decrypt_len % 4 != 0 {
            decrypt_len + (4 - (decrypt_len % 4))
        } else {
            decrypt_len
        };
        let mut pad_buf = enc_head.clone();
        pad_buf.resize(padded_len, 0u8);

        let cipher = Aes128Cfb::new(key.into(), iv.into());
        cipher.decrypt(&mut pad_buf);

        out.write_all(&pad_buf[..decrypt_len])?;

        // Copy remaining plain partition content
        if rlength as usize > decrypt_len {
            let remain = rlength - (decrypt_len as u64);
            copy_stream(src_file, &mut out, remain)?;
        }

        out.flush()?;
        verify_checksums(&target_path, &item.sha256, &item.md5, false)?;
    }

    Ok(())
}

fn verify_checksums(file_path: &Path, sha256_sum: &str, md5_sum: &str, is_copy: bool) -> Result<()> {
    let mode_str = if is_copy { "Copy" } else { "Decrypt" };
    let mut f = File::open(file_path)?;
    let metadata_len = f.metadata()?.len();

    let mut md5_verified = true;
    if !md5_sum.is_empty() {
        let check_len = std::cmp::min(0x40000, metadata_len) as usize;
        let mut head_buf = vec![0u8; check_len];
        f.read_exact(&mut head_buf)?;
        let computed_md5 = format!("{:x}", Md5::digest(&head_buf));
        if !computed_md5.eq_ignore_ascii_case(md5_sum) {
            md5_verified = false;
        }
    }

    let mut sha256_verified = true;
    if !sha256_sum.is_empty() {
        let mut matches = false;
        // Test SHA256 of first 0x40000 bytes OR total file length (matches Kerler's verification)
        for &limit in &[Some(0x40000u64), None] {
            f.seek(SeekFrom::Start(0))?;
            let mut hasher = Sha256::new();
            match limit {
                Some(max_bytes) => {
                    let mut remain = max_bytes;
                    let mut buf = [0u8; 8192];
                    while remain > 0 {
                        let to_read = std::cmp::min(remain, buf.len() as u64) as usize;
                        let n = f.read(&mut buf[..to_read])?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                        remain -= n as u64;
                    }
                }
                None => {
                    let mut buf = [0u8; 8192];
                    while let Ok(n) = f.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                    }
                }
            }
            let digest_str = format!("{:x}", hasher.finalize());
            if digest_str.eq_ignore_ascii_case(sha256_sum) {
                matches = true;
                break;
            }
        }
        if !matches {
            sha256_verified = false;
        }
    }


    if !md5_verified || !sha256_verified {
        bail!(
            "{}: Checksum verification failed! (md5_ok: {}, sha256_ok: {})",
            mode_str, md5_verified, sha256_verified
        );
    } else {
        println!("  [+] {}: Verified checksums successfully.", mode_str);
    }

    Ok(())
}

fn extract_realme_zip_ofp(ofp_path: &Path, out_dir: &Path, target_partition: Option<&str>) -> Result<()> {
    let zippw = b"flash@realme$50E7F7D847732396F1582CD62DD385ED7ABB0897";
    println!("[*] Extracting password-protected Realme OFP archive...");
    let file = File::open(ofp_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut count = 0;

    for i in 0..archive.len() {
        let mut zfile = match archive.by_index_decrypt(i, zippw) {
            Ok(f) => f,
            Err(e) => bail!("Failed to read/decrypt Realme ZIP entry {}: {}", i, e),
        };
        let raw_name = zfile.name()?.to_string();
        if raw_name.ends_with('/') {
            continue;
        }

        if let Some(target) = target_partition {
            let target_lower = target.to_lowercase();
            if !raw_name.to_lowercase().contains(&target_lower) {
                continue;
            }
        }

        let out_file_path = crate::crypto::safe_join(out_dir, &raw_name)?;
        if let Some(parent) = out_file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        println!("[*] Extracting \"{}\" to {}...", raw_name, out_file_path.display());
        let mut out = File::create(&out_file_path)?;
        std::io::copy(&mut zfile, &mut out)?;
        count += 1;
    }

    if count == 0 {
        if let Some(target) = target_partition {
            bail!("No partition matching '{}' found in Realme ZIP archive.", target);
        } else {
            bail!("No files extracted from Realme ZIP archive.");
        }
    }

    println!("[+] Successfully extracted {} file(s) from Realme OFP ZIP.", count);
    Ok(())
}
