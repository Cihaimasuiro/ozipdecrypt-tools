use crate::crypto::{decrypt_block, decrypt_blocks, keytest, KeyConfig};
use aes::cipher::KeyInit;
use aes::Aes128;
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

const OZIP_MAGIC: &[u8; 12] = b"OPPOENCRYPT!";

pub fn read_full<R: Read>(reader: &mut R, mut buf: &mut [u8]) -> io::Result<usize> {
    let total = buf.len();
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => break,
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total - buf.len())
}

pub fn decrypt_ozip(input_path: &Path, output_path: &Path, keys: &KeyConfig) -> Result<()> {
    if input_path == output_path {
        bail!(
            "Input and output paths are identical ({}). Refusing to run to prevent destroying input archive.",
            input_path.display()
        );
    }
    if let (Ok(in_c), Ok(out_c)) = (input_path.canonicalize(), output_path.canonicalize()) {
        if in_c == out_c {
            bail!(
                "Input and output paths resolve to the same file ({}). Refusing to run to prevent destroying input archive.",
                input_path.display()
            );
        }
    }

    println!("[*] Opening OZIP archive: {}", input_path.display());
    let mut file = File::open(input_path)
        .with_context(|| format!("Unable to open {}", input_path.display()))?;

    let mut magic = [0u8; 12];
    file.read_exact(&mut magic)
        .context("Input file is too short to be a valid OZIP archive.")?;

    let is_zip = if &magic == OZIP_MAGIC {
        false
    } else if &magic[0..2] == b"PK" {
        true
    } else {
        bail!("Unknown magic header in OZIP: expected 'OPPOENCRYPT!' or 'PK'.");
    };

    let tmp_output = output_path.with_file_name(format!(
        "{}.part",
        output_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("output")
    ));

    let run_res = if !is_zip {
        // Standalone OZIP mode
        file.seek(SeekFrom::Start(0x1050))?;
        let mut sample_block = [0u8; 16];
        file.read_exact(&mut sample_block)?;

        let matched_key = keytest(&sample_block, &keys.ozip_keys)
            .context("No matching AES key found for standalone OZIP file.")?;

        let cipher = Aes128::new_from_slice(&matched_key)
            .map_err(|e| anyhow::anyhow!("Failed to initialize AES cipher: {}", e))?;

        let out_file = File::create(&tmp_output).with_context(|| {
            format!("Unable to create temporary file: {}", tmp_output.display())
        })?;
        let mut wf = BufWriter::new(out_file);
        let mut fr = BufReader::new(file);

        fr.seek(SeekFrom::Start(0x1050))?;
        println!("[*] Streaming decryption to {}...", output_path.display());

        let mut block = [0u8; 16];
        let mut plain = [0u8; 0x4000];

        loop {
            let n = read_full(&mut fr, &mut block)?;
            if n == 0 {
                break;
            }
            if n == 16 {
                decrypt_block(&cipher, &mut block);
            }
            wf.write_all(&block[..n])?;

            let n = read_full(&mut fr, &mut plain)?;
            if n == 0 {
                break;
            }
            wf.write_all(&plain[..n])?;
        }

        wf.flush()?;
        Ok(())
    } else {
        // Zip container mode
        let mut archive = match ZipArchive::new(BufReader::new(file)) {
            Ok(a) => a,
            Err(_) => {
                decrypt_mode2(input_path, &tmp_output, keys)?;
                if tmp_output.exists() {
                    fs::rename(&tmp_output, output_path)?;
                }
                println!(
                    "[+] DONE! Successfully decrypted Mode 2 OZIP to {}",
                    output_path.display()
                );
                return Ok(());
            }
        };

        let mut clist = HashSet::new();
        let has_oppo_metadata = match archive.by_name("oppo_metadata") {
            Ok(mut meta_entry) => {
                let mut content = String::new();
                if meta_entry.read_to_string(&mut content).is_ok() {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            clist.insert(trimmed.to_string());
                        }
                    }
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        };

        if !has_oppo_metadata {
            println!("[*] No oppo_metadata detected, attempting Zip Mode 2 (CPH1803/CPH1901)...");
            decrypt_mode2(input_path, &tmp_output, keys)?;
            if tmp_output.exists() {
                fs::rename(&tmp_output, output_path)?;
            }
            println!(
                "[+] DONE! Successfully decrypted Mode 2 OZIP to {}",
                output_path.display()
            );
            return Ok(());
        }

        // Find vbmeta.img for key testing
        let mut fname = String::new();
        if clist.contains("firmware-update/vbmeta.img") {
            fname = "firmware-update/vbmeta.img".to_string();
        } else if clist.contains("vbmeta.img") {
            fname = "vbmeta.img".to_string();
        } else if archive.by_name("firmware-update/vbmeta.img").is_ok() {
            fname = "firmware-update/vbmeta.img".to_string();
        } else if archive.by_name("vbmeta.img").is_ok() {
            fname = "vbmeta.img".to_string();
        }

        if fname.is_empty() {
            bail!("Could not locate vbmeta.img to identify AES key in Mode 1 archive.");
        }

        let key = {
            let mut vbmeta = archive.by_name(&fname)?;
            io::copy(&mut (&mut vbmeta).take(0x1050), &mut io::sink())?;
            let mut data = [0u8; 16];
            let n = read_full(&mut vbmeta, &mut data)?;
            if n < 16 {
                bail!("vbmeta.img is too short for AES key verification.");
            }
            keytest(&data, &keys.ozip_keys).context("Unknown AES key for Zip Mode 1 archive.")?
        };

        let out_file = File::create(&tmp_output)
            .with_context(|| format!("Unable to create output file: {}", tmp_output.display()))?;
        let mut writer = ZipWriter::new(BufWriter::new(out_file));
        let decrypt_options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::DEFLATE)
            .large_file(true);
        let pass_options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .large_file(true);

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let orgfilename = entry.name()?.to_string();
            println!("[*] Extracting {}", orgfilename);

            if entry.is_dir() {
                writer.add_directory(&orgfilename, pass_options)?;
                continue;
            }

            let file_size = entry.size();
            if !clist.is_empty() {
                if clist.contains(&orgfilename) {
                    println!("[+] Decrypting {}", orgfilename);
                    writer.start_file(&orgfilename, decrypt_options)?;
                    decrypt_file_v1(&key, None, &mut entry, file_size, &mut writer)?;
                } else {
                    writer.start_file(&orgfilename, pass_options)?;
                    io::copy(&mut entry, &mut writer)?;
                }
            } else {
                let mut magic = [0u8; 12];
                let n = read_full(&mut entry, &mut magic)?;
                if n == 12 && &magic == OZIP_MAGIC {
                    println!("[+] Decrypting {}", orgfilename);
                    writer.start_file(&orgfilename, decrypt_options)?;
                    decrypt_file_v1(&key, Some(&magic), &mut entry, file_size, &mut writer)?;
                } else {
                    writer.start_file(&orgfilename, pass_options)?;
                    if n > 0 {
                        writer.write_all(&magic[..n])?;
                    }
                    io::copy(&mut entry, &mut writer)?;
                }
            }
        }

        writer.finish()?;
        Ok(())
    };

    match run_res {
        Ok(()) => {
            if tmp_output.exists() {
                fs::rename(&tmp_output, output_path).with_context(|| {
                    format!(
                        "Failed to move {} to {}",
                        tmp_output.display(),
                        output_path.display()
                    )
                })?;
            }
            println!(
                "[+] DONE! Successfully decrypted OZIP to {}",
                output_path.display()
            );
            Ok(())
        }
        Err(e) => {
            if tmp_output.exists() {
                let _ = fs::remove_file(&tmp_output);
            }
            Err(e)
        }
    }
}

pub fn decrypt_file_v1<R: Read, W: Write>(
    key: &[u8; 16],
    initial_magic: Option<&[u8; 12]>,
    reader: &mut R,
    file_size: u64,
    writer: &mut W,
) -> Result<()> {
    let cipher = Aes128::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to initialize AES cipher: {}", e))?;

    if initial_magic.is_some() {
        let mut pad = [0u8; 4];
        read_full(reader, &mut pad)?;
    } else {
        let mut header = [0u8; 16];
        read_full(reader, &mut header)?;
    }

    let mut dsize_buf = [0u8; 16];
    read_full(reader, &mut dsize_buf)?;
    let dsize_str = String::from_utf8_lossy(&dsize_buf);
    let mut dsize: u64 = dsize_str.trim_matches('\0').trim().parse().unwrap_or(0);

    // Skip (0x1050 - 0x20 = 4144) bytes
    io::copy(&mut reader.by_ref().take(4144), &mut io::sink())?;

    let mut flen = file_size.saturating_sub(0x1050);
    let mut buf = [0u8; 0x4000];

    while dsize > 0 {
        let size = std::cmp::min(flen, 0x4000) as usize;
        if size == 0 {
            break;
        }
        let n = read_full(reader, &mut buf[..size])?;
        if n == 0 {
            break;
        }
        decrypt_blocks(&cipher, &mut buf[..n]);
        let write_size = std::cmp::min(dsize as usize, n);
        writer.write_all(&buf[..write_size])?;
        flen = flen.saturating_sub(size as u64);
        dsize = dsize.saturating_sub(write_size as u64);
    }

    Ok(())
}

pub fn decrypt_mode2(input_path: &Path, output_path: &Path, keys: &KeyConfig) -> Result<()> {
    println!(
        "[*] Finding key for Mode 2 archive: {}",
        input_path.display()
    );
    let file = File::open(input_path)?;
    let mut archive = ZipArchive::new(BufReader::new(file))?;

    let mut key: Option<[u8; 16]> = None;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name()?.to_string();
        if name.contains("boot.img") {
            let mut magic = [0u8; 12];
            let n = read_full(&mut entry, &mut magic)?;
            if n == 12 && &magic == OZIP_MAGIC {
                io::copy(&mut (&mut entry).take(68), &mut io::sink())?;
                let mut data = [0u8; 16];
                let n = read_full(&mut entry, &mut data)?;
                if n == 16 {
                    if let Some(k) = keytest(&data, &keys.ozip_keys) {
                        key = Some(k);
                        break;
                    }
                }
            } else {
                bail!("Unknown Mode 2: boot.img was not encrypted.");
            }
        }
    }

    let key = key.context("No matching AES key found for Mode 2 archive.")?;
    println!("[*] Extracting and decrypting Mode 2 archive...");

    let out_file = File::create(output_path)?;
    let mut writer = ZipWriter::new(BufWriter::new(out_file));
    let decrypt_options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::DEFLATE)
        .large_file(true);
    let pass_options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true);

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let orgfilename = entry.name()?.to_string();

        if entry.is_dir() {
            writer.add_directory(&orgfilename, pass_options)?;
            continue;
        }

        let mut magic = [0u8; 12];
        let n = read_full(&mut entry, &mut magic)?;
        if n == 12 && &magic == OZIP_MAGIC {
            println!("[+] Decrypting {}", orgfilename);
            writer.start_file(&orgfilename, decrypt_options)?;
            if !decrypt_file_v2(&key, Some(&magic), &mut entry, &mut writer)? {
                bail!("Failed to decrypt chunk in {}", orgfilename);
            }
        } else {
            writer.start_file(&orgfilename, pass_options)?;
            if n > 0 {
                writer.write_all(&magic[..n])?;
            }
            io::copy(&mut entry, &mut writer)?;
        }
    }

    writer.finish()?;
    println!(
        "[+] DONE! Successfully decrypted Mode 2 OZIP to {}",
        output_path.display()
    );
    Ok(())
}

pub fn decrypt_file_v2<R: Read, W: Write>(
    key: &[u8; 16],
    initial_header: Option<&[u8; 12]>,
    reader: &mut R,
    writer: &mut W,
) -> Result<bool> {
    let cipher = Aes128::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to initialize AES cipher: {}", e))?;
    let mut is_first_block = true;
    let mut goon = true;
    let mut header_buf = [0u8; 12];
    let mut skip_buf = [0u8; 48];
    let mut block16 = [0u8; 16];
    let mut plain_buf = [0u8; 0x3FF0];

    while goon {
        let header = if is_first_block {
            is_first_block = false;
            if let Some(h) = initial_header {
                h
            } else {
                let n = read_full(reader, &mut header_buf)?;
                if n == 0 {
                    break;
                }
                if n < 12 {
                    return Ok(false);
                }
                &header_buf
            }
        } else {
            let n = read_full(reader, &mut header_buf)?;
            if n == 0 {
                break;
            }
            if n < 12 {
                return Ok(false);
            }
            &header_buf
        };

        if header != OZIP_MAGIC {
            return Ok(false);
        }

        let n = read_full(reader, &mut skip_buf[..4])?;
        if n < 4 {
            return Ok(false);
        }

        let mut bdsize_buf = [0u8; 16];
        let n = read_full(reader, &mut bdsize_buf)?;
        if n < 16 {
            return Ok(false);
        }
        let bdsize_str = String::from_utf8_lossy(&bdsize_buf);
        let bdsize_clean = bdsize_str.trim_matches('\0').trim();
        let mut bdsize: u64 = bdsize_clean.parse().unwrap_or(0);

        if bdsize < 0x40000 {
            goon = false;
        }

        let n = read_full(reader, &mut skip_buf[..48])?;
        if n < 48 {
            return Ok(false);
        }

        while bdsize > 0 {
            let n1 = read_full(reader, &mut block16)?;
            if n1 == 0 {
                break;
            }
            let size = if bdsize < 0x10 { bdsize as usize } else { 0x10 };
            let write_size = std::cmp::min(n1, size);
            if n1 == 16 {
                decrypt_block(&cipher, &mut block16);
            }
            writer.write_all(&block16[..write_size])?;
            bdsize = bdsize.saturating_sub(0x10);

            let n2 = read_full(reader, &mut plain_buf)?;
            if n2 == 0 {
                break;
            }
            bdsize = bdsize.saturating_sub(0x3FF0);
            writer.write_all(&plain_buf[..n2])?;
        }
    }

    Ok(true)
}

/// Selectively extract one or more partitions from an OZIP archive without repacking the entire ZIP.
///
/// If target_partition is "modem", it automatically matches "NON-HLOS.bin" or any entry containing "modem".
/// If target_partition is "wifi" or "wlan", it automatically matches "NON-HLOS.bin" or any WLAN entry.
pub fn extract_ozip_partition(
    input_path: &Path,
    out_dir: &Path,
    target_partition: &str,
    keys: &KeyConfig,
) -> Result<Vec<std::path::PathBuf>> {
    fs::create_dir_all(out_dir)?;
    let mut file = File::open(input_path)
        .with_context(|| format!("Unable to open {}", input_path.display()))?;

    let mut magic = [0u8; 12];
    file.read_exact(&mut magic)
        .context("Input file is too short to be a valid OZIP archive.")?;

    if &magic == OZIP_MAGIC {
        bail!("Standalone single-file OZIP does not support selective partition extraction; please decrypt the full container.");
    }
    if &magic[0..2] != b"PK" {
        bail!("Unknown magic header in OZIP: expected 'OPPOENCRYPT!' or 'PK'.");
    }

    file.seek(SeekFrom::Start(0))?;
    let mut archive = ZipArchive::new(BufReader::new(file))?;

    let target_lower = target_partition.to_lowercase();
    let matches_target = |entry_name: &str| -> bool {
        let name_lower = entry_name.to_lowercase();
        if target_lower == "modem" {
            name_lower.contains("modem") || name_lower.contains("non-hlos")
        } else if target_lower == "wifi" || target_lower == "wlan" {
            name_lower.contains("non-hlos")
                || name_lower.contains("wlan")
                || name_lower.contains("wifi")
        } else {
            name_lower.contains(&target_lower)
        }
    };

    let mut clist = HashSet::new();
    let has_oppo_metadata = match archive.by_name("oppo_metadata") {
        Ok(mut meta_entry) => {
            let mut content = String::new();
            if meta_entry.read_to_string(&mut content).is_ok() {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        clist.insert(trimmed.to_string());
                    }
                }
                true
            } else {
                false
            }
        }
        Err(_) => false,
    };

    let mut extracted = Vec::new();

    if !has_oppo_metadata {
        // Mode 2 extraction
        println!(
            "[*] Extracting partition '{}' from Mode 2 OZIP archive...",
            target_partition
        );
        let mut key: Option<[u8; 16]> = None;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let name = entry.name()?.to_string();
            if name.contains("boot.img") {
                let mut m = [0u8; 12];
                let n = read_full(&mut entry, &mut m)?;
                if n == 12 && &m == OZIP_MAGIC {
                    io::copy(&mut (&mut entry).take(68), &mut io::sink())?;
                    let mut data = [0u8; 16];
                    let n = read_full(&mut entry, &mut data)?;
                    if n == 16 {
                        if let Some(k) = keytest(&data, &keys.ozip_keys) {
                            key = Some(k);
                            break;
                        }
                    }
                }
            }
        }
        let key = key.context("No matching AES key found for Mode 2 archive.")?;
        println!("[+] Matched AES decryption key for Mode 2 archive.");

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            if entry.is_dir() {
                continue;
            }
            let orgfilename = entry.name()?.to_string();
            if !matches_target(&orgfilename) {
                continue;
            }

            let file_name = Path::new(&orgfilename).file_name().unwrap();
            let dest_path = out_dir.join(file_name);
            println!("[*] Extracting: {} -> {}", orgfilename, dest_path.display());

            let mut out = File::create(&dest_path)?;
            let mut m = [0u8; 12];
            let n = read_full(&mut entry, &mut m)?;
            if n == 12 && &m == OZIP_MAGIC {
                if !decrypt_file_v2(&key, Some(&m), &mut entry, &mut out)? {
                    bail!("Failed to decrypt chunk in {}", orgfilename);
                }
            } else {
                if n > 0 {
                    out.write_all(&m[..n])?;
                }
                io::copy(&mut entry, &mut out)?;
            }
            out.flush()?;
            println!(
                "  [+] Successfully extracted {} ({} bytes)",
                file_name.to_string_lossy(),
                dest_path.metadata()?.len()
            );
            extracted.push(dest_path);
        }
    } else {
        // Mode 1 extraction
        println!(
            "[*] Extracting partition '{}' from Mode 1 OZIP archive...",
            target_partition
        );
        let mut fname = String::new();
        if clist.contains("firmware-update/vbmeta.img") {
            fname = "firmware-update/vbmeta.img".to_string();
        } else if clist.contains("vbmeta.img") {
            fname = "vbmeta.img".to_string();
        } else if archive.by_name("firmware-update/vbmeta.img").is_ok() {
            fname = "firmware-update/vbmeta.img".to_string();
        } else if archive.by_name("vbmeta.img").is_ok() {
            fname = "vbmeta.img".to_string();
        }
        if fname.is_empty() {
            bail!("Could not locate vbmeta.img to identify AES key in Mode 1 archive.");
        }
        let key = {
            let mut vbmeta = archive.by_name(&fname)?;
            io::copy(&mut (&mut vbmeta).take(0x1050), &mut io::sink())?;
            let mut data = [0u8; 16];
            let n = read_full(&mut vbmeta, &mut data)?;
            if n < 16 {
                bail!("vbmeta.img is too short to identify key.");
            }
            keytest(&data, &keys.ozip_keys)
                .context("No matching AES key found for Mode 1 archive.")?
        };
        println!("[+] Matched AES decryption key for Mode 1 archive.");

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            if entry.is_dir() {
                continue;
            }
            let orgfilename = entry.name()?.to_string();
            if !matches_target(&orgfilename) {
                continue;
            }

            let file_name = Path::new(&orgfilename).file_name().unwrap();
            let dest_path = out_dir.join(file_name);
            println!("[*] Extracting: {} -> {}", orgfilename, dest_path.display());

            let file_size = entry.size();
            let mut out = File::create(&dest_path)?;
            if !clist.is_empty() {
                if clist.contains(&orgfilename) {
                    decrypt_file_v1(&key, None, &mut entry, file_size, &mut out)?;
                } else {
                    io::copy(&mut entry, &mut out)?;
                }
            } else {
                let mut m = [0u8; 12];
                let n = read_full(&mut entry, &mut m)?;
                if n == 12 && &m == OZIP_MAGIC {
                    decrypt_file_v1(&key, Some(&m), &mut entry, file_size, &mut out)?;
                } else {
                    if n > 0 {
                        out.write_all(&m[..n])?;
                    }
                    io::copy(&mut entry, &mut out)?;
                }
            }
            out.flush()?;
            println!(
                "  [+] Successfully extracted {} ({} bytes)",
                file_name.to_string_lossy(),
                dest_path.metadata()?.len()
            );
            extracted.push(dest_path);
        }
    }

    if extracted.is_empty() {
        let mut available = Vec::new();
        for i in 0..std::cmp::min(archive.len(), 15) {
            if let Ok(entry) = archive.by_index(i) {
                if let Ok(name) = entry.name() {
                    available.push(name.to_string());
                }
            }
        }
        bail!(
            "No partition matching '{}' found in OZIP archive. Examples of files in this archive: {}",
            target_partition,
            available.join(", ")
        );
    }

    println!(
        "\n[+] Successfully extracted {} partition(s) to {}",
        extracted.len(),
        out_dir.display()
    );
    Ok(extracted)
}
