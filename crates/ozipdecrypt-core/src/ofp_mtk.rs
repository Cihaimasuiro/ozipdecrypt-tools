use crate::error::OzipError;
use crate::reporter::{ChecksumStatus, NoopReporter, ProgressEvent, ProgressReporter};
use aes::Aes128;
use anyhow::{bail, Context, Result};
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use md5::{Digest, Md5};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

type Aes128Cfb = cfb_mode::Decryptor<Aes128>;

pub const MTK_KEYTABLES: &[&[&str]] = &[
    // A77 CPH1715EX_11_A.04_170426, F1S A1601_MT6750_EX_11_A.15_160913 FW
    &[
        "67657963787565E837D226B69A495D21",
        "F6C50203515A2CE7D8C3E1F938B7E94C",
        "42F2D5399137E2B2813CD8ECDF2F4D72",
    ],
    // A77 CPH1715EX_11_A.04_170426, F1S A1601_MT6750_EX_11_A.15_160913 CDT
    &[
        "9E4F32639D21357D37D226B69A495D21",
        "A3D8D358E42F5A9E931DD3917D9A3218",
        "386935399137416B67416BECF22F519A",
    ],
    &[
        "892D57E92A4D8A975E3C216B7C9DE189",
        "D26DF2D9913785B145D18C7219B89F26",
        "516989E4A1BFC78B365C6BC57D944391",
    ],
    &[
        "27827963787265EF89D126B69A495A21",
        "82C50203285A2CE7D8C3E198383CE94C",
        "422DD5399181E223813CD8ECDF2E4D72",
    ],
    &[
        "3C4A618D9BF2E4279DC758CD535147C3",
        "87B13D29709AC1BF2382276C4E8DF232",
        "59B7A8E967265E9BCABE2469FE4A915E",
    ],
    // A83 CPH1827_11_A.21_2G_180923 FW, Realme 3 RMX1827EX_11_C.13_200624
    &[
        "1C3288822BF824259DC852C1733127D3",
        "E7918D22799181CF2312176C9E2DF298",
        "3247F889A7B6DECBCA3E28693E4AAAFE",
    ],
    &[
        "1E4F32239D65A57D37D2266D9A775D43",
        "A332D3C3E42F5A3E931DD991729A321D",
        "3F2A35399A373377674155ECF28FD19A",
    ],
    &[
        "122D57E92A518AFF5E3C786B7C34E189",
        "DD6DF2D9543785674522717219989FB0",
        "12698965A132C76136CC88C5DD94EE91",
    ],
    // Direct AES key & IV
    &["ab3f76d7989207f2", "2bf515b3a9737835"],
];

/// Deobfuscates bytes by XORing with key[i % keylen] and swapping nibbles
pub fn mtk_shuffle(key: &[u8], input: &mut [u8]) {
    for (i, b) in input.iter_mut().enumerate() {
        let k = key[i % key.len()];
        *b = k ^ b.rotate_left(4);
    }
}

/// Swaps nibbles on (key[i % keylen] ^ input[i])
pub fn mtk_shuffle2(key: &[u8], input: &mut [u8]) {
    for (i, b) in input.iter_mut().enumerate() {
        let tmp = key[i % key.len()] ^ *b;
        *b = tmp.rotate_left(4);
    }
}

pub fn derive_mtk_key(index: usize) -> Result<([u8; 16], [u8; 16])> {
    let entry = MTK_KEYTABLES
        .get(index)
        .context("Invalid MTK key table index")?;

    if entry.len() == 3 {
        let obskey = hex::decode(entry[0])?;
        let mut encaeskey = hex::decode(entry[1])?;
        let mut encaesiv = hex::decode(entry[2])?;

        mtk_shuffle2(&obskey, &mut encaeskey);
        mtk_shuffle2(&obskey, &mut encaesiv);

        let key_hex = format!("{:x}", Md5::digest(&encaeskey));
        let iv_hex = format!("{:x}", Md5::digest(&encaesiv));

        let mut aes_key = [0u8; 16];
        let mut aes_iv = [0u8; 16];
        aes_key.copy_from_slice(&key_hex.as_bytes()[0..16]);
        aes_iv.copy_from_slice(&iv_hex.as_bytes()[0..16]);

        Ok((aes_key, aes_iv))
    } else if entry.len() == 2 {
        let mut aes_key = [0u8; 16];
        let mut aes_iv = [0u8; 16];
        aes_key.copy_from_slice(entry[0].as_bytes());
        aes_iv.copy_from_slice(entry[1].as_bytes());
        Ok((aes_key, aes_iv))
    } else {
        bail!("Unsupported MTK keytable format at index {}", index);
    }
}

pub fn brute_mtk_key(file: &mut File) -> Result<([u8; 16], [u8; 16])> {
    file.seek(SeekFrom::Start(0))?;
    let mut sample_block = [0u8; 16];
    file.read_exact(&mut sample_block)?;

    for idx in 0..MTK_KEYTABLES.len() {
        if let Ok((key, iv)) = derive_mtk_key(idx) {
            let mut candidate = sample_block;
            let cipher = Aes128Cfb::new(&key.into(), &iv.into());
            cipher.decrypt(&mut candidate);
            if candidate.starts_with(b"MMM") {
                return Ok((key, iv));
            }
        }
    }

    bail!("No matching MediaTek AES key found. Header did not decrypt to 'MMM' magic.")
}

#[derive(Debug)]
pub struct MtkPartitionEntry {
    pub name: String,
    pub start: u64,
    pub length: u64,
    pub enc_length: u64,
    pub filename: String,
    #[allow(dead_code)]
    pub crc: u64,
}

pub fn extract_ofp_mtk(
    ofp_path: &Path,
    out_dir: &Path,
    target_partition: Option<&str>,
) -> Result<()> {
    extract_ofp_mtk_with_reporter(ofp_path, out_dir, target_partition, &NoopReporter)?;
    Ok(())
}

pub fn extract_ofp_mtk_with_reporter(
    ofp_path: &Path,
    out_dir: &Path,
    target_partition: Option<&str>,
    reporter: &dyn ProgressReporter,
) -> Result<Vec<(String, u64, ChecksumStatus)>> {
    let targets = target_partition.map(|p| vec![p.to_string()]);
    extract_ofp_mtk_partitions_with_reporter(ofp_path, out_dir, targets.as_deref(), reporter)
}

pub fn extract_ofp_mtk_partitions_with_reporter(
    ofp_path: &Path,
    out_dir: &Path,
    target_partitions: Option<&[String]>,
    reporter: &dyn ProgressReporter,
) -> Result<Vec<(String, u64, ChecksumStatus)>> {
    fs::create_dir_all(out_dir)?;
    let mut file = File::open(ofp_path).with_context(|| {
        format!(
            "Failed to open MediaTek OFP archive: {}",
            ofp_path.display()
        )
    })?;
    let file_size = file.metadata()?.len();

    let (aes_key, aes_iv) =
        brute_mtk_key(&mut file).context("Failed to detect MediaTek OFP AES key.")?;

    let hdr_key = b"geyixue";
    let hdr_length = 0x6Cu64;
    if file_size < hdr_length {
        bail!("File is too small to contain MediaTek OFP trailer metadata.");
    }

    // Read 0x6C trailer metadata at end of file
    file.seek(SeekFrom::Start(file_size - hdr_length))?;
    let mut hdr = vec![0u8; hdr_length as usize];
    file.read_exact(&mut hdr)?;
    mtk_shuffle(hdr_key, &mut hdr);

    let hdr2entries = u16::from_le_bytes(hdr[72..74].try_into().unwrap()) as u64;
    const MAX_MTK_ENTRIES: u64 = 1000;
    if hdr2entries > MAX_MTK_ENTRIES {
        bail!(
            "Invalid MediaTek partition table: entry count {} exceeds safety limit",
            hdr2entries
        );
    }

    let hdr2_length = hdr2entries * 0x60;
    if file_size < hdr2_length + hdr_length {
        bail!("File size too small for secondary MediaTek partition table.");
    }

    let hdr2_offset = file_size - hdr2_length - hdr_length;
    file.seek(SeekFrom::Start(hdr2_offset))?;
    let mut hdr2 = vec![0u8; hdr2_length as usize];
    file.read_exact(&mut hdr2)?;
    mtk_shuffle(hdr_key, &mut hdr2);

    let mut entries = Vec::new();
    for i in 0..(hdr2_length / 0x60) as usize {
        let chunk = &hdr2[i * 0x60..(i + 1) * 0x60];
        let name = String::from_utf8_lossy(&chunk[0..32])
            .trim_matches('\0')
            .trim()
            .to_string();
        let start = u64::from_le_bytes(chunk[32..40].try_into().unwrap());
        let length = u64::from_le_bytes(chunk[40..48].try_into().unwrap());
        let enc_length = u64::from_le_bytes(chunk[48..56].try_into().unwrap());
        let filename = String::from_utf8_lossy(&chunk[56..88])
            .trim_matches('\0')
            .trim()
            .to_string();
        let crc = u64::from_le_bytes(chunk[88..96].try_into().unwrap());

        if !name.is_empty() && !filename.is_empty() {
            entries.push(MtkPartitionEntry {
                name,
                start,
                length,
                enc_length,
                filename,
                crc,
            });
        }
    }

    let mut filtered_entries = Vec::new();
    for entry in entries {
        if let Some(targets) = target_partitions {
            let fn_lower = entry.filename.to_lowercase();
            let name_lower = entry.name.to_lowercase();
            let matches = targets.iter().any(|target| {
                let t_lower = target.to_lowercase();
                if t_lower == "modem" {
                    fn_lower.contains("modem")
                        || fn_lower.contains("md1img")
                        || name_lower == "modem"
                } else if t_lower == "wifi" || t_lower == "wlan" {
                    fn_lower.contains("wlan") || name_lower.contains("wlan")
                } else {
                    fn_lower == t_lower || name_lower == t_lower
                }
            });
            if !matches {
                continue;
            }
        }
        filtered_entries.push(entry);
    }

    if filtered_entries.is_empty() {
        if let Some(targets) = target_partitions {
            bail!("No MediaTek partition matching {:?} was found.", targets);
        } else {
            bail!("No extractable partitions found in MediaTek OFP archive.");
        }
    }

    let total_bytes: u64 = filtered_entries.iter().map(|e| e.length).sum();
    reporter.on_event(ProgressEvent::Started {
        total_items: filtered_entries.len(),
        total_bytes,
    });

    let mut cumulative_done = 0u64;
    let mut results = Vec::new();

    for entry in &filtered_entries {
        if reporter.is_cancelled() {
            return Err(OzipError::Cancelled.into());
        }

        reporter.on_event(ProgressEvent::ItemStarted {
            name: entry.filename.clone(),
            size: entry.length,
        });

        let out_file_path = crate::crypto::safe_join(out_dir, &entry.filename)?;
        if let (Ok(src_c), Ok(dst_c)) = (ofp_path.canonicalize(), out_file_path.canonicalize()) {
            if src_c == dst_c {
                bail!(
                    "Refusing to overwrite input archive: {}",
                    ofp_path.display()
                );
            }
        }

        if let Some(parent) = out_file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if entry.enc_length > entry.length {
            bail!(
                "Corrupted MTK entry '{}': enc_length ({}) exceeds length ({})",
                entry.filename,
                entry.enc_length,
                entry.length
            );
        }

        const MAX_MTK_ENC_LEN: u64 = 16 * 1024 * 1024; // 16 MB max encrypted header
        if entry.enc_length > MAX_MTK_ENC_LEN {
            bail!(
                "Corrupted MTK entry '{}': enc_length ({}) exceeds 16 MB safety limit",
                entry.filename,
                entry.enc_length
            );
        }

        let out_of_bounds = match entry.start.checked_add(entry.length) {
            Some(end) => end > file_size,
            None => true,
        };
        if out_of_bounds {
            bail!(
                "Corrupted MTK entry '{}': start ({:#x}) + length ({:#x}) exceeds file size ({:#x})",
                entry.filename,
                entry.start,
                entry.length,
                file_size
            );
        }

        let part_path = crate::crypto::get_part_path(&out_file_path);

        let write_res = (|| -> Result<()> {
            let mut out = File::create(&part_path)?;
            file.seek(SeekFrom::Start(entry.start))?;
            let mut remaining_len = entry.length;

            if entry.enc_length > 0 {
                // AES CFB pad to 16 bytes if not divisible by 16
                let padded_len = if entry.enc_length % 16 != 0 {
                    (entry.enc_length + (16 - (entry.enc_length % 16))) as usize
                } else {
                    entry.enc_length as usize
                };
                let mut enc_data = vec![0u8; padded_len];
                file.read_exact(&mut enc_data[..entry.enc_length as usize])?;

                let cipher = Aes128Cfb::new(&aes_key.into(), &aes_iv.into());
                cipher.decrypt(&mut enc_data);

                out.write_all(&enc_data[..entry.enc_length as usize])?;
                remaining_len = remaining_len.saturating_sub(entry.enc_length);
                cumulative_done += entry.enc_length;
                reporter.on_event(ProgressEvent::Progress {
                    bytes_done: cumulative_done,
                    bytes_total: total_bytes,
                });
            }

            // Stream remaining plain partition payload in 64 KB blocks for responsiveness
            let mut buf = vec![0u8; 64 * 1024];
            while remaining_len > 0 {
                if reporter.is_cancelled() {
                    return Err(OzipError::Cancelled.into());
                }
                let to_read = std::cmp::min(remaining_len, buf.len() as u64) as usize;
                let n = file.read(&mut buf[..to_read])?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n])?;
                remaining_len -= n as u64;
                cumulative_done += n as u64;
                reporter.on_event(ProgressEvent::Progress {
                    bytes_done: cumulative_done,
                    bytes_total: total_bytes,
                });
            }

            out.flush()?;
            Ok(())
        })();

        if let Err(e) = write_res {
            let _ = fs::remove_file(&part_path);
            return Err(e);
        }

        fs::rename(&part_path, &out_file_path)?;

        reporter.on_event(ProgressEvent::ItemDone {
            name: entry.filename.clone(),
            checksum: ChecksumStatus::NoHashInManifest,
        });

        results.push((
            entry.filename.clone(),
            entry.length,
            ChecksumStatus::NoHashInManifest,
        ));
    }

    reporter.on_event(ProgressEvent::Finished);
    Ok(results)
}
