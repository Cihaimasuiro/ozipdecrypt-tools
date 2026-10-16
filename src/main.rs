mod crypto;
mod detect;
mod flash;
mod ofp;
mod ofp_mtk;
mod ops;
mod ozip;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use crypto::KeyConfig;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "ozipdecrypt-tools",
    version,
    about = "Unified high-performance Rust CLI for decrypting .ozip/.ofp/.ops firmware archives and automating radio updates"
)]
struct Cli {
    /// Path to TOML file containing AES keys (optional, uses built-in database by default)
    #[arg(short, long, default_value = "keys.toml")]
    keys: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Quick-mode: Path to a firmware file to auto-detect and extract directly
    #[arg(value_name = "FIRMWARE_FILE")]
    direct_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Universal zero-config auto-detection and extraction (.ozip, .ofp, .ops, .zip)
    Extract {
        /// Path to firmware file
        input: PathBuf,
        /// Directory to extract decrypted partitions or target .zip
        #[arg(short, long)]
        out_dir: Option<PathBuf>,
        /// Optional single partition to extract (e.g., "modem" or "boot")
        #[arg(short, long)]
        partition: Option<String>,
        /// Automatically sideload via ADB if the resulting output is a .zip
        #[arg(long)]
        sideload: bool,
    },
    /// Inspect and diagnose firmware container format, signature, and encryption parameters
    Info {
        /// Path to firmware file to inspect
        input: PathBuf,
    },
    /// Decrypt an Oppo/Realme .ozip file to a standard .zip archive (and optionally sideload it)
    Ozip {
        /// Input .ozip firmware file
        input: PathBuf,
        /// Output .zip file path
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Automatically run `adb sideload` once decryption finishes
        #[arg(long)]
        sideload: bool,
    },
    /// Decrypt and unpack a Qualcomm or MediaTek .ofp stock firmware archive
    Ofp {
        /// Input .ofp firmware file
        input: PathBuf,
        /// Directory to extract decrypted files into
        #[arg(short, long, default_value = "./extracted_ofp")]
        out_dir: PathBuf,
        /// Optional single partition to extract (e.g., "modem" for NON-HLOS.bin Wi-Fi/radio fix)
        #[arg(short, long)]
        partition: Option<String>,
        /// Explicitly select MediaTek mode (auto-detected by default)
        #[arg(long)]
        mtk: bool,
    },
    /// Decrypt and unpack a OnePlus .ops stock firmware archive
    Ops {
        /// Input .ops firmware file
        input: PathBuf,
        /// Directory to extract decrypted files into
        #[arg(short, long, default_value = "./extracted_ops")]
        out_dir: PathBuf,
        /// Optional single partition to extract (e.g., "modem" or "boot.img")
        #[arg(short, long)]
        partition: Option<String>,
    },
    /// Directly sideload a decrypted .zip firmware package to an attached device
    Sideload {
        /// Path to .zip package to sideload
        zip_file: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let key_config = KeyConfig::load_or_default(&cli.keys)?;

    match (cli.command, cli.direct_file) {
        (
            Some(Commands::Extract {
                input,
                out_dir,
                partition,
                sideload,
            }),
            _,
        ) => {
            handle_extract(&input, out_dir.as_deref(), partition.as_deref(), sideload, &key_config)?;
        }
        (Some(Commands::Info { input }), _) => {
            handle_info(&input)?;
        }
        (
            Some(Commands::Ozip {
                input,
                output,
                sideload,
            }),
            _,
        ) => {
            let out_path = output.unwrap_or_else(|| {
                if input.extension().map(|e| e.eq_ignore_ascii_case("zip")).unwrap_or(false) {
                    input.with_file_name(format!(
                        "{}.decrypted.zip",
                        input.file_stem().and_then(|s| s.to_str()).unwrap_or("firmware")
                    ))
                } else {
                    input.with_extension("zip")
                }
            });
            ozip::decrypt_ozip(&input, &out_path, &key_config)?;
            if sideload {
                flash::adb_sideload(&out_path)?;
            }
        }
        (
            Some(Commands::Ofp {
                input,
                out_dir,
                partition,
                mtk,
            }),
            _,
        ) => {
            if mtk {
                ofp_mtk::extract_ofp_mtk(&input, &out_dir, partition.as_deref())?;
            } else {
                // Try Qualcomm first; if it fails with invalid magic/trailer, fallback to MediaTek
                match ofp::extract_ofp_partition(&input, &out_dir, partition.as_deref(), &key_config) {
                    Ok(()) => {}
                    Err(qc_err) => {
                        println!("[*] Qualcomm OFP detection did not match, trying MediaTek OFP...");
                        if let Err(mtk_err) = ofp_mtk::extract_ofp_mtk(&input, &out_dir, partition.as_deref()) {
                            bail!(
                                "Failed to extract OFP archive as Qualcomm or MediaTek:\n\
                                 - Qualcomm check: {}\n\
                                 - MediaTek check: {}",
                                qc_err, mtk_err
                            );
                        }
                    }
                }
            }
        }
        (
            Some(Commands::Ops {
                input,
                out_dir,
                partition,
            }),
            _,
        ) => {
            ops::extract_ops(&input, &out_dir, partition.as_deref())?;
        }
        (Some(Commands::Sideload { zip_file }), _) => {
            flash::adb_sideload(&zip_file)?;
        }
        (None, Some(input)) => {
            // Quick direct mode: Auto-detect container and extract seamlessly
            handle_extract(&input, None, None, false, &key_config)?;
        }
        (None, None) => {
            println!("ozipdecrypt-tools {}\n", env!("CARGO_PKG_VERSION"));
            println!("Usage:\n    ozipdecrypt-tools <command> [OPTIONS]\n    ozipdecrypt-tools <firmware_file>\n");
            println!("Commands:\n    extract     Universal auto-detection and extraction (.ozip/.ofp/.ops)\n    info        Inspect and diagnose firmware container metadata\n    ozip        Decrypt .ozip to .zip archive\n    ofp         Extract Qualcomm/MediaTek .ofp firmware archive\n    ops         Extract OnePlus .ops firmware archive\n    sideload    Sideload .zip update via ADB\n");
            println!("Run 'ozipdecrypt-tools --help' for full options.");
        }
    }

    Ok(())
}

fn handle_extract(
    input: &Path,
    out_dir: Option<&Path>,
    partition: Option<&str>,
    sideload: bool,
    key_config: &KeyConfig,
) -> Result<()> {
    let container_type = detect::detect_container(input)?;
    println!("[*] Analyzing container format for {}...", input.display());
    println!("[+] Identified: {}", container_type);

    match container_type {
        detect::ContainerType::Ozip => {
            let out_path = if let Some(dir) = out_dir {
                dir.join(format!("{}.zip", input.file_stem().and_then(|s| s.to_str()).unwrap_or("firmware")))
            } else if input.extension().map(|e| e.eq_ignore_ascii_case("zip")).unwrap_or(false) {
                input.with_file_name(format!(
                    "{}.decrypted.zip",
                    input.file_stem().and_then(|s| s.to_str()).unwrap_or("firmware")
                ))
            } else {
                input.with_extension("zip")
            };
            ozip::decrypt_ozip(input, &out_path, key_config)?;
            if sideload {
                flash::adb_sideload(&out_path)?;
            }
        }
        detect::ContainerType::OfpQualcomm => {
            let default_dir = PathBuf::from("./extracted_ofp");
            let target_dir = out_dir.unwrap_or(&default_dir);
            match ofp::extract_ofp_partition(input, target_dir, partition, key_config) {
                Ok(()) => {}
                Err(qc_err) => {
                    println!("[*] Qualcomm OFP extraction did not match, falling back to MediaTek...");
                    if let Err(mtk_err) = ofp_mtk::extract_ofp_mtk(input, target_dir, partition) {
                        bail!(
                            "Failed to extract OFP archive as Qualcomm or MediaTek:\n\
                             - Qualcomm: {}\n\
                             - MediaTek: {}",
                            qc_err, mtk_err
                        );
                    }
                }
            }
        }
        detect::ContainerType::OfpMediaTek => {
            let default_dir = PathBuf::from("./extracted_mtk");
            let target_dir = out_dir.unwrap_or(&default_dir);
            ofp_mtk::extract_ofp_mtk(input, target_dir, partition)?;
        }
        detect::ContainerType::OnePlusOps => {
            let default_dir = PathBuf::from("./extracted_ops");
            let target_dir = out_dir.unwrap_or(&default_dir);
            ops::extract_ops(input, target_dir, partition)?;
        }
        detect::ContainerType::StandardZip => {
            println!("[+] File is already a standard unencrypted ZIP archive.");
            if sideload {
                flash::adb_sideload(input)?;
            } else {
                println!("[*] Pass '--sideload' to automatically flash this update via ADB.");
            }
        }
        detect::ContainerType::Unknown => {
            bail!(
                "Unrecognized container format for '{}'. Please verify the file or specify a subcommand (ozip, ofp, ops).",
                input.display()
            );
        }
    }

    Ok(())
}

fn handle_info(input: &Path) -> Result<()> {
    let info = detect::describe_container(input)?;
    println!("\n=== Firmware Container Diagnostic ===");
    println!("File:         {}", input.display());
    println!("Size:         {:.2} MB ({} bytes)", info.file_size as f64 / (1024.0 * 1024.0), info.file_size);
    println!("Format:       {}", info.container_type);
    println!("Description:  {}", info.details);
    println!("=====================================\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;
    use crypto::{derive_ofp_qc_key_iv, key_shuffle, swap_nibbles, OfpKeyTriplet};
    use std::io::Cursor;

    #[test]
    fn test_swap_nibbles() {
        assert_eq!(swap_nibbles(0x12), 0x21);
        assert_eq!(swap_nibbles(0xAB), 0xBA);
        assert_eq!(swap_nibbles(0x0F), 0xF0);
    }

    #[test]
    fn test_key_shuffle() {
        let key = [0x11u8; 16];
        let hkey = [0x22u8; 16];
        let shuffled = key_shuffle(&key, &hkey);
        // 0x11 ^ 0x22 = 0x33, swapped = 0x33
        assert_eq!(shuffled, [0x33u8; 16]);
    }

    #[test]
    fn test_ofp_key_derivation() {
        let triplet = OfpKeyTriplet {
            name: "Test Triplet".to_string(),
            mc: "00112233445566778899AABBCCDDEEFF".to_string(),
            userkey: "FFEEDDCCBBAA99887766554433221100".to_string(),
            ivec: "0102030405060708090A0B0C0D0E0F10".to_string(),
        };

        let res = derive_ofp_qc_key_iv(&triplet);
        assert!(res.is_ok());
        let (key, iv) = res.unwrap();
        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 16);
    }

    #[test]
    fn test_ozip_v1_decryption() {
        let key_bytes = crypto::hex_to_bytes(crypto::DEFAULT_OZIP_KEYS[0]).unwrap();
        let cipher = Aes128::new_from_slice(&key_bytes).unwrap();

        let original_data = b"VBMETA_PAYLOAD_TEST_DATA_FOR_OZIP_DECRYPTION";
        let dsize = original_data.len();

        let mut enc = Vec::new();
        enc.extend_from_slice(b"OPPOENCRYPT!\0\0\0\0");
        let dsize_str = format!("{}", dsize);
        let mut dsize_field = [0u8; 16];
        dsize_field[..dsize_str.len()].copy_from_slice(dsize_str.as_bytes());
        enc.extend_from_slice(&dsize_field);
        enc.resize(0x1050, 0xAA);

        let mut padded = original_data.to_vec();
        while padded.len() % 16 != 0 {
            padded.push(0);
        }
        for chunk in padded.chunks_exact(16) {
            let mut block = cipher::generic_array::GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            enc.extend_from_slice(&block);
        }

        let mut reader = Cursor::new(&enc);
        let mut decrypted = Vec::new();
        ozip::decrypt_file_v1(&key_bytes, None, &mut reader, enc.len() as u64, &mut decrypted).unwrap();

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_ozip_v2_decryption() {
        let key_bytes = crypto::hex_to_bytes(crypto::DEFAULT_OZIP_KEYS[16]).unwrap();
        let cipher = Aes128::new_from_slice(&key_bytes).unwrap();

        let mut original_data = Vec::new();
        for i in 0..1000 {
            original_data.extend_from_slice(format!("Boot image line {}\n", i).as_bytes());
        }
        let bdsize = original_data.len();

        let mut enc = Vec::new();
        enc.extend_from_slice(b"OPPOENCRYPT!");
        enc.extend_from_slice(&[0u8; 4]);
        let bdsize_str = format!("{}", bdsize);
        let mut bdsize_field = [0u8; 16];
        bdsize_field[..bdsize_str.len()].copy_from_slice(bdsize_str.as_bytes());
        enc.extend_from_slice(&bdsize_field);
        enc.extend_from_slice(&[0u8; 48]);

        let mut offset = 0;
        while offset < original_data.len() {
            let chunk_end = std::cmp::min(offset + 0x4000, original_data.len());
            let sub = &original_data[offset..chunk_end];
            if sub.len() <= 16 {
                let mut b = [0u8; 16];
                b[..sub.len()].copy_from_slice(sub);
                let mut block = cipher::generic_array::GenericArray::clone_from_slice(&b);
                cipher.encrypt_block(&mut block);
                enc.extend_from_slice(&block[..sub.len()]);
            } else {
                let mut block = cipher::generic_array::GenericArray::clone_from_slice(&sub[..16]);
                cipher.encrypt_block(&mut block);
                enc.extend_from_slice(&block);
                enc.extend_from_slice(&sub[16..]);
            }
            offset += 0x4000;
        }

        let mut reader = Cursor::new(&enc);
        let mut decrypted = Vec::new();
        let ok = ozip::decrypt_file_v2(&key_bytes, None, &mut reader, &mut decrypted).unwrap();
        assert!(ok);
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_ozip_v2_multi_chunk_decryption() {
        let key_bytes = crypto::hex_to_bytes(crypto::DEFAULT_OZIP_KEYS[16]).unwrap();
        let cipher = Aes128::new_from_slice(&key_bytes).unwrap();

        // Generate data spanning two 0x40000 blocks (300,000 bytes)
        let total_size = 300_000usize;
        let mut original_data = vec![0u8; total_size];
        for i in 0..original_data.len() {
            original_data[i] = (i % 251) as u8;
        }

        let mut enc = Vec::new();
        let mut offset = 0;

        while offset < total_size {
            let block_payload_len = std::cmp::min(0x40000, total_size - offset);
            enc.extend_from_slice(b"OPPOENCRYPT!");
            enc.extend_from_slice(&[0u8; 4]);
            let bdsize_str = format!("{}", block_payload_len);
            let mut bdsize_field = [0u8; 16];
            bdsize_field[..bdsize_str.len()].copy_from_slice(bdsize_str.as_bytes());
            enc.extend_from_slice(&bdsize_field);
            enc.extend_from_slice(&[0u8; 48]);

            let block_slice = &original_data[offset..offset + block_payload_len];
            let mut sub_offset = 0;
            while sub_offset < block_slice.len() {
                let sub_remain = &block_slice[sub_offset..];
                if sub_remain.len() <= 16 {
                    let mut b = [0u8; 16];
                    b[..sub_remain.len()].copy_from_slice(sub_remain);
                    let mut block = cipher::generic_array::GenericArray::clone_from_slice(&b);
                    cipher.encrypt_block(&mut block);
                    enc.extend_from_slice(&block[..sub_remain.len()]);
                    sub_offset += sub_remain.len();
                } else {
                    let mut block = cipher::generic_array::GenericArray::clone_from_slice(&sub_remain[..16]);
                    cipher.encrypt_block(&mut block);
                    enc.extend_from_slice(&block);
                    sub_offset += 16;

                    let plain_len = std::cmp::min(0x3FF0, block_slice.len() - sub_offset);
                    enc.extend_from_slice(&block_slice[sub_offset..sub_offset + plain_len]);
                    sub_offset += plain_len;
                }
            }

            offset += block_payload_len;
        }

        let mut reader = Cursor::new(&enc);
        let mut decrypted = Vec::new();
        let ok = ozip::decrypt_file_v2(&key_bytes, None, &mut reader, &mut decrypted).unwrap();
        assert!(ok);
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_profile_xml_parsing() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<data>
    <Sahara>
        <File Path="prog_emmc_firehose_8953_ddr.mbn" FileOffsetInSrc="10" SizeInByteInSrc="204800" SizeInSectorInSrc="400" md5="d41d8cd98f00b204e9800998ecf8427e" sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"/>
    </Sahara>
    <Firmware>
        <File Path="NON-HLOS.bin" FileOffsetInSrc="500" SizeInByteInSrc="67108864" SizeInSectorInSrc="131072" md5="abc123" sha256="def456"/>
    </Firmware>
</data>"#;
        let items = ofp::parse_profile_xml(xml, 0x200).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].filename, "prog_emmc_firehose_8953_ddr.mbn");
        assert_eq!(items[0].start, 10 * 0x200);
        assert_eq!(items[0].decrypt_size, 204800);
        assert!(!items[0].is_copy_only);

        assert_eq!(items[1].filename, "NON-HLOS.bin");
        assert_eq!(items[1].start, 500 * 0x200);
        assert!(items[1].is_copy_only);
    }

    #[test]
    fn test_overwrite_guard() {
        let path = PathBuf::from("dummy_test.zip");
        let res = ozip::decrypt_ozip(&path, &path, &KeyConfig::default());
        assert!(res.is_err());
        let err_msg = res.err().unwrap().to_string();
        assert!(err_msg.contains("identical"));
    }

    #[test]
    fn test_mtk_shuffle_primitives() {
        let key = b"geyixue";
        let mut data = [0x12, 0x34, 0x56, 0x78];
        ofp_mtk::mtk_shuffle(key, &mut data);
        assert_ne!(data, [0x12, 0x34, 0x56, 0x78]);

        let mut data2 = [0xAB, 0xCD, 0xEF, 0x01];
        ofp_mtk::mtk_shuffle2(key, &mut data2);
        assert_ne!(data2, [0xAB, 0xCD, 0xEF, 0x01]);
    }

    #[test]
    fn test_mtk_key_derivation() {
        for idx in 0..ofp_mtk::MTK_KEYTABLES.len() {
            let res = ofp_mtk::derive_mtk_key(idx);
            assert!(res.is_ok());
            let (key, iv) = res.unwrap();
            assert_eq!(key.len(), 16);
            assert_eq!(iv.len(), 16);
        }
    }

    #[test]
    fn test_ops_key_update() {
        let sbox = hex::decode(ops::SBOX_HEX).unwrap();
        let iv = [0u32; 4];
        let next_key = ops::key_update(iv, &ops::MBOX5, &sbox);
        assert_ne!(next_key, [0u32; 4]);
        let next_key2 = ops::key_update(iv, &ops::MBOX5, &sbox);
        assert_eq!(next_key, next_key2);
    }

    #[test]
    fn test_ops_xml_parsing() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<data>
    <Sahara>
        <File Path="prog_firehose_lite.elf" FileOffsetInSrc="10" SizeInByteInSrc="102400" Sha256="aabbcc"/>
    </Sahara>
    <Firmware>
        <File Path="boot.img" FileOffsetInSrc="200" SizeInByteInSrc="67108864" Sha256="ddeeff"/>
    </Firmware>
</data>"#;
        let items = ops::parse_ops_xml(xml).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].filename, "prog_firehose_lite.elf");
        assert_eq!(items[0].start, 10 * 0x200);
        assert_eq!(items[0].length, 102400);
        assert!(items[0].is_encrypted);

        assert_eq!(items[1].filename, "boot.img");
        assert_eq!(items[1].start, 200 * 0x200);
        assert_eq!(items[1].length, 67108864);
        assert!(!items[1].is_encrypted);
    }

    #[test]
    fn test_detect_ozip_magic() {
        let tmp_dir = std::env::temp_dir();
        let test_ozip = tmp_dir.join("test_detect_sample.ozip");
        let mut data = vec![0u8; 256];
        data[0..12].copy_from_slice(b"OPPOENCRYPT!");
        std::fs::write(&test_ozip, &data).unwrap();

        let detected = detect::detect_container(&test_ozip).unwrap();
        let _ = std::fs::remove_file(&test_ozip);
        assert_eq!(detected, detect::ContainerType::Ozip);
    }

    #[test]
    fn test_detect_unknown() {
        let tmp_dir = std::env::temp_dir();
        let test_unknown = tmp_dir.join("test_detect_sample.bin");
        std::fs::write(&test_unknown, b"RANDOM_NON_CONTAINER_DATA_BYTES_EXCEEDING_MINIMUM_LENGTH_FOR_DETECTION_CHECK_128_BYTES_PADDING_PAD_PAD_PAD_PAD_PAD_PAD_PAD_PAD_PAD_PAD").unwrap();

        let detected = detect::detect_container(&test_unknown).unwrap();
        let _ = std::fs::remove_file(&test_unknown);
        assert_eq!(detected, detect::ContainerType::Unknown);
    }
}
