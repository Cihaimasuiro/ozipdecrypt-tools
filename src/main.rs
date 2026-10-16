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
            handle_extract(
                &input,
                out_dir.as_deref(),
                partition.as_deref(),
                sideload,
                &key_config,
            )?;
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
                if input
                    .extension()
                    .map(|e| e.eq_ignore_ascii_case("zip"))
                    .unwrap_or(false)
                {
                    input.with_file_name(format!(
                        "{}.decrypted.zip",
                        input
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("firmware")
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
                match ofp::extract_ofp_partition(
                    &input,
                    &out_dir,
                    partition.as_deref(),
                    &key_config,
                ) {
                    Ok(()) => {}
                    Err(qc_err) => {
                        println!(
                            "[*] Qualcomm OFP detection did not match, trying MediaTek OFP..."
                        );
                        if let Err(mtk_err) =
                            ofp_mtk::extract_ofp_mtk(&input, &out_dir, partition.as_deref())
                        {
                            bail!(
                                "Failed to extract OFP archive as Qualcomm or MediaTek:\n\
                                 - Qualcomm check: {}\n\
                                 - MediaTek check: {}",
                                qc_err,
                                mtk_err
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
                dir.join(format!(
                    "{}.zip",
                    input
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("firmware")
                ))
            } else if input
                .extension()
                .map(|e| e.eq_ignore_ascii_case("zip"))
                .unwrap_or(false)
            {
                input.with_file_name(format!(
                    "{}.decrypted.zip",
                    input
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("firmware")
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
                    println!(
                        "[*] Qualcomm OFP extraction did not match, falling back to MediaTek..."
                    );
                    if let Err(mtk_err) = ofp_mtk::extract_ofp_mtk(input, target_dir, partition) {
                        bail!(
                            "Failed to extract OFP archive as Qualcomm or MediaTek:\n\
                             - Qualcomm: {}\n\
                             - MediaTek: {}",
                            qc_err,
                            mtk_err
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
    println!(
        "Size:         {:.2} MB ({} bytes)",
        info.file_size as f64 / (1024.0 * 1024.0),
        info.file_size
    );
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
    use sha2::{Digest, Sha256};
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
        ozip::decrypt_file_v1(
            &key_bytes,
            None,
            &mut reader,
            enc.len() as u64,
            &mut decrypted,
        )
        .unwrap();

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
                    let mut block =
                        cipher::generic_array::GenericArray::clone_from_slice(&sub_remain[..16]);
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
    fn test_ops_key_update_known_answer_vector() {
        let sbox = hex::decode(ops::SBOX_HEX).unwrap();
        let next_key = ops::key_update(ops::MASTER_KEY, &ops::MBOX5, &sbox);
        assert_eq!(
            next_key,
            [0x3CE51B36, 0x916C9E09, 0x3709AC36, 0x4BB526AB],
            "OPS key_update must exactly match upstream python test vector"
        );
    }

    #[test]
    fn test_ops_mbox4_mbox6_known_answer_vectors() {
        let sbox = hex::decode(ops::SBOX_HEX).unwrap();
        let key4 = ops::key_update(ops::MASTER_KEY, &ops::MBOX4, &sbox);
        assert_eq!(
            key4,
            [0x925425CC, 0x4490281F, 0xDBB2FE00, 0x8255FC56],
            "MBOX4 test vector mismatch"
        );

        let key6 = ops::key_update(ops::MASTER_KEY, &ops::MBOX6, &sbox);
        assert_eq!(
            key6,
            [0x5CED7EB1, 0x63EDDFC3, 0x544A73A7, 0xC8F6D44E],
            "MBOX6 test vector mismatch"
        );
    }

    #[test]
    fn test_detect_qualcomm_ofp_0x200_regression() {
        let tmp_dir = std::env::temp_dir();
        let test_file = tmp_dir.join("test_qc_0x200_regression.bin");
        let file_size = 0x1000usize;
        let mut data = vec![0u8; file_size];

        let trailer_pos = file_size - 0x200;
        data[trailer_pos + 0x10..trailer_pos + 0x14].copy_from_slice(&0x7CEFu32.to_le_bytes());
        data[trailer_pos + 0x14..trailer_pos + 0x18].copy_from_slice(&500u32.to_le_bytes());

        std::fs::write(&test_file, &data).unwrap();

        let detected = detect::detect_container(&test_file).unwrap();
        let _ = std::fs::remove_file(&test_file);
        assert_eq!(
            detected,
            detect::ContainerType::OfpQualcomm,
            "0x200 page size Qualcomm OFP must not be misdetected as OPS"
        );
    }

    #[test]
    fn test_safe_join_path_traversal() {
        let base = PathBuf::from("/tmp/extracted");
        assert!(crypto::safe_join(&base, "modem.img").is_ok());
        assert!(crypto::safe_join(&base, "sub/dir/boot.img").is_ok());
        assert!(crypto::safe_join(&base, "").is_err());
        assert!(crypto::safe_join(&base, "   ").is_err());
        assert!(crypto::safe_join(&base, "bad\0file").is_err());
        assert!(crypto::safe_join(&base, "../evil.img").is_err());
        assert!(crypto::safe_join(&base, "..\\evil.img").is_err());
        assert!(crypto::safe_join(&base, "/etc/shadow").is_err());
        assert!(crypto::safe_join(&base, "C:\\Windows\\System32").is_err());
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

    #[test]
    fn test_qualcomm_derived_keys_known_answer_vectors() {
        let expected = [
            ("d154afeeaafa958f", "2c040f5786829207"),
            ("2e96d7f462591a0f", "17cc63224c208708"),
            ("94d62e831cf1a1a0", "7ab5e33bd50d81ca"),
            ("4a837229e6fc77d4", "00bed47b80eec9d7"),
            ("3398699acebda0da", "b39a46f5cc4f0d45"),
            ("b4b7358eea220991", "e9077e26ab102d1b"),
        ];

        for (idx, (exp_key, exp_iv)) in expected.iter().enumerate() {
            let triplet = &crypto::default_ofp_keysets()[idx];
            let (key, iv) = crypto::derive_ofp_qc_key_iv(triplet).unwrap();
            assert_eq!(
                std::str::from_utf8(&key).unwrap(),
                *exp_key,
                "QC Key #{idx} mismatch"
            );
            assert_eq!(
                std::str::from_utf8(&iv).unwrap(),
                *exp_iv,
                "QC IV #{idx} mismatch"
            );
        }
    }

    #[test]
    fn test_mtk_derived_keys_known_answer_vectors() {
        let expected = [
            ("94d62e831cf1a1a0", "7ab5e33bd50d81ca"),
            ("52dddab2c46aab56", "35f19b6877f9c360"),
            ("403200d7e3ccbd16", "e6a12148a4d75e7d"),
            ("d154afeeaafa958f", "2c040f5786829207"),
            ("264f527f9ad1ae8c", "788391d4ae2fd10c"),
            ("443ec2fc7f543de6", "f02df2210580c734"),
            ("be594eab795ccc85", "2016267766ad552b"),
            ("1c1ca204c41d4f83", "916e63a107139707"),
            ("ab3f76d7989207f2", "2bf515b3a9737835"),
        ];

        for (idx, (exp_key, exp_iv)) in expected.iter().enumerate() {
            let (key, iv) = ofp_mtk::derive_mtk_key(idx).unwrap();
            assert_eq!(
                std::str::from_utf8(&key).unwrap(),
                *exp_key,
                "MTK Key #{idx} mismatch"
            );
            assert_eq!(
                std::str::from_utf8(&iv).unwrap(),
                *exp_iv,
                "MTK IV #{idx} mismatch"
            );
        }
    }

    #[test]
    fn test_ops_stream_decrypt_known_answer_vectors() {
        let sbox = hex::decode(ops::SBOX_HEX).unwrap();
        // 16-byte encrypted test vector generated with Python opscrypto.py for plain 0..16 using MBOX5
        let enc5_first_16 = [
            54u8, 26, 231, 63, 13, 155, 106, 150, 62, 165, 3, 60, 167, 43, 187, 68,
        ];
        let (dec, _rkey) = ops::key_custom_decrypt_chunk(
            &enc5_first_16,
            ops::MASTER_KEY,
            &ops::MBOX5,
            &sbox,
            false,
        );
        let expected_plain: Vec<u8> = (0u8..16).collect();
        assert_eq!(
            dec, expected_plain,
            "OPS stream decrypt vector mismatch for MBOX5"
        );

        // 7-byte vector (< 16 bytes total) generated with Python opscrypto.py (calls key_update with sbox)
        let cipher7: Vec<u8> = (0..7).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let expected7 = [72u8, 139, 132, 7, 104, 83, 225];
        let (dec7, _rkey) =
            ops::key_custom_decrypt_chunk(&cipher7, ops::MASTER_KEY, &ops::MBOX5, &sbox, true);
        assert_eq!(
            dec7, expected7,
            "OPS 7-byte stream decrypt vector mismatch for MBOX5"
        );

        // 15-byte vector (< 16 bytes total, uses S-box key schedule)
        let cipher15: Vec<u8> = (0..15).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let expected15 = [
            72u8, 139, 132, 7, 104, 83, 225, 223, 7, 215, 161, 189, 24, 200, 37,
        ];
        let (dec15, _rkey) =
            ops::key_custom_decrypt_chunk(&cipher15, ops::MASTER_KEY, &ops::MBOX5, &sbox, true);
        assert_eq!(
            dec15, expected15,
            "OPS 15-byte stream decrypt vector mismatch for MBOX5"
        );

        // 16-byte vector (full 16-byte block, uses MBOX)
        let cipher16: Vec<u8> = (0..16).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let expected16 = [
            59u8, 15, 254, 30, 32, 174, 91, 175, 115, 224, 90, 109, 202, 78, 218, 61,
        ];
        let (dec16, _rkey) =
            ops::key_custom_decrypt_chunk(&cipher16, ops::MASTER_KEY, &ops::MBOX5, &sbox, false);
        assert_eq!(
            dec16, expected16,
            "OPS 16-byte stream decrypt vector mismatch for MBOX5"
        );

        // 17-byte vector (16-byte block + 1-byte tail, uses MBOX because whole input >= 16)
        let cipher17: Vec<u8> = (0..17).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let expected17 = [
            59u8, 15, 254, 30, 32, 174, 91, 175, 115, 224, 90, 109, 202, 78, 218, 61, 36,
        ];
        let (dec17, _rkey) =
            ops::key_custom_decrypt_chunk(&cipher17, ops::MASTER_KEY, &ops::MBOX5, &sbox, false);
        assert_eq!(
            dec17, expected17,
            "OPS 17-byte stream decrypt vector mismatch for MBOX5"
        );

        // 20-byte vector (16-byte block + 4-byte tail) generated with Python opscrypto.py
        let cipher20: Vec<u8> = (0..20).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let expected20 = [
            59u8, 15, 254, 30, 32, 174, 91, 175, 115, 224, 90, 109, 202, 78, 218, 61, 36, 107, 121,
            83,
        ];
        let (dec20, _rkey) =
            ops::key_custom_decrypt_chunk(&cipher20, ops::MASTER_KEY, &ops::MBOX5, &sbox, false);
        assert_eq!(
            dec20, expected20,
            "OPS 20-byte stream decrypt tail vector mismatch for MBOX5"
        );

        // 100-byte vector (6 full 16-byte blocks + 4-byte tail) generated with Python opscrypto.py
        let cipher100: Vec<u8> = (0..100).map(|i| ((i * 11 + 3) % 256) as u8).collect();
        let expected100 = hex::decode(
            "3515fc1826a429c16dca784b2cb428e3e0d5968b672d409577edc87be67a1bb8\
             0a8df81c970519c94c72c8bdd4e86649f0093a7993e660cec876d3059079cdde\
             bb5b01ea98ef3f000f7515dfd8a5ff63b63b1e8a6aab2554c707e1dda5b43ae2\
             53cfc484",
        )
        .unwrap();
        let (dec100, _rkey) =
            ops::key_custom_decrypt_chunk(&cipher100, ops::MASTER_KEY, &ops::MBOX5, &sbox, false);
        assert_eq!(
            dec100, expected100,
            "OPS 100-byte stream decrypt tail vector mismatch for MBOX5"
        );

        // 65536 + 15 byte vector against upstream output (both single-call and chunked)
        let cipher65536_15: Vec<u8> = (0..(65536 + 15))
            .map(|i| ((i * 7 + 13) % 256) as u8)
            .collect();
        let (c1, r1) = ops::key_custom_decrypt_chunk(
            &cipher65536_15[..65536],
            ops::MASTER_KEY,
            &ops::MBOX5,
            &sbox,
            false,
        );
        let (c2, _) =
            ops::key_custom_decrypt_chunk(&cipher65536_15[65536..], r1, &ops::MBOX5, &sbox, false);
        let mut chunked65536_15 = c1;
        chunked65536_15.extend_from_slice(&c2);

        let single65536_15 =
            ops::key_custom_decrypt(&cipher65536_15, ops::MASTER_KEY, &ops::MBOX5, &sbox);
        assert_eq!(
            chunked65536_15, single65536_15,
            "Chunked 64KB+15 output must match single-call decrypt"
        );

        let mut hasher = Sha256::new();
        hasher.update(&chunked65536_15);
        let digest = format!("{:x}", hasher.finalize());
        assert_eq!(
            digest,
            "7d0da28273b31f098a153669f80f8902f2b8edff0b8c1cfbf12ab6a872150966"
        );
        assert_eq!(
            &chunked65536_15[65536..],
            &[82u8, 69, 157, 154, 107, 43, 228, 215, 49, 176, 83, 29, 255, 153, 31]
        );
    }

    #[test]
    fn test_ops_chunked_vs_single_call_decrypt() {
        let sbox = hex::decode(ops::SBOX_HEX).unwrap();
        // Test 64 KB + 5 bytes: chunked 64 KB + 5 bytes vs single-call
        let inp: Vec<u8> = (0..(65536 + 5))
            .map(|i| ((i * 11 + 3) % 256) as u8)
            .collect();
        let single = ops::key_custom_decrypt(&inp, ops::MASTER_KEY, &ops::MBOX5, &sbox);

        let (c1, r1) = ops::key_custom_decrypt_chunk(
            &inp[..65536],
            ops::MASTER_KEY,
            &ops::MBOX5,
            &sbox,
            false,
        );
        let (c2, _) = ops::key_custom_decrypt_chunk(&inp[65536..], r1, &ops::MBOX5, &sbox, false);
        let mut chunked = c1;
        chunked.extend_from_slice(&c2);

        assert_eq!(
            chunked, single,
            "64 KB + 5 chunked decrypt must match single-call decrypt"
        );
        assert_eq!(
            &chunked[65536..],
            &[4u8, 124, 59, 19, 151],
            "Last 5 bytes must match upstream key_custom"
        );
    }

    #[test]
    fn test_detect_qualcomm_ofp_0x1000_page_size() {
        let tmp_dir = std::env::temp_dir();
        let test_file = tmp_dir.join("test_qc_0x1000.bin");
        let file_size = 0x2000usize;
        let mut data = vec![0u8; file_size];
        let trailer_pos = file_size - 0x1000;
        data[trailer_pos + 0x10..trailer_pos + 0x14].copy_from_slice(&0x7CEFu32.to_le_bytes());
        std::fs::write(&test_file, &data).unwrap();

        let detected = detect::detect_container(&test_file).unwrap();
        let _ = std::fs::remove_file(&test_file);
        assert_eq!(detected, detect::ContainerType::OfpQualcomm);
    }

    #[test]
    fn test_detect_mtk_with_non_zero_count() {
        let tmp_dir = std::env::temp_dir();
        let test_file = tmp_dir.join("test_mtk_detect.bin");
        let file_size = 0x1000usize;
        let mut data = vec![0u8; file_size];
        let trailer_pos = file_size - 0x6C;
        let key = b"geyixue";
        for i in 0..0x6C {
            let k = key[i % key.len()];
            let target_byte = if i == 72 { 10u8 } else { 0u8 };
            let val = target_byte ^ k;
            data[trailer_pos + i] = ((val & 0xF) << 4) | ((val & 0xF0) >> 4);
        }
        std::fs::write(&test_file, &data).unwrap();

        let detected = detect::detect_container(&test_file).unwrap();
        let _ = std::fs::remove_file(&test_file);
        assert_eq!(detected, detect::ContainerType::OfpMediaTek);
    }

    #[test]
    fn test_detect_ops_trailer_magic() {
        let tmp_dir = std::env::temp_dir();
        let test_file = tmp_dir.join("test_ops_detect.bin");
        let file_size = 0x1000usize;
        let mut data = vec![0u8; file_size];
        data[file_size - 4..file_size].copy_from_slice(&0x9EE3B5D1u32.to_le_bytes());
        std::fs::write(&test_file, &data).unwrap();

        let detected = detect::detect_container(&test_file).unwrap();
        let _ = std::fs::remove_file(&test_file);
        assert_eq!(detected, detect::ContainerType::OnePlusOps);
    }

    #[test]
    fn test_detect_ofp_extension_fallback() {
        let tmp_dir = std::env::temp_dir();
        let test_file = tmp_dir.join("fallback_device.ofp");
        let data = vec![0x55u8; 512];
        std::fs::write(&test_file, &data).unwrap();

        let detected = detect::detect_container(&test_file).unwrap();
        let _ = std::fs::remove_file(&test_file);
        assert_eq!(detected, detect::ContainerType::OfpQualcomm);
    }

    #[test]
    fn test_truncated_corrupt_files_return_err() {
        let tmp_dir = std::env::temp_dir();
        let corrupt_file = tmp_dir.join("test_corrupt.bin");
        std::fs::write(&corrupt_file, b"TOO_SHORT").unwrap();

        let keys = crypto::KeyConfig::default();
        let out_dir = tmp_dir.join("out_corrupt");

        // OZIP on truncated file should return Err without panic
        assert!(
            ozip::decrypt_ozip(&corrupt_file, &corrupt_file.with_extension("zip"), &keys).is_err()
        );

        // OFP extraction on truncated/corrupt file should return Err without panic
        assert!(ofp::extract_ofp_partition(&corrupt_file, &out_dir, None, &keys).is_err());

        // OPS extraction on truncated/corrupt file should return Err without panic
        assert!(ops::extract_ops(&corrupt_file, &out_dir, None).is_err());

        let _ = std::fs::remove_file(&corrupt_file);
    }
}
