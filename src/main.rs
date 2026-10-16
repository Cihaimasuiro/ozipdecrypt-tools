mod crypto;
mod flash;
mod ofp;
mod ozip;

use anyhow::Result;
use clap::{Parser, Subcommand};
use crypto::KeyConfig;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ozipdecrypt-tools",
    version,
    about = "Unified high-performance Rust CLI for decrypting .ozip/.ofp firmware archives and automating radio updates"
)]
struct Cli {
    /// Path to TOML file containing AES keys (optional, uses built-in database by default)
    #[arg(short, long, default_value = "keys.toml")]
    keys: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Quick-mode: Path to an .ozip file to decrypt directly without specifying 'ozip' subcommand
    #[arg(value_name = "OZIP_FILE")]
    direct_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
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
    /// Decrypt and unpack a Qualcomm .ofp stock firmware archive
    Ofp {
        /// Input .ofp firmware file
        input: PathBuf,
        /// Directory to extract decrypted files into
        #[arg(short, long, default_value = "./extracted_ofp")]
        out_dir: PathBuf,
        /// Optional single partition to extract (e.g., "modem" for NON-HLOS.bin Wi-Fi/radio fix)
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
            Some(Commands::Ozip {
                input,
                output,
                sideload,
            }),
            _,
        ) => {
            let out_path = output.unwrap_or_else(|| input.with_extension("zip"));
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
            }),
            _,
        ) => {
            ofp::extract_ofp_partition(&input, &out_dir, partition.as_deref(), &key_config)?;
        }
        (Some(Commands::Sideload { zip_file }), _) => {
            flash::adb_sideload(&zip_file)?;
        }
        (None, Some(input)) => {
            // Quick direct OZIP decryption mode
            let out_path = input.with_extension("zip");
            ozip::decrypt_ozip(&input, &out_path, &key_config)?;
        }
        (None, None) => {
            println!("ozipdecrypt-tools {}\n", env!("CARGO_PKG_VERSION"));
            println!("Usage:\n    ozipdecrypt-tools <command> [OPTIONS]\n    ozipdecrypt-tools <filename.ozip>\n");
            println!("Commands:\n    ozip        Decrypt .ozip to .zip archive\n    ofp         Extract Qualcomm .ofp firmware archive\n    sideload    Sideload .zip update via ADB\n");
            println!("Run 'ozipdecrypt-tools --help' for full options.");
        }
    }

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
}
