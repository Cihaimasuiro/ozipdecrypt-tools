use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use anyhow::{Context, Result};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const DEFAULT_OZIP_KEYS: &[&str] = &[
    "D6EECF0AE5ACD4E0E9FE522DE7CE381E", // mnkey
    "D6ECCF0AE5ACD4E0E92E522DE7C1381E", // mkey
    "D6DCCF0AD5ACD4E0292E522DB7C1381E", // realkey, R9s CPH1607 MSM8953, Plus, R11, RMX1921 Realme XT, RMX1851EX
    "D7DCCE1AD4AFDCE2393E5161CBDC4321", // testkey
    "D7DBCE2AD4ADDCE1393E5521CBDC4321", // utilkey
    "D7DBCE1AD4AFDCE1393E5121CBDC4321", // R11s CPH1719 MSM8976, Plus
    "D4D2CD61D4AFDCE13B5E01221BD14D20", // FindX CPH1871 SDM845
    "261CC7131D7C1481294E532DB752381E", // FindX
    "1CA21E12271335AE33AB81B2A7B14622", // Realme 2 pro SDM660/MSM8976
    "D4D2CE11D4AFDCE13B3E0121CBD14D20", // K1 SDM660/MSM8976
    "1C4C1EA3A12531AE491B21BB31613C11", // Realme 3 Pro SDM710, X, 5 Pro, Q, RMX1921 Realme XT
    "1C4C1EA3A12531AE4A1B21BB31C13C21", // Reno 10x zoom PCCM00 SDM855, CPH1921EX Reno 5G
    "1C4A11A3A12513AE441B23BB31513121", // Reno 2 PCKM00 SDM730G
    "1C4A11A3A12589AE441A23BB31517733", // Realme X2 SDM730G
    "1C4A11A3A22513AE541B53BB31513121", // Realme 5 SDM665
    "2442CE821A4F352E33AE81B22BC1462E", // R17 Pro SDM710
    "14C2CD6214CFDC2733AE81B22BC1462C", // CPH1803 OppoA3s / CPH1901 Oppo A7 SDM450
    "1E38C1B72D522E29E0D4ACD50ACFDCD6",
    "12341EAAC4C123CE193556A1BBCC232D",
    "2143DCCB21513E39E1DCAFD41ACEDBD7",
    "2D23CCBBA1563519CE23C1C4AA1E3412", // A77 CPH1715 MT6750T
    "172B3E14E46F3CE13E2B5121CBDC4321", // Realme 1 MTK P60
    "ACAA1E12A71431CE4A1B21BBA1C1C6A2", // Realme U1 RMX1831 MTK P70
    "ACAC1E13A72531AE4A1B22BB31C1CC22", // Realme 3 RMX1825EX P70
    "1C4411A3A12533AE441B21BB31613C11", // A1k CPH1923 MTK P22
    "1C4416A8A42717AE441523B336513121", // Reno 3 PCRM00 MTK 1000L, CPH2059 OPPO A92, CPH2067 OPPO A72
    "55EEAA33112133AE441B23BB31513121", // RenoAce SDM855Plus
    "ACAC1E13A12531AE4A1B21BB31C13C21", // Reno, K3
    "ACAC1E13A72431AE4A1B22BBA1C1C6A2", // A9
    "12CAC11211AAC3AEA2658690122C1E81", // A1, A83t
    "1CA21E12271435AE331B81BBA7C14612", // CPH1909 OppoA5s MT6765
    "D1DACF24351CE428A9CE32ED87323216", // Realme1(reserved)
    "A1CC75115CAECB890E4A563CA1AC67C8", // A73(reserved)
    "2132321EA2CA86621A11241ABA512722", // Realme3(reserved)
    "22A21E821743E5EE33AE81B227B1462E", // F3 Plus CPH1613 MSM8976
];

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyConfig {
    #[serde(default = "default_ozip_keys")]
    pub ozip_keys: Vec<String>,
    #[serde(default)]
    pub ofp_keysets: Vec<OfpKeyTriplet>,
}

fn default_ozip_keys() -> Vec<String> {
    DEFAULT_OZIP_KEYS.iter().map(|&s| s.to_string()).collect()
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            ozip_keys: default_ozip_keys(),
            ofp_keysets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OfpKeyTriplet {
    pub name: String,
    pub mc: String,
    pub userkey: String,
    pub ivec: String,
}

impl KeyConfig {
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("Failed to read key configuration from {}", path.display()))?;
            let mut cfg: KeyConfig = toml::from_str(&raw)
                .context("Failed to parse TOML key configuration")?;
            if cfg.ozip_keys.is_empty() {
                cfg.ozip_keys = default_ozip_keys();
            }
            Ok(cfg)
        } else {
            Ok(Self::default())
        }
    }
}

/// Swaps the upper and lower 4-bit nibbles of a byte:
/// Equivalent to Python: ((ch & 0xF) << 4) + ((ch & 0xF0) >> 4)
#[inline]
pub fn swap_nibbles(byte: u8) -> u8 {
    byte.rotate_left(4)
}

/// XORs two 16-byte buffers and swaps nibbles on every byte:
/// Equivalent to `keyshuffle(key, hkey)` in `ofp_qc_decrypt.py`
pub fn key_shuffle(key: &[u8; 16], hkey: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = swap_nibbles(hkey[i] ^ key[i]);
    }
    out
}

/// Derives the 16-byte AES key and 16-byte IV from an OFP key triplet
/// using the MD5 hex-prefix derivation from `ofp_qc_decrypt.py`.
pub fn derive_ofp_qc_key_iv(triplet: &OfpKeyTriplet) -> Result<([u8; 16], [u8; 16])> {
    let mc_bytes: [u8; 16] = hex::decode(&triplet.mc)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("mc must be 16 bytes (32 hex chars)"))?;
    let userkey_bytes: [u8; 16] = hex::decode(&triplet.userkey)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("userkey must be 16 bytes (32 hex chars)"))?;
    let ivec_bytes: [u8; 16] = hex::decode(&triplet.ivec)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("ivec must be 16 bytes (32 hex chars)"))?;

    let shuffled_key = key_shuffle(&userkey_bytes, &mc_bytes);
    let shuffled_iv = key_shuffle(&ivec_bytes, &mc_bytes);

    let key_md5_hex = format!("{:x}", Md5::digest(shuffled_key));
    let iv_md5_hex = format!("{:x}", Md5::digest(shuffled_iv));

    let mut aes_key = [0u8; 16];
    let mut aes_iv = [0u8; 16];
    aes_key.copy_from_slice(&key_md5_hex.as_bytes()[0..16]);
    aes_iv.copy_from_slice(&iv_md5_hex.as_bytes()[0..16]);

    Ok((aes_key, aes_iv))
}

pub fn hex_to_bytes(hex_str: &str) -> Option<[u8; 16]> {
    let clean = hex_str.trim();
    if clean.len() != 32 {
        return None;
    }
    let vec = hex::decode(clean).ok()?;
    vec.try_into().ok()
}

pub fn keytest(data: &[u8; 16], candidate_keys: &[String]) -> Option<[u8; 16]> {
    for key_hex in candidate_keys {
        if let Some(key_bytes) = hex_to_bytes(key_hex) {
            if let Ok(cipher) = Aes128::new_from_slice(&key_bytes) {
                let mut block = cipher::generic_array::GenericArray::clone_from_slice(data);
                cipher.decrypt_block(&mut block);
                let magic = &block[0..4];
                if magic == b"\x50\x4B\x03\x04" || magic == b"AVB0" || magic == b"ANDR" {
                    println!("[+] Found correct AES key: {}", key_hex);
                    return Some(key_bytes);
                }
            }
        }
    }
    None
}

pub fn decrypt_block(cipher: &Aes128, buf: &mut [u8; 16]) {
    let mut block = cipher::generic_array::GenericArray::clone_from_slice(buf);
    cipher.decrypt_block(&mut block);
    buf.copy_from_slice(&block);
}

pub fn decrypt_blocks(cipher: &Aes128, buf: &mut [u8]) {
    for chunk in buf.chunks_exact_mut(16) {
        let mut block = cipher::generic_array::GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
}
