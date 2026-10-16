use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use aes::Aes128;
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

const KEYS: [&str; 35] = [
    "D6EECF0AE5ACD4E0E9FE522DE7CE381E", // mnkey
    "D6ECCF0AE5ACD4E0E92E522DE7C1381E", // mkey
    "D6DCCF0AD5ACD4E0292E522DB7C1381E", // realkey, R9s CPH1607 MSM8953, Plus, R11, RMX1921 Realme XT, RMX1851EX Realme Android 10, RMX1992EX_11_OTA_1050
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
    "14C2CD6214CFDC2733AE81B22BC1462C", // CPH1803 OppoA3s SDM450/MSM8953
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
    "12CAC11211AAC3AEA2658690122C1E81", // A1,A83t
    "1CA21E12271435AE331B81BBA7C14612", // CPH1909 OppoA5s MT6765
    "D1DACF24351CE428A9CE32ED87323216", // Realme1(reserved)
    "A1CC75115CAECB890E4A563CA1AC67C8", // A73(reserved)
    "2132321EA2CA86621A11241ABA512722", // Realme3(reserved)
    "22A21E821743E5EE33AE81B227B1462E", // F3 Plus CPH1613 - MSM8976
];

fn hex_to_bytes(hex: &str) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    let b = hex.as_bytes();
    for i in 0..16 {
        let hi = match b[i * 2] {
            b'0'..=b'9' => b[i * 2] - b'0',
            b'a'..=b'f' => b[i * 2] - b'a' + 10,
            b'A'..=b'F' => b[i * 2] - b'A' + 10,
            _ => 0,
        };
        let lo = match b[i * 2 + 1] {
            b'0'..=b'9' => b[i * 2 + 1] - b'0',
            b'a'..=b'f' => b[i * 2 + 1] - b'a' + 10,
            b'A'..=b'F' => b[i * 2 + 1] - b'A' + 10,
            _ => 0,
        };
        bytes[i] = (hi << 4) | lo;
    }
    bytes
}

fn keytest(data: &[u8; 16]) -> Option<[u8; 16]> {
    for &key_hex in &KEYS {
        let key_bytes = hex_to_bytes(key_hex);
        let cipher = Aes128::new(&key_bytes.into());
        let mut block = (*data).into();
        cipher.decrypt_block(&mut block);
        let magic = &block[0..4];
        if magic == b"\x50\x4B\x03\x04" || magic == b"AVB0" || magic == b"ANDR" {
            println!("Found correct AES key: {}", key_hex);
            return Some(key_bytes);
        }
    }
    None
}

fn decrypt_block(cipher: &Aes128, buf: &mut [u8; 16]) {
    let mut block = (*buf).into();
    cipher.decrypt_block(&mut block);
    *buf = block.into();
}

fn decrypt_blocks(cipher: &Aes128, buf: &mut [u8]) {
    for chunk in buf.chunks_exact_mut(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let mut arr = block.into();
        cipher.decrypt_block(&mut arr);
        let out: [u8; 16] = arr.into();
        chunk.copy_from_slice(&out);
    }
}

fn read_full<R: Read>(reader: &mut R, mut buf: &mut [u8]) -> io::Result<usize> {
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

fn get_out_filename(input: &str) -> String {
    if input.len() >= 4 {
        format!("{}zip", &input[..input.len() - 4])
    } else {
        format!("{}.zip", input)
    }
}

fn decrypt_file_v1<R: Read, W: Write>(
    key: &[u8; 16],
    initial_magic: Option<&[u8; 12]>,
    reader: &mut R,
    file_size: u64,
    writer: &mut W,
) -> io::Result<()> {
    let cipher = Aes128::new(key.into());

    // Skip first 0x10 bytes (magic + padding)
    if initial_magic.is_some() {
        let mut pad = [0u8; 4];
        read_full(reader, &mut pad)?;
    } else {
        let mut header = [0u8; 16];
        read_full(reader, &mut header)?;
    }

    // Read 16 bytes dsize string at offset 0x10
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

fn decrypt_file_v2<R: Read, W: Write>(
    key: &[u8; 16],
    initial_header: Option<&[u8; 12]>,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<bool> {
    let cipher = Aes128::new(key.into());
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

        if header != b"OPPOENCRYPT!" {
            return Ok(false);
        }

        // Seek 0x10 + bstart: skip 4 bytes after 12-byte header
        let n = read_full(reader, &mut skip_buf[..4])?;
        if n < 4 {
            return Ok(false);
        }

        // Read 16 bytes bdsize string
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

        // Seek 0x50 + bstart: skip 48 bytes (from 0x20 to 0x50)
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

fn mode2(filename: &str) -> io::Result<i32> {
    println!("Finding key...  {}", filename);
    let file = File::open(filename)?;
    let mut archive = ZipArchive::new(BufReader::new(file))?;

    let mut key: Option<[u8; 16]> = None;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name()?.to_string();
        if name.contains("boot.img") {
            let mut magic = [0u8; 12];
            let n = read_full(&mut entry, &mut magic)?;
            if n == 12 && &magic == b"OPPOENCRYPT!" {
                // Seek to 0x50 (skip 0x50 - 12 = 68 bytes)
                io::copy(&mut entry.by_ref().take(68), &mut io::sink())?;
                let mut data = [0u8; 16];
                let n = read_full(&mut entry, &mut data)?;
                if n == 16 {
                    if let Some(k) = keytest(&data) {
                        key = Some(k);
                        break;
                    }
                }
            } else {
                println!("Unknown mode2, boot.img wasn't encrypted");
                return Ok(1);
            }
        }
    }

    let key = match key {
        Some(k) => k,
        None => {
            println!("Unknown AES key, reverse key from recovery first!");
            return Ok(1);
        }
    };

    println!("Extracting...  {}", filename);
    let outzip = get_out_filename(filename);
    let out_file = File::create(&outzip)?;
    let mut writer = ZipWriter::new(BufWriter::new(out_file));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::DEFLATE);

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let orgfilename = entry.name()?.to_string();

        if entry.is_dir() {
            writer.add_directory(&orgfilename, options)?;
            continue;
        }

        let mut magic = [0u8; 12];
        let n = read_full(&mut entry, &mut magic)?;
        if n == 12 && &magic == b"OPPOENCRYPT!" {
            println!("Decrypting {}", orgfilename);
            writer.start_file(&orgfilename, options)?;
            if !decrypt_file_v2(&key, Some(&magic), &mut entry, &mut writer)? {
                return Ok(1);
            }
        } else {
            writer.start_file(&orgfilename, options)?;
            if n > 0 {
                writer.write_all(&magic[..n])?;
            }
            io::copy(&mut entry, &mut writer)?;
        }
    }

    writer.finish()?;
    println!("DONE... file decrypted to: {}", outzip);
    Ok(0)
}

fn run(filename: &str) -> io::Result<i32> {
    println!("ozipdecrypt 1.32 (c) B.Kerler 2017-2022");

    let mut file = File::open(filename)?;
    let mut magic = [0u8; 12];
    let n = file.read(&mut magic)?;
    if n < 12 {
        println!("ozip has unknown magic, OPPOENCRYPT! expected!");
        return Ok(1);
    }

    let pk = if &magic == b"OPPOENCRYPT!" {
        false
    } else if &magic[0..2] == b"PK" {
        true
    } else {
        println!("ozip has unknown magic, OPPOENCRYPT! expected!");
        return Ok(1);
    };

    if !pk {
        file.seek(SeekFrom::Start(0x1050))?;
        let mut data = [0u8; 16];
        file.read_exact(&mut data)?;
        let key = match keytest(&data) {
            Some(k) => k,
            None => {
                println!("Unknown AES key, reverse key from recovery first!");
                return Ok(1);
            }
        };

        let cipher = Aes128::new((&key).into());
        let out_filename = get_out_filename(filename);
        let out_file = File::create(&out_filename)?;
        let mut wf = BufWriter::new(out_file);
        let mut fr = BufReader::new(file);

        fr.seek(SeekFrom::Start(0x1050))?;
        println!("Decrypting...");

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
        println!("DONE!!");
        Ok(0)
    } else {
        // Zip mode 1
        let mut archive = match ZipArchive::new(BufReader::new(file)) {
            Ok(a) => a,
            Err(_) => {
                return mode2(filename);
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
            println!("'There is no item named \\'oppo_metadata\\' in the archive'");
            println!("Detected mode 2....");
            return mode2(filename);
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
            println!("Unknown image, please report an issue with image name!");
            return Ok(1);
        }

        let key = {
            let mut vbmeta = archive.by_name(&fname)?;
            // Seek to 0x1050
            io::copy(&mut vbmeta.by_ref().take(0x1050), &mut io::sink())?;
            let mut data = [0u8; 16];
            let n = read_full(&mut vbmeta, &mut data)?;
            if n < 16 {
                println!("Unknown AES key, reverse key from recovery first!");
                return Ok(1);
            }
            match keytest(&data) {
                Some(k) => k,
                None => {
                    println!("Unknown AES key, reverse key from recovery first!");
                    return Ok(1);
                }
            }
        };

        let outzip = get_out_filename(filename);
        let out_file = File::create(&outzip)?;
        let mut writer = ZipWriter::new(BufWriter::new(out_file));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::DEFLATE);

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let orgfilename = entry.name()?.to_string();
            println!("Extracting {}", orgfilename);

            if entry.is_dir() {
                writer.add_directory(&orgfilename, options)?;
                continue;
            }

            let file_size = entry.size();
            if !clist.is_empty() {
                if clist.contains(&orgfilename) {
                    println!("Decrypting {}", orgfilename);
                    writer.start_file(&orgfilename, options)?;
                    decrypt_file_v1(&key, None, &mut entry, file_size, &mut writer)?;
                } else {
                    writer.start_file(&orgfilename, options)?;
                    io::copy(&mut entry, &mut writer)?;
                }
            } else {
                let mut magic = [0u8; 12];
                let n = read_full(&mut entry, &mut magic)?;
                if n == 12 && &magic == b"OPPOENCRYPT!" {
                    println!("Decrypting {}", orgfilename);
                    writer.start_file(&orgfilename, options)?;
                    decrypt_file_v1(&key, Some(&magic), &mut entry, file_size, &mut writer)?;
                } else {
                    writer.start_file(&orgfilename, options)?;
                    if n > 0 {
                        writer.write_all(&magic[..n])?;
                    }
                    io::copy(&mut entry, &mut writer)?;
                }
            }
        }

        writer.finish()?;
        println!("DONE... files decrypted to: {}", outzip);
        Ok(0)
    }
}

fn print_help() {
    println!("ozipdecrypt 1.3 (c) B.Kerler 2017-2021\n");
    println!("Usage:\n    ozipdecrypt [options] <filename>\n");
    println!("Required:\n    <filename>    Path to ozip file\n");
    println!("Optional:\n    -h, --help    Show this help message and exit");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        std::process::exit(1);
    }

    if args[1] == "-h" || args[1] == "--help" {
        print_help();
        std::process::exit(0);
    }

    let filename = &args[1];
    if !Path::new(filename).exists() {
        eprintln!("Error: File not found: {}", filename);
        std::process::exit(1);
    }

    match run(filename) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockCipherEncrypt;
    use std::io::Cursor;

    #[test]
    fn test_hex_to_bytes() {
        let hex = "D6EECF0AE5ACD4E0E9FE522DE7CE381E";
        let bytes = hex_to_bytes(hex);
        assert_eq!(
            bytes,
            [
                0xD6, 0xEE, 0xCF, 0x0A, 0xE5, 0xAC, 0xD4, 0xE0,
                0xE9, 0xFE, 0x52, 0x2D, 0xE7, 0xCE, 0x38, 0x1E
            ]
        );
    }

    #[test]
    fn test_keytest_detection() {
        let key_hex = KEYS[2]; // realkey
        let key = hex_to_bytes(key_hex);
        let cipher = Aes128::new((&key).into());

        // Test ZIP magic PK\x03\x04
        let mut block = [0u8; 16];
        block[0..4].copy_from_slice(b"\x50\x4B\x03\x04");
        block[4..8].copy_from_slice(b"TEST");
        let mut enc_block = block.into();
        cipher.encrypt_block(&mut enc_block);
        let enc_bytes: [u8; 16] = enc_block.into();

        let found = keytest(&enc_bytes);
        assert_eq!(found, Some(key));

        // Test AVB0 magic
        let mut block_avb = [0u8; 16];
        block_avb[0..4].copy_from_slice(b"AVB0");
        let mut enc_avb = block_avb.into();
        cipher.encrypt_block(&mut enc_avb);
        let enc_avb_bytes: [u8; 16] = enc_avb.into();
        assert_eq!(keytest(&enc_avb_bytes), Some(key));

        // Test ANDR magic
        let mut block_andr = [0u8; 16];
        block_andr[0..4].copy_from_slice(b"ANDR");
        let mut enc_andr = block_andr.into();
        cipher.encrypt_block(&mut enc_andr);
        let enc_andr_bytes: [u8; 16] = enc_andr.into();
        assert_eq!(keytest(&enc_andr_bytes), Some(key));
    }

    #[test]
    fn test_mode1_decrypt_file() {
        let key = hex_to_bytes(KEYS[0]);
        let cipher = Aes128::new((&key).into());

        let original_data = b"Hello, this is original unencrypted firmware data! It can be arbitrary bytes.";
        let dsize = original_data.len();

        // Build Mode 1 encrypted format:
        // 0..0x10: b"OPPOENCRYPT!\0\0\0\0"
        // 0x10..0x20: dsize as string, null padded
        // 0x20..0x1050: 4144 bytes padding
        // 0x1050..: encrypted data in blocks of 16
        let mut enc = Vec::new();
        enc.extend_from_slice(b"OPPOENCRYPT!\0\0\0\0");
        let dsize_str = format!("{}", dsize);
        let mut dsize_field = [0u8; 16];
        dsize_field[..dsize_str.len()].copy_from_slice(dsize_str.as_bytes());
        enc.extend_from_slice(&dsize_field);
        enc.resize(0x1050, 0xAA);

        // Pad original data to 16 bytes
        let mut padded = original_data.to_vec();
        while padded.len() % 16 != 0 {
            padded.push(0);
        }
        for chunk in padded.chunks_exact(16) {
            let b: [u8; 16] = chunk.try_into().unwrap();
            let mut arr = b.into();
            cipher.encrypt_block(&mut arr);
            let out: [u8; 16] = arr.into();
            enc.extend_from_slice(&out);
        }

        let mut reader = Cursor::new(&enc);
        let mut decrypted = Vec::new();
        decrypt_file_v1(&key, None, &mut reader, enc.len() as u64, &mut decrypted).unwrap();

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_mode2_decrypt_file() {
        let key = hex_to_bytes(KEYS[1]);
        let cipher = Aes128::new((&key).into());

        // Make data larger than 16 bytes to test both AES and plain parts
        let mut original_data = Vec::new();
        for i in 0..1000 {
            original_data.extend_from_slice(format!("Line {} of data\n", i).as_bytes());
        }
        let bdsize = original_data.len();

        // Build Mode 2 encrypted chunk:
        // 0..12: "OPPOENCRYPT!"
        // 12..16: 4 bytes padding
        // 16..32: bdsize string
        // 32..80: 48 bytes padding
        // 80..: 16 bytes encrypted + up to 0x3FF0 bytes plaintext
        let mut enc = Vec::new();
        enc.extend_from_slice(b"OPPOENCRYPT!");
        enc.extend_from_slice(&[0u8; 4]);
        let bdsize_str = format!("{}", bdsize);
        let mut bdsize_field = [0u8; 16];
        bdsize_field[..bdsize_str.len()].copy_from_slice(bdsize_str.as_bytes());
        enc.extend_from_slice(&bdsize_field);
        enc.extend_from_slice(&[0u8; 48]);

        // Mode 2 chunk payload: every 0x4000 sub-chunk has first 16 bytes encrypted
        let mut offset = 0;
        while offset < original_data.len() {
            let chunk_end = std::cmp::min(offset + 0x4000, original_data.len());
            let sub = &original_data[offset..chunk_end];
            if sub.len() <= 16 {
                let mut b = [0u8; 16];
                b[..sub.len()].copy_from_slice(sub);
                let mut arr = b.into();
                cipher.encrypt_block(&mut arr);
                let out: [u8; 16] = arr.into();
                enc.extend_from_slice(&out[..sub.len()]);
            } else {
                let mut b = [0u8; 16];
                b.copy_from_slice(&sub[..16]);
                let mut arr = b.into();
                cipher.encrypt_block(&mut arr);
                let out: [u8; 16] = arr.into();
                enc.extend_from_slice(&out);
                enc.extend_from_slice(&sub[16..]);
            }
            offset += 0x4000;
        }

        let mut reader = Cursor::new(&enc);
        let mut decrypted = Vec::new();
        let ok = decrypt_file_v2(&key, None, &mut reader, &mut decrypted).unwrap();
        assert!(ok);
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_e2e_single_file_mode() {
        let dir = env::temp_dir().join("ozip_test_single");
        let _ = std::fs::create_dir_all(&dir);
        let ozip_path = dir.join("test_fw.ozip");
        let zip_path = dir.join("test_fw.zip");
        let _ = std::fs::remove_file(&ozip_path);
        let _ = std::fs::remove_file(&zip_path);

        let key = hex_to_bytes(KEYS[0]);
        let cipher = Aes128::new((&key).into());

        // Single file format:
        // 0..12: "OPPOENCRYPT!"
        // padded to 0x1050
        // at 0x1050: 16 bytes encrypted (starts with PK\x03\x04), then up to 0x4000 plain
        let mut file_content = Vec::new();
        file_content.extend_from_slice(b"OPPOENCRYPT!");
        file_content.resize(0x1050, 0);

        let mut block = [0u8; 16];
        block[0..4].copy_from_slice(b"\x50\x4B\x03\x04");
        block[4..16].copy_from_slice(b"MYTESTHEADER");
        let mut arr = block.into();
        cipher.encrypt_block(&mut arr);
        let enc_block: [u8; 16] = arr.into();
        file_content.extend_from_slice(&enc_block);
        file_content.extend_from_slice(b"PLAINTEXT_PAYLOAD_DATA");

        std::fs::write(&ozip_path, &file_content).unwrap();

        let res = run(ozip_path.to_str().unwrap()).unwrap();
        assert_eq!(res, 0);

        let decrypted = std::fs::read(&zip_path).unwrap();
        assert_eq!(&decrypted[0..4], b"\x50\x4B\x03\x04");
        assert_eq!(&decrypted[4..16], b"MYTESTHEADER");
        assert_eq!(&decrypted[16..], b"PLAINTEXT_PAYLOAD_DATA");

        let _ = std::fs::remove_file(&ozip_path);
        let _ = std::fs::remove_file(&zip_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_e2e_zip_mode1() {
        let dir = env::temp_dir().join("ozip_test_mode1");
        let _ = std::fs::create_dir_all(&dir);
        let ozip_path = dir.join("update_mode1.ozip");
        let zip_path = dir.join("update_mode1.zip");
        let _ = std::fs::remove_file(&ozip_path);
        let _ = std::fs::remove_file(&zip_path);

        let key = hex_to_bytes(KEYS[2]);
        let cipher = Aes128::new((&key).into());

        // Create encrypted vbmeta.img
        let raw_vbmeta = b"AVB0_RAW_VBMETA_PAYLOAD_BYTES_FOR_TESTING";
        let mut enc_vbmeta = Vec::new();
        enc_vbmeta.extend_from_slice(b"OPPOENCRYPT!\0\0\0\0");
        let dsize_str = format!("{}", raw_vbmeta.len());
        let mut dsize_field = [0u8; 16];
        dsize_field[..dsize_str.len()].copy_from_slice(dsize_str.as_bytes());
        enc_vbmeta.extend_from_slice(&dsize_field);
        enc_vbmeta.resize(0x1050, 0x55);

        let mut padded = raw_vbmeta.to_vec();
        while padded.len() % 16 != 0 {
            padded.push(0);
        }
        for chunk in padded.chunks_exact(16) {
            let b: [u8; 16] = chunk.try_into().unwrap();
            let mut arr = b.into();
            cipher.encrypt_block(&mut arr);
            let out: [u8; 16] = arr.into();
            enc_vbmeta.extend_from_slice(&out);
        }

        // Create the zip archive
        {
            let file = File::create(&ozip_path).unwrap();
            let mut zw = ZipWriter::new(file);
            let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::STORE);

            // Entry 1: oppo_metadata
            zw.start_file("oppo_metadata", options).unwrap();
            zw.write_all(b"vbmeta.img\n").unwrap();

            // Entry 2: vbmeta.img
            zw.start_file("vbmeta.img", options).unwrap();
            zw.write_all(&enc_vbmeta).unwrap();

            // Entry 3: unencrypted plain file
            zw.start_file("plain.txt", options).unwrap();
            zw.write_all(b"Plain text in mode1 zip").unwrap();

            zw.finish().unwrap();
        }

        let res = run(ozip_path.to_str().unwrap()).unwrap();
        assert_eq!(res, 0);

        // Verify output zip
        {
            let file = File::open(&zip_path).unwrap();
            let mut za = ZipArchive::new(file).unwrap();

            {
                let mut vbmeta_entry = za.by_name("vbmeta.img").unwrap();
                let mut vbmeta_content = Vec::new();
                vbmeta_entry.read_to_end(&mut vbmeta_content).unwrap();
                assert_eq!(vbmeta_content, raw_vbmeta);
            }

            {
                let mut plain_entry = za.by_name("plain.txt").unwrap();
                let mut plain_content = String::new();
                plain_entry.read_to_string(&mut plain_content).unwrap();
                assert_eq!(plain_content, "Plain text in mode1 zip");
            }
        }

        let _ = std::fs::remove_file(&ozip_path);
        let _ = std::fs::remove_file(&zip_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_e2e_zip_mode2() {
        let dir = env::temp_dir().join("ozip_test_mode2");
        let _ = std::fs::create_dir_all(&dir);
        let ozip_path = dir.join("cph1803_ota.ozip");
        let zip_path = dir.join("cph1803_ota.zip");
        let _ = std::fs::remove_file(&ozip_path);
        let _ = std::fs::remove_file(&zip_path);

        let key = hex_to_bytes(KEYS[16]); // CPH1803 key
        let cipher = Aes128::new((&key).into());

        // Create boot.img encrypted in Mode 2 format
        let raw_boot = b"ANDR_BOOT_IMAGE_HEADER_TEST_PAYLOAD_HERE";
        let mut enc_boot = Vec::new();
        enc_boot.extend_from_slice(b"OPPOENCRYPT!");
        enc_boot.extend_from_slice(&[0u8; 4]);
        let bdsize_str = format!("{}", raw_boot.len());
        let mut bdsize_field = [0u8; 16];
        bdsize_field[..bdsize_str.len()].copy_from_slice(bdsize_str.as_bytes());
        enc_boot.extend_from_slice(&bdsize_field);
        enc_boot.extend_from_slice(&[0u8; 48]); // Pad to 0x50

        // Encrypt first 16 bytes with AES-ECB
        let mut first16 = [0u8; 16];
        first16.copy_from_slice(&raw_boot[..16]);
        let mut arr = first16.into();
        cipher.encrypt_block(&mut arr);
        let out: [u8; 16] = arr.into();
        enc_boot.extend_from_slice(&out);
        enc_boot.extend_from_slice(&raw_boot[16..]);

        // Create the zip archive without oppo_metadata
        {
            let file = File::create(&ozip_path).unwrap();
            let mut zw = ZipWriter::new(file);
            let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::STORE);

            // Entry 1: boot.img
            zw.start_file("boot.img", options).unwrap();
            zw.write_all(&enc_boot).unwrap();

            // Entry 2: unencrypted plain file
            zw.start_file("readme.txt", options).unwrap();
            zw.write_all(b"CPH1803 unencrypted notes").unwrap();

            zw.finish().unwrap();
        }

        let res = run(ozip_path.to_str().unwrap()).unwrap();
        assert_eq!(res, 0);

        // Verify output zip
        {
            let file = File::open(&zip_path).unwrap();
            let mut za = ZipArchive::new(file).unwrap();

            {
                let mut boot_entry = za.by_name("boot.img").unwrap();
                let mut boot_content = Vec::new();
                boot_entry.read_to_end(&mut boot_content).unwrap();
                assert_eq!(boot_content, raw_boot);
            }

            {
                let mut readme_entry = za.by_name("readme.txt").unwrap();
                let mut readme_content = String::new();
                readme_entry.read_to_string(&mut readme_content).unwrap();
                assert_eq!(readme_content, "CPH1803 unencrypted notes");
            }
        }

        let _ = std::fs::remove_file(&ozip_path);
        let _ = std::fs::remove_file(&zip_path);
        let _ = std::fs::remove_dir(&dir);
    }
}
