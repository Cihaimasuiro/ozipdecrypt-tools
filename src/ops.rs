use anyhow::{bail, Context, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const MASTER_KEY: [u32; 4] = [0x9EE3B5D1, 0x9D04EA5E, 0xABD51D67, 0xAFCBD2BA];

pub const MBOX5: [u32; 62] = [
    0x60, 0x8a, 0x3f, 0x2d, 0x68, 0x6b, 0xd4, 0x23, 0x51, 0x0c, 0xd0, 0x95, 0xbb, 0x40, 0xe9,
    0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00,
];

pub const MBOX6: [u32; 62] = [
    0xAA, 0x69, 0x82, 0x9E, 0x5D, 0xDE, 0xB1, 0x3D, 0x30, 0xBB, 0x81, 0xA3, 0x46, 0x65, 0xa3,
    0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00,
];

pub const MBOX4: [u32; 62] = [
    0xC4, 0x5D, 0x05, 0x71, 0x99, 0xDD, 0xBB, 0xEE, 0x29, 0xA1, 0x6D, 0xC7, 0xAD, 0xBF, 0xA4,
    0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00,
];

pub const SBOX_HEX: &str = concat!(
    "c66363a5c66363a5f87c7c84f87c7c84ee777799ee777799f67b7b8df67b7b8d",
    "fff2f20dfff2f20dd66b6bbdd66b6bbdde6f6fb1de6f6fb191c5c55491c5c554",
    "60303050603030500201010302010103ce6767a9ce6767a9562b2b7d562b2b7d",
    "e7fefe19e7fefe19b5d7d762b5d7d7624dababe64dababe6ec76769aec76769a",
    "8fcaca458fcaca451f82829d1f82829d89c9c94089c9c940fa7d7d87fa7d7d87",
    "effafa15effafa15b25959ebb25959eb8e4747c98e4747c9fbf0f00bfbf0f00b",
    "41adadec41adadecb3d4d467b3d4d4675fa2a2fd5fa2a2fd45afafea45afafea",
    "239c9cbf239c9cbf53a4a4f753a4a4f7e4727296e47272969bc0c05b9bc0c05b",
    "75b7b7c275b7b7c2e1fdfd1ce1fdfd1c3d9393ae3d9393ae4c26266a4c26266a",
    "6c36365a6c36365a7e3f3f417e3f3f41f5f7f702f5f7f70283cccc4f83cccc4f",
    "6834345c6834345c51a5a5f451a5a5f4d1e5e534d1e5e534f9f1f108f9f1f108",
    "e2717193e2717193abd8d873abd8d87362313153623131532a15153f2a15153f",
    "0804040c0804040c95c7c75295c7c75246232365462323659dc3c35e9dc3c35e",
    "3018182830181828379696a1379696a10a05050f0a05050f2f9a9ab52f9a9ab5",
    "0e0707090e07070924121236241212361b80809b1b80809bdfe2e23ddfe2e23d",
    "cdebeb26cdebeb264e2727694e2727697fb2b2cd7fb2b2cdea75759fea75759f",
    "1209091b1209091b1d83839e1d83839e582c2c74582c2c74341a1a2e341a1a2e",
    "361b1b2d361b1b2ddc6e6eb2dc6e6eb2b45a5aeeb45a5aee5ba0a0fb5ba0a0fb",
    "a45252f6a45252f6763b3b4d763b3b4db7d6d661b7d6d6617db3b3ce7db3b3ce",
    "5229297b5229297bdde3e33edde3e33e5e2f2f715e2f2f711384849713848497",
    "a65353f5a65353f5b9d1d168b9d1d1680000000000000000c1eded2cc1eded2c",
    "4020206040202060e3fcfc1fe3fcfc1f79b1b1c879b1b1c8b65b5bedb65b5bed",
    "d46a6abed46a6abe8dcbcb468dcbcb4667bebed967bebed97239394b7239394b",
    "944a4ade944a4ade984c4cd4984c4cd4b05858e8b05858e885cfcf4a85cfcf4a",
    "bbd0d06bbbd0d06bc5efef2ac5efef2a4faaaae54faaaae5edfbfb16edfbfb16",
    "864343c5864343c59a4d4dd79a4d4dd766333355663333551185859411858594",
    "8a4545cf8a4545cfe9f9f910e9f9f9100402020604020206fe7f7f81fe7f7f81",
    "a05050f0a05050f0783c3c44783c3c44259f9fba259f9fba4ba8a8e34ba8a8e3",
    "a25151f3a25151f35da3a3fe5da3a3fe804040c0804040c0058f8f8a058f8f8a",
    "3f9292ad3f9292ad219d9dbc219d9dbc7038384870383848f1f5f504f1f5f504",
    "63bcbcdf63bcbcdf77b6b6c177b6b6c1afdada75afdada754221216342212163",
    "2010103020101030e5ffff1ae5ffff1afdf3f30efdf3f30ebfd2d26dbfd2d26d",
    "81cdcd4c81cdcd4c180c0c14180c0c142613133526131335c3ecec2fc3ecec2f",
    "be5f5fe1be5f5fe1359797a2359797a2884444cc884444cc2e1717392e171739",
    "93c4c45793c4c45755a7a7f255a7a7f2fc7e7e82fc7e7e827a3d3d477a3d3d47",
    "c86464acc86464acba5d5de7ba5d5de73219192b3219192be6737395e6737395",
    "c06060a0c06060a019818198198181989e4f4fd19e4f4fd1a3dcdc7fa3dcdc7f",
    "4422226644222266542a2a7e542a2a7e3b9090ab3b9090ab0b8888830b888883",
    "8c4646ca8c4646cac7eeee29c7eeee296bb8b8d36bb8b8d32814143c2814143c",
    "a7dede79a7dede79bc5e5ee2bc5e5ee2160b0b1d160b0b1daddbdb76addbdb76",
    "dbe0e03bdbe0e03b6432325664323256743a3a4e743a3a4e140a0a1e140a0a1e",
    "924949db924949db0c06060a0c06060a4824246c4824246cb85c5ce4b85c5ce4",
    "9fc2c25d9fc2c25dbdd3d36ebdd3d36e43acacef43acacefc46262a6c46262a6",
    "399191a8399191a8319595a4319595a4d3e4e437d3e4e437f279798bf279798b",
    "d5e7e732d5e7e7328bc8c8438bc8c8436e3737596e373759da6d6db7da6d6db7",
    "018d8d8c018d8d8cb1d5d564b1d5d5649c4e4ed29c4e4ed249a9a9e049a9a9e0",
    "d86c6cb4d86c6cb4ac5656faac5656faf3f4f407f3f4f407cfeaea25cfeaea25",
    "ca6565afca6565aff47a7a8ef47a7a8e47aeaee947aeaee91008081810080818",
    "6fbabad56fbabad5f0787888f07878884a25256f4a25256f5c2e2e725c2e2e72",
    "381c1c24381c1c2457a6a6f157a6a6f173b4b4c773b4b4c797c6c65197c6c651",
    "cbe8e823cbe8e823a1dddd7ca1dddd7ce874749ce874749c3e1f1f213e1f1f21",
    "964b4bdd964b4bdd61bdbddc61bdbddc0d8b8b860d8b8b860f8a8a850f8a8a85",
    "e0707090e07070907c3e3e427c3e3e4271b5b5c471b5b5c4cc6666aacc6666aa",
    "904848d8904848d80603030506030305f7f6f601f7f6f6011c0e0e121c0e0e12",
    "c26161a3c26161a36a35355f6a35355fae5757f9ae5757f969b9b9d069b9b9d0",
    "178686911786869199c1c15899c1c1583a1d1d273a1d1d27279e9eb9279e9eb9",
    "d9e1e138d9e1e138ebf8f813ebf8f8132b9898b32b9898b32211113322111133",
    "d26969bbd26969bba9d9d970a9d9d970078e8e89078e8e89339494a7339494a7",
    "2d9b9bb62d9b9bb63c1e1e223c1e1e221587879215878792c9e9e920c9e9e920",
    "87cece4987cece49aa5555ffaa5555ff5028287850282878a5dfdf7aa5dfdf7a",
    "038c8c8f038c8c8f59a1a1f859a1a1f809898980098989801a0d0d171a0d0d17",
    "65bfbfda65bfbfdad7e6e631d7e6e631844242c6844242c6d06868b8d06868b8",
    "824141c3824141c3299999b0299999b05a2d2d775a2d2d771e0f0f111e0f0f11",
    "7bb0b0cb7bb0b0cba85454fca85454fc6dbbbbd66dbbbbd62c16163a2c16163a"
);

fn gsbox(sbox: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(sbox[offset..offset + 4].try_into().unwrap())
}

pub fn key_update(iv1: [u32; 4], asbox: &[u32], sbox: &[u8]) -> [u32; 4] {
    let mut d = iv1[0] ^ asbox[0];
    let mut a = iv1[1] ^ asbox[1];
    let b = iv1[2] ^ asbox[2];
    let c = iv1[3] ^ asbox[3];

    let mut e = gsbox(sbox, (((b >> 0x10) & 0xff) * 8 + 2) as usize)
        ^ gsbox(sbox, (((a >> 8) & 0xff) * 8 + 3) as usize)
        ^ gsbox(sbox, ((c >> 0x18) * 8 + 1) as usize)
        ^ gsbox(sbox, ((d & 0xff) * 8) as usize)
        ^ asbox[4];

    let mut h = gsbox(sbox, (((c >> 0x10) & 0xff) * 8 + 2) as usize)
        ^ gsbox(sbox, (((b >> 8) & 0xff) * 8 + 3) as usize)
        ^ gsbox(sbox, ((d >> 0x18) * 8 + 1) as usize)
        ^ gsbox(sbox, ((a & 0xff) * 8) as usize)
        ^ asbox[5];

    let mut i = gsbox(sbox, (((d >> 0x10) & 0xff) * 8 + 2) as usize)
        ^ gsbox(sbox, (((c >> 8) & 0xff) * 8 + 3) as usize)
        ^ gsbox(sbox, ((a >> 0x18) * 8 + 1) as usize)
        ^ gsbox(sbox, ((b & 0xff) * 8) as usize)
        ^ asbox[6];

    a = gsbox(sbox, (((d >> 8) & 0xff) * 8 + 3) as usize)
        ^ gsbox(sbox, (((a >> 0x10) & 0xff) * 8 + 2) as usize)
        ^ gsbox(sbox, ((b >> 0x18) * 8 + 1) as usize)
        ^ gsbox(sbox, ((c & 0xff) * 8) as usize)
        ^ asbox[7];

    let mut g = 8;
    let rounds = (asbox[0x3c] - 2) as usize;

    for _ in 0..rounds {
        d = e >> 0x18;
        let m = h >> 0x10;
        let s = h >> 0x18;
        let z = e >> 0x10;
        let l = i >> 0x18;
        let t = e >> 8;

        e = gsbox(sbox, (((i >> 0x10) & 0xff) * 8 + 2) as usize)
            ^ gsbox(sbox, (((h >> 8) & 0xff) * 8 + 3) as usize)
            ^ gsbox(sbox, ((a >> 0x18) * 8 + 1) as usize)
            ^ gsbox(sbox, ((e & 0xff) * 8) as usize)
            ^ asbox[g];

        h = gsbox(sbox, (((a >> 0x10) & 0xff) * 8 + 2) as usize)
            ^ gsbox(sbox, (((i >> 8) & 0xff) * 8 + 3) as usize)
            ^ gsbox(sbox, (d * 8 + 1) as usize)
            ^ gsbox(sbox, ((h & 0xff) * 8) as usize)
            ^ asbox[g + 1];

        i = gsbox(sbox, ((z & 0xff) * 8 + 2) as usize)
            ^ gsbox(sbox, (((a >> 8) & 0xff) * 8 + 3) as usize)
            ^ gsbox(sbox, (s * 8 + 1) as usize)
            ^ gsbox(sbox, ((i & 0xff) * 8) as usize)
            ^ asbox[g + 2];

        a = gsbox(sbox, ((t & 0xff) * 8 + 3) as usize)
            ^ gsbox(sbox, ((m & 0xff) * 8 + 2) as usize)
            ^ gsbox(sbox, (l * 8 + 1) as usize)
            ^ gsbox(sbox, ((a & 0xff) * 8) as usize)
            ^ asbox[g + 3];

        g += 4;
    }

    [
        (gsbox(sbox, (((i >> 0x10) & 0xff) * 8) as usize) & 0xff0000)
            ^ (gsbox(sbox, (((h >> 8) & 0xff) * 8 + 1) as usize) & 0xff00)
            ^ (gsbox(sbox, ((a >> 0x18) * 8 + 3) as usize) & 0xff000000)
            ^ (gsbox(sbox, ((e & 0xff) * 8 + 2) as usize) & 0xFF)
            ^ asbox[g],
        (gsbox(sbox, (((a >> 0x10) & 0xff) * 8) as usize) & 0xff0000)
            ^ (gsbox(sbox, (((i >> 8) & 0xff) * 8 + 1) as usize) & 0xff00)
            ^ (gsbox(sbox, ((e >> 0x18) * 8 + 3) as usize) & 0xff000000)
            ^ (gsbox(sbox, ((h & 0xff) * 8 + 2) as usize) & 0xFF)
            ^ asbox[g + 3],
        (gsbox(sbox, (((e >> 0x10) & 0xff) * 8) as usize) & 0xff0000)
            ^ (gsbox(sbox, (((a >> 8) & 0xff) * 8 + 1) as usize) & 0xff00)
            ^ (gsbox(sbox, ((h >> 0x18) * 8 + 3) as usize) & 0xff000000)
            ^ (gsbox(sbox, ((i & 0xff) * 8 + 2) as usize) & 0xFF)
            ^ asbox[g + 2],
        (gsbox(sbox, (((h >> 0x10) & 0xff) * 8) as usize) & 0xff0000)
            ^ (gsbox(sbox, (((e >> 8) & 0xff) * 8 + 1) as usize) & 0xff00)
            ^ (gsbox(sbox, ((i >> 0x18) * 8 + 3) as usize) & 0xff000000)
            ^ (gsbox(sbox, ((a & 0xff) * 8 + 2) as usize) & 0xFF)
            ^ asbox[g + 1],
    ]
}

pub fn key_custom_decrypt(inp: &[u8], mut rkey: [u32; 4], mbox: &[u32], sbox: &[u8]) -> Vec<u8> {
    let mut outp = Vec::with_capacity(inp.len());
    let mut ptr = 0;
    let mut remaining = inp.len();

    while remaining >= 16 {
        rkey = key_update(rkey, mbox, sbox);
        let mut cipher_words = [0u32; 4];
        for i in 0..4 {
            let offset = ptr + i * 4;
            cipher_words[i] = u32::from_le_bytes(inp[offset..offset + 4].try_into().unwrap());
            let plain_word = cipher_words[i] ^ rkey[i];
            outp.extend_from_slice(&plain_word.to_le_bytes());
        }
        rkey = cipher_words;
        ptr += 16;
        remaining -= 16;
    }

    if remaining > 0 {
        rkey = key_update(rkey, mbox, sbox);
        let mut j = ptr;
        let mut m = 0;
        while remaining > 0 {
            let take = std::cmp::min(remaining, 4);
            let mut chunk = [0u8; 4];
            chunk[..take].copy_from_slice(&inp[j..j + take]);
            let cipher_word = u32::from_le_bytes(chunk);
            let plain_word = cipher_word ^ rkey[m];
            outp.extend_from_slice(&plain_word.to_le_bytes()[..take]);
            j += take;
            remaining -= take;
            m += 1;
        }
    }

    outp
}

#[derive(Debug)]
pub struct OpsPartitionItem {
    pub filename: String,
    pub start: u64,
    pub length: u64,
    pub sha256: String,
    pub is_encrypted: bool,
}

pub fn extract_ops(ops_path: &Path, out_dir: &Path, target_partition: Option<&str>) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    let mut file = File::open(ops_path)
        .with_context(|| format!("Failed to open OnePlus OPS archive: {}", ops_path.display()))?;
    let file_size = file.metadata()?.len();

    let sbox_bytes = hex::decode(SBOX_HEX)?;

    let (xml_str, matched_mbox) = extract_ops_xml(&mut file, file_size, &sbox_bytes)
        .context("Failed to decrypt XML partition manifest from OPS container.")?;

    let settings_path = out_dir.join("settings.xml");
    fs::write(&settings_path, &xml_str)?;
    println!("[+] Saved decrypted OPS manifest to {}", settings_path.display());

    let items = parse_ops_xml(&xml_str)?;
    println!("[+] Found {} partition items in OPS archive.", items.len());

    let mut extracted_count = 0;
    for item in &items {
        if let Some(target) = target_partition {
            let target_lower = target.to_lowercase();
            let file_lower = item.filename.to_lowercase();
            if !file_lower.contains(&target_lower) {
                continue;
            }
        }

        println!(
            "[*] Extracting \"{}\" (size: {} bytes, encrypted: {})...",
            item.filename, item.length, item.is_encrypted
        );

        let out_file_path = out_dir.join(&item.filename);
        if let Some(parent) = out_file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        file.seek(SeekFrom::Start(item.start))?;
        let mut out = File::create(&out_file_path)
            .with_context(|| format!("Failed to create {}", out_file_path.display()))?;

        if item.is_encrypted {
            // Decrypt using key_custom_decrypt
            let mut buf = vec![0u8; item.length as usize];
            file.read_exact(&mut buf)?;
            let plain = key_custom_decrypt(&buf, MASTER_KEY, matched_mbox, &sbox_bytes);
            out.write_all(&plain[..item.length as usize])?;
        } else {
            // Unencrypted stream copy
            let mut remaining = item.length;
            let mut buf = [0u8; 64 * 1024];
            while remaining > 0 {
                let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
                let n = file.read(&mut buf[..to_read])?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n])?;
                remaining -= n as u64;
            }
        }

        out.flush()?;

        // Verify SHA256 if present
        if !item.sha256.is_empty() {
            let mut f = File::open(&out_file_path)?;
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            while let Ok(n) = f.read(&mut buf) {
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            if item.length % 0x1000 > 0 {
                let pad = 0x1000 - (item.length % 0x1000);
                hasher.update(&vec![0u8; pad as usize]);
            }
            let digest_str = format!("{:x}", hasher.finalize());
            if digest_str.eq_ignore_ascii_case(&item.sha256) {
                println!("  [+] Verified SHA-256 successfully.");
            } else {
                println!("  [!] SHA-256 mismatch! (computed {}, expected {})", digest_str, item.sha256);
            }
        }

        extracted_count += 1;
    }

    if extracted_count == 0 {
        if let Some(target) = target_partition {
            bail!("No OPS partition matching '{}' was found.", target);
        } else {
            bail!("No extractable partitions found in OPS archive.");
        }
    }

    println!(
        "\n[+] Successfully extracted {} OnePlus partition(s) to {}",
        extracted_count,
        out_dir.display()
    );
    Ok(())
}

fn extract_ops_xml(file: &mut File, file_size: u64, sbox: &[u8]) -> Result<(String, &'static [u32; 62])> {
    if file_size < 0x200 {
        bail!("File too small to be an OPS container.");
    }
    file.seek(SeekFrom::Start(file_size - 0x200))?;
    let mut hdr = [0u8; 0x200];
    file.read_exact(&mut hdr)?;

    let xml_length = u32::from_le_bytes(hdr[0x18..0x1C].try_into().unwrap()) as u64;
    let xml_pad = if xml_length % 0x200 != 0 {
        0x200 - (xml_length % 0x200)
    } else {
        0
    };

    if file_size < 0x200 + xml_length + xml_pad {
        bail!("Invalid XML offset in OPS container header.");
    }

    let xml_offset = file_size - 0x200 - (xml_length + xml_pad);
    file.seek(SeekFrom::Start(xml_offset))?;
    let mut enc_xml = vec![0u8; (xml_length + xml_pad) as usize];
    file.read_exact(&mut enc_xml)?;

    for (name, mbox) in &[("MBox5", &MBOX5), ("MBox6", &MBOX6), ("MBox4", &MBOX4)] {
        let dec = key_custom_decrypt(&enc_xml, MASTER_KEY, *mbox, sbox);
        if dec.windows(4).any(|w| w == b"xml " || w == b"<?xm") {
            println!("[+] Matched OnePlus OPS profile: {}", name);
            let s = String::from_utf8_lossy(&dec[..xml_length as usize]).to_string();
            return Ok((s, *mbox));
        }
    }

    bail!("Failed to decrypt OPS XML manifest with any known MBox profile.");
}

pub fn parse_ops_xml(xml_content: &str) -> Result<Vec<OpsPartitionItem>> {
    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);

    let mut items = Vec::new();
    let mut tag_stack: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let parent_tag = tag_stack.last().cloned().unwrap_or_default();
                if let Some(item) = parse_ops_element(&reader, &e, &parent_tag)? {
                    items.push(item);
                }
                tag_stack.push(tag_name);
            }
            Ok(Event::Empty(e)) => {
                let parent_tag = tag_stack.last().cloned().unwrap_or_default();
                if let Some(item) = parse_ops_element(&reader, &e, &parent_tag)? {
                    items.push(item);
                }
            }
            Ok(Event::End(_)) => {
                tag_stack.pop();
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => (),
        }
    }

    Ok(items)
}

fn parse_ops_element(
    reader: &Reader<&[u8]>,
    e: &quick_xml::events::BytesStart,
    parent_tag: &str,
) -> Result<Option<OpsPartitionItem>> {
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

    let start_sectors: u64 = attribs
        .get("FileOffsetInSrc")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let start = start_sectors * 0x200;

    let length: u64 = attribs
        .get("SizeInByteInSrc")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let sha256 = attribs.get("Sha256").cloned().unwrap_or_default();

    let is_encrypted = parent_tag.eq_ignore_ascii_case("SAHARA");

    Ok(Some(OpsPartitionItem {
        filename,
        start,
        length,
        sha256,
        is_encrypted,
    }))
}
