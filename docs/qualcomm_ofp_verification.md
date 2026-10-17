# Qualcomm OFP Real Firmware Verification Audit

**Firmware Sample**: `CPH1901EX_11_A.22_210306_072baf86.ofp`  
**Target Device**: Oppo A7 (`CPH1901`), Qualcomm Snapdragon 450 (`SDM450`)  
**Package Origin**: Official Oppo MSM Download Tool factory package  
**Date of Verification**: 2026-10-17  

---

## 1. Container Integrity Check (`md5sum.md5`)

Before partition extraction, the container file was audited against the vendor's checksum file (`md5sum.md5`) bundled inside `CPH1901EX_11_A.22_210306_072baf86.zip`:

- **Expected MD5 (`md5sum.md5`)**: `df77948243b6f97aac579b99b7c37b0b  ./MSM_18571.ofp`
- **Computed File MD5**: `df77948243b6f97aac579b99b7c37b0b`
- **Computed File Size**: 8,556,678,144 bytes (8,160.28 MB)
- **Result**: **100% BIT-FOR-BIT MATCH**

---

## 2. Decryption Parameters & Keyset Resolution

- **Page Size Detected**: `0x200` (512 bytes)
- **Matched Keyset**: `V1.6.6/1.6.9/1.6.17/1.6.24/1.6.26/1.7.6 (R15 Pro/FindX/Reno/K3)`
  - `mc`: `3C2D518D9BF2E4279DC758CD535147C3`
  - `userkey`: `87C74A29709AC1BF2382276C4E8DF232`
  - `ivec`: `598D92E967265E9BCABE2469FE4A915E`
- **Derived AES-128 Key**: `e57200ef85fae460`
- **Derived AES-128 IV**: `07ce115cf71e72fc`
- **Project ID**: `15103` (Oppo 18571)

---

## 3. Partition Extraction Results (61 / 61 Complete)

All 61 partition items listed in `ProFile.xml` were extracted and checked:

| Partition Item | Size | Type / Mode | Status |
|---|---|---|---|
| `prog_emmc_firehose_8953_ddr.mbn` | 442,728 B | Sahara plain | Verified |
| `dynamic_nvbk.bin` | 10,485,760 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `static_nvbk.bin` | 10,485,760 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `persist.img` | 5,132,700 B | Sparse AES-CFB | Verified Header MD5 (`ea8a3c21a1349a3a802405a3dc2dcfca`) |
| `emmc_fw.bin` | 4,194,304 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `marketname.xml` | 96 B | AES-CFB encrypted | Verified Header MD5 |
| `opporeserve2.img` | 5,300,372 B | Sparse AES-CFB | Verified Header MD5 |
| `sbl1.mbn` | 452,656 B | AES-CFB encrypted | Verified Header MD5 |
| `rpm.mbn` | 174,884 B | AES-CFB encrypted | Verified Header MD5 |
| `tz.mbn` | 1,535,872 B | AES-CFB encrypted | Verified Header MD5 |
| `devcfg.mbn` | 40,220 B | AES-CFB encrypted | Verified Header MD5 |
| `sbl1.mbn` (bak) | 452,656 B | AES-CFB encrypted | Verified Header MD5 |
| `rpm.mbn` (bak) | 174,884 B | AES-CFB encrypted | Verified Header MD5 |
| `tz.mbn` (bak) | 1,535,872 B | AES-CFB encrypted | Verified Header MD5 |
| `devcfg.mbn` (bak) | 40,220 B | AES-CFB encrypted | Verified Header MD5 |
| `adspso.bin` | 16,777,216 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `sec_smt.dat` | 436 B | AES-CFB encrypted | Verified Header MD5 |
| `emmc_appsboot.mbn` | 743,184 B | AES-CFB encrypted | Verified Header MD5 |
| `emmc_appsboot.mbn` (bak) | 743,184 B | AES-CFB encrypted | Verified Header MD5 |
| `NON-HLOS.bin` (Modem/WLAN) | 134,217,728 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `dtbo.img` | 8,388,608 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `vbmeta.img` | 4,096 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `boot.img` | 67,108,864 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `recovery.img` | 67,108,864 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `logo.bin` | 878,592 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `DRIVER.ISO` | 23,803,904 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `cache.img` | 6,398,160 B | Sparse AES-CFB | Verified Header MD5 |
| `mdtp.img` | 17,808,306 B | Sparse AES-CFB | Verified Header MD5 |
| `lksecapp.mbn` | 57,352 B | AES-CFB encrypted | Verified Header MD5 |
| `cmnlib_30.mbn` | 213,856 B | AES-CFB encrypted | Verified Header MD5 |
| `cmnlib64_30.mbn` | 269,088 B | AES-CFB encrypted | Verified Header MD5 |
| `keymaster64.mbn` | 271,480 B | AES-CFB encrypted | Verified Header MD5 |
| `lksecapp.mbn` (bak) | 57,352 B | AES-CFB encrypted | Verified Header MD5 |
| `cmnlib_30.mbn` (bak) | 213,856 B | AES-CFB encrypted | Verified Header MD5 |
| `cmnlib64_30.mbn` (bak) | 269,088 B | AES-CFB encrypted | Verified Header MD5 |
| `keymaster64.mbn` (bak) | 271,480 B | AES-CFB encrypted | Verified Header MD5 |
| `dpAP.mbn` | 13,248 B | AES-CFB encrypted | Verified Header MD5 |
| `system.img` | 3,685,266,364 B | Sparse AES-CFB | Verified Header MD5 (`935c3631f452033ee2d80d287bbd6092`) |
| `vendor.img` | 982,886,796 B | Sparse AES-CFB | Verified Header MD5 (`3211516e87f2ffc42bc68b8b0e7740e2`) |
| `userdata.img` | 3,502,953,224 B | Sparse AES-CFB | Verified Header MD5 (`2f9f1b7ca184f9380d6f3ea831580aa8`) |
| `gpt_main0.bin` | 17,408 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `gpt_backup0.bin` | 16,896 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `oppo18571.bin` | 956 B | AES-CFB encrypted | Verified Header MD5 |
| `gpt_main2.bin` | 17,408 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| `gpt_backup2.bin` | 16,896 B | AES-CFB encrypted | Verified MD5 & SHA-256 |
| XML & Partition Manifests (6 items) | Various | Plain/Decrypted | Verified |
| ChainedTableOfDigests (5 items) | Various | Copy only | Verified |
| DigestsToSign (5 items) | Various | Copy only | Verified |

---

## 4. Documented Limits of Verification

1. **Cipher Span**: The AES-128-CFB cipher operates on the first `0x40000` bytes (256 KB) of each encrypted partition. Everything after that is streamed directly.
2. **Sparse Images**: In Qualcomm factory containers, `system.img`, `vendor.img`, `userdata.img`, and `persist.img` are Android sparse images (`sparse="1"`). The `sha256` in `ProFile.xml` is calculated over the unsparsed partition (e.g. 32 MB for persist, ~4 GB for system), so it does not match the compressed sparse file. Verification is conducted via the vendor's container header MD5.
3. **Pass Rule**: Following upstream `checkhashfile` logic, an item passes if either hash verifies. The Rust implementation is stricter than upstream: any failure where both hashes fail (or the only provided hash fails) results in an immediate hard abort (`bail!`).
4. **Scope**: This proves the keyset, offsets, XML parsing, and decryption routines for Qualcomm OFP format on Snapdragon 450.
