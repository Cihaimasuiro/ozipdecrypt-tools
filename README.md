# ozipdecrypt-tools

Unified high-performance Rust CLI for decrypting Oppo, OnePlus, and Realme firmware archives (`.ozip`, Qualcomm `.ofp`, MediaTek `.ofp`, and OnePlus `.ops`) and automating recovery/radio firmware updates.

---

## Features

- **Blazing Fast & Streaming**: Decrypts directly into the target `.zip` in memory without writing multi-gigabyte temporary files to disk (zero disk wear, peak RAM ~64 KB).
- **All OZIP Formats Supported**:
  - **Standalone Mode**: Single `.ozip` files starting with `OPPOENCRYPT!`.
  - **Zip Mode 1**: Standard OTA packages with `oppo_metadata` and `vbmeta.img`.
  - **Zip Mode 2**: Interleaved chunk encryption used by Snapdragon 450 devices (e.g., Oppo A3s `CPH1803`, Oppo A7 `CPH1901`, Oppo A5s `CPH1909`).
- **Qualcomm & MediaTek OFP Unpackers**: Decrypts and unpacks Qualcomm Snapdragon and MediaTek Helio/Dimensity `.ofp` stock firmware containers with selective partition extraction (such as `modem` / `NON-HLOS.bin` for Wi-Fi/radio repairs). Supports password-protected Realme encrypted ZIP OFP containers.
- **OnePlus OPS Unpacker**: Decrypts and extracts partitions from OnePlus `.ops` unbrick containers using the custom CFB-128 cipher engine, 2048-byte S-Box table, MBOX vectors, and XML metadata manifest parser.
- **One-Command Sideload**: Automatically invokes `adb sideload` once decryption finishes.
- **Built-in Key Database & Constants Audit**: 35 preconfigured AES-128 keys matched automatically against Android / ZIP header magics (`PK\x03\x04`, `AVB0`, and `ANDR`), 6 Qualcomm OFP keysets, and 9 MediaTek keytables, verified 100% bit-for-bit against upstream Python tools (`python tools/check_constants.py`). Custom keys can also be supplied via `keys.toml`.

---

## Desktop GUI (`ozipdecrypt-gui`)

In addition to the command-line interface, `ozipdecrypt-tools` includes a fast, native desktop GUI:

1. **Drag & Drop**: Drag your firmware file (`.ozip`, `.ofp`, `.ops`, or `.zip`) directly into the window (or click **Choose Firmware File...**).
2. **Inspect & Select**: View container details, SoC/platform, and verification badge. Filter partitions and pick individual items or **Select All**. Set your destination folder (defaults to `<input_name>_extracted`).
3. **Extract & Cancel**: Click **Extract Selected**. Monitor real-time progress, throughput, and elapsed time. Cancel at any point to stop safely and remove partial `.part` files automatically.

> [!NOTE]
> **Unsigned Binaries & Antivirus False Positives**:
> Release binaries are currently self-built and unsigned. Windows SmartScreen and macOS Gatekeeper will display a warning on first run, and heuristic antivirus engines may flag firmware decryption utilities. You can safely bypass SmartScreen via *More info -> Run anyway* or inspect/build the full source yourself with `cargo build --release`.

---

## Installation & Build

Prerequisites: [Rust Toolchain](https://rustup.rs/) (1.80+)

```bash
# Build both CLI and GUI:
cargo build --release --workspace

# Or run the GUI directly:
cargo run --release -p ozipdecrypt-gui
```

The optimized binaries will be compiled to `target/release/ozipdecrypt-gui` and `target/release/ozipdecrypt-tools` (or `.exe` on Windows).

---

## Quick Start (Zero-Config Auto-Detection)

`ozipdecrypt-tools` automatically detects the container format (`.ozip`, Qualcomm `.ofp`, MediaTek `.ofp`, OnePlus `.ops`, or standard `.zip`) and dispatches the appropriate decryption engine without needing manual flags:

```bash
# Auto-detects and extracts ANY container directly
ozipdecrypt-tools firmware.ozip
ozipdecrypt-tools CPH1901EX_11_A.16.ofp
ozipdecrypt-tools OnePlus7Pro.ops

# Or explicitly via the extract command:
ozipdecrypt-tools extract firmware.ofp --partition modem
```

### Inspect Container Metadata (`info`)

```bash
# Inspect container header, signature magic, and encryption specifications
ozipdecrypt-tools info firmware.ofp
```

---

## Detailed Command Usage

### 1. Decrypt an `.ozip` File

```bash
# Decrypt to default <filename.zip>
ozipdecrypt-tools ozip CPH1901_OTA.ozip

# Decrypt to custom path
ozipdecrypt-tools ozip CPH1901_OTA.ozip -o update.zip

# Decrypt and immediately sideload to connected phone over ADB
ozipdecrypt-tools ozip CPH1901_OTA.ozip --sideload
```

### 2. Extract Qualcomm & MediaTek `.ofp` Stock Firmware

`ozipdecrypt-tools` automatically detects whether the `.ofp` file is a Qualcomm Snapdragon or MediaTek Helio/Dimensity archive:

```bash
# Auto-detects chipset and unpacks all partitions into ./extracted_ofp
ozipdecrypt-tools ofp CPH1901EX_11_A.16.ofp

# Selectively extract only the Wi-Fi/modem partition (NON-HLOS.bin / md1img)
ozipdecrypt-tools ofp CPH1901EX_11_A.16.ofp --partition modem

# Extract MediaTek OFP archive (A77, F1s, A83, Realme 3)
ozipdecrypt-tools ofp CPH1827EX_11_A.21.ofp --out-dir ./extracted_mtk
```

### 3. Extract OnePlus `.ops` Stock Containers

```bash
# Decrypt and unpack all partitions into ./extracted_ops
ozipdecrypt-tools ops OnePlus7Pro.ops

# Selectively extract only the modem partition
ozipdecrypt-tools ops OnePlus7Pro.ops --partition modem --out-dir ./extracted_ops
```

### 4. Sideload a `.zip` Package Directly

```bash
ozipdecrypt-tools sideload update.zip
```

---

## Configuration (`keys.toml`)

`ozipdecrypt-tools` works out of the box with its built-in database of 35 OZIP keys. To add custom OZIP keys or OFP key triplets, copy `keys.toml.example` to `keys.toml`:

```toml
# Custom OZIP AES-128 keys (hex)
ozip_keys = [
    "D6EECF0AE5ACD4E0E9FE522DE7CE381E",
]

# Triplets for Qualcomm OFP containers
[[ofp_keysets]]
name = "Qualcomm SDM450 / CPH1901 Profile"
mc = "00000000000000000000000000000000"
userkey = "00000000000000000000000000000000"
ivec = "00000000000000000000000000000000"
```

---

## Verification Matrix

The project enforces strict separation between algorithms verified on real firmware data vs. synthetic test fixtures:

| Format | Constants vs Upstream | Known-Answer Tests | Real Firmware Data | Status |
|---|---|---|---|---|
| **Qualcomm `.ofp`** | Audited (6 keysets) | Derived key/IV for all 6 keysets | **Verified**: CPH1901 `.ofp` (8.16 GB), all 61/61 partitions extracted, MD5 verified against `ProFile.xml` and package `md5sum.md5` | **Verified on real data** (see limits below) |
| **`.ozip`** (standalone, zip mode 1 & 2) | Audited (35 keys) | Synthetic v1, v2, multi-chunk | Pending real OTA `.ozip` run | Synthetic only |
| **MediaTek `.ofp`** | Audited (8 triplets + 1 raw pair) | Derived keys, shuffles | None | Synthetic only |
| **OnePlus `.ops`** | Audited (`MASTER_KEY`, S-box, MBOX4/5/6) | `key_update`, stream vectors, whole-item tail rule | None | Synthetic only |
| **Realme zip `.ofp`** | Audited (password) | None | None | Unverified |

### Documented Limits of the Qualcomm OFP Verification

1. **Cipher Span**: The AES-128-CFB cipher operates on the first `0x40000` bytes (256 KB) of each partition. Trailing data is streamed directly.
2. **Sparse Image Checksums**: Manifest SHA-256 for sparse images (`system`, `vendor`, `userdata`, `persist`) is calculated on the unsparsed partition, so only the container header MD5 can be verified against the file.
3. **Source Verification**: The `.ofp` container file was checked against the package's bundled `md5sum.md5` (`df77948243b6f97aac579b99b7c37b0b`), verifying the 8.16 GB archive was not corrupted in transfer.
4. **Hard-Fail Policy**: Rust enforces strict termination: if both MD5 and SHA-256 fail (or the only provided hash fails), extraction aborts immediately.
5. **Sample Scope**: Verified on Oppo A7 CPH1901 (Qualcomm SDM450, Keyset V1.6.6+). Other keysets are validated via automated constants audit and derived-key vectors.

---

## Automated Tests & CI

Run the automated constants audit diffing against upstream Python modules:
```bash
python tools/check_constants.py
```

Run the built-in test suite (44 active unit tests + 1 doc-test):
```bash
cargo test --workspace
```

Run cross-platform synthetic parity verification:
```bash
python tools/parity.py
```

---

## Credits

- Rust architecture by [Cihaimasuiro](https://github.com/Cihaimasuiro).
- Original reverse engineering and Python research by [B. Kerler](https://github.com/bkerler).

