# ozipdecrypt-tools

Unified high-performance Rust CLI for decrypting Oppo, OnePlus, and Realme firmware archives (`.ozip` and Qualcomm `.ofp`) and automating recovery/radio firmware updates.

---

## Features

- **Blazing Fast & Streaming**: Decrypts directly into the target `.zip` in memory without writing multi-gigabyte temporary files to disk (zero disk wear, peak RAM ~64 KB).
- **All OZIP Formats Supported**:
  - **Standalone Mode**: Single `.ozip` files starting with `OPPOENCRYPT!`.
  - **Zip Mode 1**: Standard OTA packages with `oppo_metadata` and `vbmeta.img`.
  - **Zip Mode 2**: Interleaved chunk encryption used by Snapdragon 450 devices (e.g., Oppo A3s `CPH1803`, Oppo A7 `CPH1901`, Oppo A5s `CPH1909`).
- **Qualcomm & MediaTek OFP Unpackers**: Decrypts and unpacks Qualcomm Snapdragon and MediaTek Helio/Dimensity `.ofp` stock firmware containers with selective partition extraction (such as `modem` / `NON-HLOS.bin` for Wi-Fi/radio repairs).
- **OnePlus OPS Unpacker**: Decrypts and extracts partitions from OnePlus `.ops` unbrick containers using the custom CFB-128 cipher engine, 256-byte S-Box expansion schedule, and XML metadata manifest parser.
- **One-Command Sideload**: Automatically invokes `adb sideload` once decryption finishes.
- **Built-in Key Database**: 35 preconfigured AES-128 keys matched automatically against Android / ZIP header magics (`PK\x03\x04`, `AVB0`, and `ANDR`). Custom keys can also be supplied via `keys.toml`.

---

## Installation & Build

Prerequisites: [Rust Toolchain](https://rustup.rs/) (1.70+)

```bash
cargo build --release
```

The optimized binary will be compiled to `target/release/ozipdecrypt-tools` (or `ozipdecrypt-tools.exe` on Windows).

---

## Usage

### 1. Decrypt an `.ozip` File

Direct decryption:
```bash
ozipdecrypt-tools <filename.ozip>
```

Or using the `ozip` subcommand:
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

## Automated Tests

Run the built-in test suite covering bitwise operations, key derivation, and multi-format chunk decryption:

```bash
cargo test
```

---

## Credits

- Rust architecture by [Cihaimasuiro](https://github.com/Cihaimasuiro).
- Original reverse engineering and Python research by [B. Kerler](https://github.com/bkerler).
