# ozipdecrypt

High-performance Oppo, OnePlus, and Realme `.ozip` firmware decrypter written in Rust.

---

## Features

- **Streaming Decryption**: Decrypts directly into the target `.zip` in memory without writing multi-gigabyte temporary files to disk.
- **Fast & Memory Efficient**: Peak RAM usage remains ~64 KB even for 10+ GB system images.
- **Full Format Support**:
  - **Standalone Mode**: Single `.ozip` files starting with `OPPOENCRYPT!`.
  - **Zip Mode 1**: Standard update zip archives with `oppo_metadata` and `vbmeta.img`.
  - **Zip Mode 2**: Interleaved chunk encryption used by CPH1803 / CPH1909.
- **Automatic Key Detection**: Built-in database of 35 AES keys matched dynamically against Android/Zip magics (`PK\x03\x04`, `AVB0`, and `ANDR`).

---

## Build

Prerequisites: [Rust Toolchain](https://rustup.rs/) (1.70+)

```bash
cargo build --release
```

The optimized executable will be located at `target/release/ozipdecrypt` (or `ozipdecrypt.exe` on Windows).

---

## Usage

```bash
ozipdecrypt <path_to_ozip_file>
```

Or run directly via Cargo:

```bash
cargo run --release -- <path_to_ozip_file>
```

The decrypted archive will be created in the same directory as `<filename>.zip`.

---

## Testing

Run the automated test suite covering unit tests and end-to-end integration tests for all 3 encryption modes:

```bash
cargo test
```

---

## History & Credits

- Ported to Rust by [Cihaimasuiro](https://github.com/Cihaimasuiro).
- Original Python research and implementation by [B. Kerler](https://github.com/bkerler/oppo_ozip_decrypt).
- Original Python source code and upstream repository history are archived in [`source-code/oppo_ozip_decrypt/`](source-code/oppo_ozip_decrypt/).
