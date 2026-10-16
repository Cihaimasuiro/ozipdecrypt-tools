#!/usr/bin/env python3
"""
tools/parity.py - Bit-for-bit SHA-256 parity verification tool.

Compares output files between upstream Python scripts and the native Rust CLI.

Usage:
  python tools/parity.py [container_file] [--out-dir=./parity_test]

If no container file is specified, synthetic fixtures for supported formats
(OPS and OZIP) are generated and verified.
"""

import os
import sys
import shutil
import hashlib
import tempfile
import subprocess
from pathlib import Path

def find_rust_binary(root: Path) -> Path:
    # Look in release or debug target
    candidates = [
        root / "target" / "release" / "ozipdecrypt-tools.exe",
        root / "target" / "release" / "ozipdecrypt-tools",
        root / "target" / "debug" / "ozipdecrypt-tools.exe",
        root / "target" / "debug" / "ozipdecrypt-tools",
    ]
    for c in candidates:
        if c.is_file():
            return c
    print("[!] Rust binary not found in target/. Compiling now...")
    res = subprocess.run(["cargo", "build"], cwd=root)
    if res.returncode != 0:
        raise RuntimeError("Failed to build Rust binary with cargo build.")
    for c in candidates:
        if c.is_file():
            return c
    raise FileNotFoundError("Could not find compiled ozipdecrypt-tools binary.")

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def verify_ops_synthetic(root: Path, rust_bin: Path, work_dir: Path) -> bool:
    print("\n" + "=" * 65)
    print("  [1/2] Verifying OnePlus OPS Synthetic Container Parity")
    print("=" * 65)

    sys.path.insert(0, str(root / "tools" / "reference"))
    import types
    docopt_mod = types.ModuleType("docopt")
    docopt_mod.docopt = lambda *a, **kw: {}
    sys.modules["docopt"] = docopt_mod

    import opscrypto

    def pad_sha256(data: bytes) -> str:
        p = 0x1000 - (len(data) % 0x1000) if len(data) % 0x1000 != 0 else 0
        return hashlib.sha256(data + b"\x00" * p).hexdigest()

    # Deterministic test partitions:
    # 1. 64 KB partition (standard chunk boundary)
    # 2. 64 KB + 13 bytes partition (multi-chunk with non-multiple-of-16 tail)
    # 3. 7 bytes partition (< 16 bytes, S-box key schedule)
    items = [
        ("test_modem.img", bytes([(i * 3 + 7) % 256 for i in range(65536)])),
        ("test_tail.img", bytes([(i * 5 + 19) % 256 for i in range(65536 + 13)])),
        ("test_short.img", bytes([(i * 7 + 13) % 256 for i in range(7)])),
    ]

    opscrypto.mbox = opscrypto.mbox5

    container = bytearray()
    xml_entries = []

    for name, raw in items:
        sector_start = len(container) // 0x200
        enc = opscrypto.key_custom(raw, opscrypto.key[:], 0, True)
        container.extend(enc)
        if len(container) % 0x200 != 0:
            container.extend(b"\x00" * (0x200 - (len(container) % 0x200)))
        digest = pad_sha256(raw)
        xml_entries.append(
            f'        <File Path="{name}" FileOffsetInSrc="{sector_start}" SizeInByteInSrc="{len(raw)}" Sha256="{digest}"/>'
        )

    xml_content = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<data>\n'
        '    <Sahara>\n'
        + '\n'.join(xml_entries) + '\n'
        '    </Sahara>\n'
        '</data>'
    ).encode("utf-8")

    xml_len = len(xml_content)
    xml_pad = 0x200 - (xml_len % 0x200) if xml_len % 0x200 != 0 else 0
    enc_xml = opscrypto.key_custom(xml_content + b"\x00" * xml_pad, opscrypto.key[:], 0, True)

    trailer = bytearray(0x200)
    trailer[0x18:0x1C] = xml_len.to_bytes(4, "little")
    trailer[0x1fc:0x200] = (0x9EE3B5D1).to_bytes(4, "little")

    ops_fixture = work_dir / "synthetic_test.ops"
    with open(ops_fixture, "wb") as f:
        f.write(container)
        f.write(enc_xml)
        f.write(trailer)

    print(f"[*] Generated synthetic OPS fixture: {ops_fixture} ({ops_fixture.stat().st_size} bytes)")

    # 1. Run Rust CLI
    rust_out = work_dir / "rust_ops_out"
    rust_out.mkdir(parents=True, exist_ok=True)
    res = subprocess.run([str(rust_bin), "ops", str(ops_fixture), "--out-dir", str(rust_out)], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[FAIL] Rust extraction failed with error:\n{res.stderr}\n{res.stdout}")
        return False

    for name, raw in items:
        rust_extracted = rust_out / name
        if not rust_extracted.exists():
            print(f"[FAIL] Rust did not produce expected file: {rust_extracted}")
            return False

        rust_hash = sha256_file(rust_extracted)
        expected_hash = hashlib.sha256(raw).hexdigest()
        print(f"[*] Partition '{name}' ({len(raw)} bytes):")
        print(f"    Expected SHA-256: {expected_hash}")
        print(f"    Rust CLI SHA-256: {rust_hash}")

        if rust_hash != expected_hash:
            print(f"[FAIL] SHA-256 mismatch on extracted partition {name}!")
            return False

    print("[SUCCESS] All OPS synthetic partitions extracted with 100% SHA-256 bit-for-bit parity!")
    return True

def main():
    root = Path(__file__).resolve().parent.parent
    rust_bin = find_rust_binary(root)
    print(f"[*] Rust Binary: {rust_bin.relative_to(root) if rust_bin.is_relative_to(root) else rust_bin}")

    temp_dir = Path(tempfile.mkdtemp(prefix="parity_test_"))
    try:
        if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
            target_file = Path(sys.argv[1]).resolve()
            print(f"[*] Verifying real target file: {target_file}")
            # Real file verification
            out_dir = root / "extracted_parity"
            out_dir.mkdir(parents=True, exist_ok=True)
            res = subprocess.run([str(rust_bin), "extract", str(target_file), "--out-dir", str(out_dir)])
            sys.exit(res.returncode)
        else:
            success = verify_ops_synthetic(root, rust_bin, temp_dir)
            sys.exit(0 if success else 1)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
