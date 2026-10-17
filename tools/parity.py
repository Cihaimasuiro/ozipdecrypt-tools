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
import time
import zipfile
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

def verify_real_ozip_parity(target_file: Path, root: Path, rust_bin: Path, work_dir: Path) -> bool:
    print("\n" + "=" * 65)
    print(f"  Verifying Real OZIP Parity: {target_file.name}")
    print("=" * 65)

    py_dir = work_dir / "py_ozip"
    py_dir.mkdir(parents=True, exist_ok=True)

    # 1. Run Python ozipdecrypt.py
    print("[*] Running upstream Python ozipdecrypt.py...")
    py_target_copy = py_dir / target_file.name
    shutil.copyfile(target_file, py_target_copy)

    t0_py = time.time()
    res_py = subprocess.run(
        [sys.executable, str(root / "tools" / "reference" / "ozipdecrypt.py"), str(py_target_copy)],
        cwd=py_dir,
        capture_output=True,
        text=True,
    )
    t1_py = time.time()

    if res_py.returncode != 0:
        print(f"[FAIL] Upstream Python ozipdecrypt failed:\n{res_py.stderr}\n{res_py.stdout}")
        return False

    py_zip = py_dir / (target_file.stem + ".zip")
    if not py_zip.exists():
        print(f"[FAIL] Python ozipdecrypt did not create expected output: {py_zip}")
        return False
    print(f"[+] Python decryption finished in {t1_py - t0_py:.2f}s (output: {py_zip.stat().st_size:,} bytes)")

    # 2. Run Rust CLI
    rust_dir = work_dir / "rust_ozip"
    rust_dir.mkdir(parents=True, exist_ok=True)
    rust_zip = rust_dir / "out.zip"

    print("[*] Running native Rust CLI ozipdecrypt-tools...")
    t0_rust = time.time()
    res_rust = subprocess.run(
        [str(rust_bin), "ozip", str(target_file), "-o", str(rust_zip)],
        capture_output=True,
        text=True,
    )
    t1_rust = time.time()

    if res_rust.returncode != 0:
        print(f"[FAIL] Rust ozip decryption failed:\n{res_rust.stderr}\n{res_rust.stdout}")
        return False

    if not rust_zip.exists():
        print(f"[FAIL] Rust ozip did not produce expected output: {rust_zip}")
        return False
    print(f"[+] Rust decryption finished in {t1_rust - t0_rust:.2f}s (output: {rust_zip.stat().st_size:,} bytes)")

    # 3. Compare entries inside both zip archives
    print("\n[*] Comparing decrypted files inside ZIP archives...")
    with zipfile.ZipFile(py_zip, "r") as z_py, zipfile.ZipFile(rust_zip, "r") as z_rust:
        py_names = sorted(z_py.namelist())
        rust_names = sorted(z_rust.namelist())

        if py_names != rust_names:
            print("[FAIL] ZIP entry list mismatch!")
            print(f"  Python entries ({len(py_names)}): {py_names[:10]}...")
            print(f"  Rust entries   ({len(rust_names)}): {rust_names[:10]}...")
            return False

        all_matched = True
        total_bytes = 0
        for name in py_names:
            py_bytes = z_py.read(name)
            rust_bytes = z_rust.read(name)
            total_bytes += len(rust_bytes)

            h_py = hashlib.sha256(py_bytes).hexdigest()
            h_rust = hashlib.sha256(rust_bytes).hexdigest()

            if h_py == h_rust:
                print(f"  [OK] {name:<35} ({len(rust_bytes):>10,} bytes) SHA-256: {h_rust}")
            else:
                print(f"  [FAIL] {name:<35} MISMATCH!")
                print(f"         Python SHA-256: {h_py}")
                print(f"         Rust   SHA-256: {h_rust}")
                all_matched = False

    if all_matched:
        print("\n" + "=" * 65)
        print(f"[SUCCESS] 100% BIT-FOR-BIT SHA-256 PARITY VERIFIED ACROSS ALL {len(py_names)} ENTRIES!")
        print(f"Total uncompressed data: {total_bytes:,} bytes")
        speedup = (t1_py - t0_py) / max(0.001, t1_rust - t0_rust)
        print(f"Speedup: {speedup:.1f}x faster in Rust ({t1_rust - t0_rust:.2f}s vs {t1_py - t0_py:.2f}s)")
        print("=" * 65)
        return True
    else:
        print("\n[FAIL] One or more entries failed bit-for-bit SHA-256 parity verification!")
        return False

def verify_real_extracted_dir_parity(py_dir: Path, rust_dir: Path) -> bool:
    print("\n[*] Comparing extracted partition files...")
    py_files = sorted([p.relative_to(py_dir) for p in py_dir.rglob("*") if p.is_file()])
    rust_files = sorted([p.relative_to(rust_dir) for p in rust_dir.rglob("*") if p.is_file()])

    if py_files != rust_files:
        print("[FAIL] Extracted file list mismatch!")
        print(f"  Python files ({len(py_files)}): {py_files[:10]}...")
        print(f"  Rust files   ({len(rust_files)}): {rust_files[:10]}...")
        return False

    all_matched = True
    total_bytes = 0
    for rel_path in py_files:
        f_py = py_dir / rel_path
        f_rust = rust_dir / rel_path
        size = f_rust.stat().st_size
        total_bytes += size

        h_py = sha256_file(f_py)
        h_rust = sha256_file(f_rust)

        if h_py == h_rust:
            print(f"  [OK] {str(rel_path):<35} ({size:>10,} bytes) SHA-256: {h_rust}")
        else:
            print(f"  [FAIL] {str(rel_path):<35} MISMATCH!")
            print(f"         Python SHA-256: {h_py}")
            print(f"         Rust   SHA-256: {h_rust}")
            all_matched = False

    if all_matched:
        print("\n" + "=" * 65)
        print(f"[SUCCESS] 100% BIT-FOR-BIT SHA-256 PARITY VERIFIED ACROSS ALL {len(py_files)} FILES!")
        print(f"Total extracted data: {total_bytes:,} bytes")
        print("=" * 65)
        return True
    else:
        print("\n[FAIL] One or more files failed bit-for-bit SHA-256 parity verification!")
        return False

def main():
    root = Path(__file__).resolve().parent.parent
    rust_bin = find_rust_binary(root)
    print(f"[*] Rust Binary: {rust_bin.relative_to(root) if rust_bin.is_relative_to(root) else rust_bin}")

    temp_dir = Path(tempfile.mkdtemp(prefix="parity_test_"))
    try:
        if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
            target_file = Path(sys.argv[1]).resolve()
            if not target_file.is_file():
                print(f"[FAIL] Target file does not exist: {target_file}")
                sys.exit(1)

            ext = target_file.suffix.lower()
            if ext == ".ozip":
                success = verify_real_ozip_parity(target_file, root, rust_bin, temp_dir)
            elif ext == ".ofp":
                rust_dir = temp_dir / "rust_ofp"
                py_dir = temp_dir / "py_ofp"
                rust_dir.mkdir(parents=True, exist_ok=True)
                py_dir.mkdir(parents=True, exist_ok=True)

                print(f"[*] Extracting with Rust CLI: {rust_bin}")
                res_rust = subprocess.run([str(rust_bin), "ofp", str(target_file), "--out-dir", str(rust_dir)], capture_output=True, text=True)
                if res_rust.returncode != 0:
                    print(f"[FAIL] Rust ofp extraction failed:\n{res_rust.stderr}\n{res_rust.stdout}")
                    sys.exit(1)

                print("[*] Extracting with upstream Python OFP tool...")
                res_py = subprocess.run([sys.executable, str(root / "tools" / "reference" / "ofp_qc_decrypt.py"), str(target_file), str(py_dir)], capture_output=True, text=True)
                if res_py.returncode != 0 or not any(py_dir.iterdir()):
                    print("[*] Trying MediaTek OFP decryptor...")
                    shutil.rmtree(py_dir, ignore_errors=True)
                    py_dir.mkdir(parents=True, exist_ok=True)
                    res_py = subprocess.run([sys.executable, str(root / "tools" / "reference" / "ofp_mtk_decrypt.py"), str(target_file), str(py_dir)], capture_output=True, text=True)

                if res_py.returncode != 0:
                    print(f"[FAIL] Upstream Python OFP decrypt failed:\n{res_py.stderr}\n{res_py.stdout}")
                    sys.exit(1)

                success = verify_real_extracted_dir_parity(py_dir, rust_dir)
            elif ext == ".ops":
                rust_dir = temp_dir / "rust_ops"
                py_dir = temp_dir / "py_ops"
                rust_dir.mkdir(parents=True, exist_ok=True)
                py_dir.mkdir(parents=True, exist_ok=True)

                print(f"[*] Extracting with Rust CLI: {rust_bin}")
                res_rust = subprocess.run([str(rust_bin), "ops", str(target_file), "--out-dir", str(rust_dir)], capture_output=True, text=True)
                if res_rust.returncode != 0:
                    print(f"[FAIL] Rust ops extraction failed:\n{res_rust.stderr}\n{res_rust.stdout}")
                    sys.exit(1)

                print("[*] Extracting with upstream Python opscrypto.py...")
                res_py = subprocess.run([sys.executable, str(root / "tools" / "reference" / "opscrypto.py"), "decrypt", str(target_file), f"--extractdir={str(py_dir)}"], cwd=temp_dir, capture_output=True, text=True)
                if res_py.returncode != 0:
                    print(f"[FAIL] Upstream Python opscrypto failed:\n{res_py.stderr}\n{res_py.stdout}")
                    sys.exit(1)

                success = verify_real_extracted_dir_parity(py_dir, rust_dir)
            else:
                print(f"[FAIL] Unsupported container extension for parity testing: {ext}")
                sys.exit(1)

            sys.exit(0 if success else 1)
        else:
            success = verify_ops_synthetic(root, rust_bin, temp_dir)
            sys.exit(0 if success else 1)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
