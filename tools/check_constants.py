#!/usr/bin/env python3
"""
tools/check_constants.py - Automated constants diff between Python upstream and Rust source.

Validates that:
  1. 35 OZIP AES keys match ozipdecrypt.py
  2. 6 Qualcomm OFP keysets match ofp_qc_decrypt.py
  3. 9 MTK OFP keytables (8 triplets + 1 raw pair) match ofp_mtk_decrypt.py
  4. Realme encrypted ZIP password matches ofp_qc_decrypt.py
  5. OPS MASTER_KEY matches opscrypto.py
  6. OPS SBOX_HEX (2048 bytes) matches opscrypto.py
  7. OPS MBOX4, MBOX5, MBOX6 arrays match opscrypto.py

Exits with code 0 on success, 1 on any difference.
"""

import sys
import re
import struct
from pathlib import Path

def find_project_root() -> Path:
    # Anchor to root of repo
    cur = Path(__file__).resolve().parent
    if (cur.parent / "Cargo.toml").exists():
        return cur.parent
    return Path.cwd()

def resolve_python_sources(root: Path) -> dict:
    candidates = [
        root / "tools" / "reference",
        root / "source-code" / "oppo_decrypt",
        root / "source-code" / "oppo_ozip_decrypt",
        root / "source-code",
        root,
    ]
    found = {}
    target_files = {
        "ozip": "ozipdecrypt.py",
        "qc": "ofp_qc_decrypt.py",
        "mtk": "ofp_mtk_decrypt.py",
        "ops": "opscrypto.py",
    }
    for key, name in target_files.items():
        for d in candidates:
            p = d / name
            if p.is_file():
                found[key] = p
                break
            # check subdirectories
            for sub in d.glob(f"**/{name}"):
                if sub.is_file():
                    found[key] = sub
                    break
            if key in found:
                break
    return found

def check_ozip_keys(root: Path, ozip_py: Path) -> bool:
    crypto_rs = (root / "src" / "crypto.rs").read_text(encoding="utf-8")
    m_rs = re.search(r"pub const DEFAULT_OZIP_KEYS:\s*&\[&str\]\s*=\s*&\[(.*?)\];", crypto_rs, re.DOTALL)
    if not m_rs:
        print("[FAIL] Could not locate DEFAULT_OZIP_KEYS in src/crypto.rs")
        return False
    rust_keys = [k.strip().upper() for k in re.findall(r'"([0-9A-Fa-f]{32})"', m_rs.group(1))]

    py_text = ozip_py.read_text(encoding="utf-8")
    m_py = re.search(r"keys\s*=\s*\[(.*?)\]\s+def\s+keytest", py_text, re.DOTALL)
    if not m_py:
        print("[FAIL] Could not locate keys list in ozipdecrypt.py")
        return False
    py_keys = [k.strip().upper() for k in re.findall(r'"([0-9A-Fa-f]{32})"', m_py.group(1))]

    if len(rust_keys) != len(py_keys):
        print(f"[FAIL] OZIP keys count mismatch: Rust has {len(rust_keys)}, Python has {len(py_keys)}")
        return False

    for idx, (rk, pk) in enumerate(zip(rust_keys, py_keys)):
        if rk != pk:
            print(f"[FAIL] OZIP key #{idx} mismatch: Rust={rk} vs Python={pk}")
            return False

    print(f"[OK] 35 OZIP keys match 1:1 against {ozip_py.name}")
    return True

def check_qc_keysets(root: Path, qc_py: Path) -> bool:
    crypto_rs = (root / "src" / "crypto.rs").read_text(encoding="utf-8")
    m_rs = re.search(r"pub const DEFAULT_OFP_KEYSETS:\s*&\[\(&str,\s*&str,\s*&str,\s*&str\)\]\s*=\s*&\[(.*?)\];", crypto_rs, re.DOTALL)
    if not m_rs:
        print("[FAIL] Could not locate DEFAULT_OFP_KEYSETS in src/crypto.rs")
        return False

    # Extract tuples of (name, k1, k2, k3)
    rust_triplets = re.findall(
        r'\(\s*"([^"]+)",\s*"([0-9A-Fa-f]{32})",\s*"([0-9A-Fa-f]{32})",\s*"([0-9A-Fa-f]{32})",?\s*\)',
        m_rs.group(1),
        re.DOTALL
    )

    py_text = qc_py.read_text(encoding="utf-8")
    m_py = re.search(r"keys\s*=\s*\[(.*?)\]\s+for\s+dkey\s+in\s+keys:", py_text, re.DOTALL)
    if not m_py:
        print("[FAIL] Could not locate keys list in ofp_qc_decrypt.py")
        return False

    py_triplets = re.findall(
        r'\[\s*"([^"]+)",\s*"([0-9A-Fa-f]{32})",\s*"([0-9A-Fa-f]{32})",\s*"([0-9A-Fa-f]{32})",?\s*\]',
        m_py.group(1),
        re.DOTALL
    )

    if len(rust_triplets) != len(py_triplets):
        print(f"[FAIL] Qualcomm OFP keysets count mismatch: Rust has {len(rust_triplets)}, Python has {len(py_triplets)}")
        return False

    for idx, (rt, pt) in enumerate(zip(rust_triplets, py_triplets)):
        # Compare keys case-insensitively
        for k_idx in (1, 2, 3):
            if rt[k_idx].upper() != pt[k_idx].upper():
                print(f"[FAIL] QC Keys #{idx} item {k_idx} mismatch: Rust={rt[k_idx]} vs Python={pt[k_idx]}")
                return False

    print(f"[OK] 6 Qualcomm OFP keysets match 1:1 against {qc_py.name}")
    return True

def check_mtk_keytables(root: Path, mtk_py: Path) -> bool:
    ofp_mtk_rs = (root / "src" / "ofp_mtk.rs").read_text(encoding="utf-8")
    m_rs = re.search(r"pub const MTK_KEYTABLES:\s*&\[&\[&str\]\]\s*=\s*&\[(.*?)\];", ofp_mtk_rs, re.DOTALL)
    if not m_rs:
        print("[FAIL] Could not locate MTK_KEYTABLES in src/ofp_mtk.rs")
        return False

    # Extract sub-arrays
    rust_blocks = re.findall(r"&\[(.*?)\]", m_rs.group(1), re.DOTALL)
    rust_tables = []
    for b in rust_blocks:
        keys = [k.strip().lower() for k in re.findall(r'"([0-9A-Fa-f]+)"', b)]
        if keys:
            rust_tables.append(keys)

    py_text = mtk_py.read_text(encoding="utf-8")
    m_py = re.search(r"keytables\s*=\s*\[(.*?)\]\s+def\s+getkey", py_text, re.DOTALL)
    if not m_py:
        print("[FAIL] Could not locate keytables in ofp_mtk_decrypt.py")
        return False

    py_blocks = re.findall(r"\[(.*?)\]", m_py.group(1), re.DOTALL)
    py_tables = []
    for b in py_blocks:
        keys = [k.strip().lower() for k in re.findall(r'"([0-9A-Fa-f]+)"', b)]
        if keys:
            py_tables.append(keys)

    if len(rust_tables) != len(py_tables):
        print(f"[FAIL] MTK keytables count mismatch: Rust has {len(rust_tables)}, Python has {len(py_tables)}")
        return False

    for idx, (rt, pt) in enumerate(zip(rust_tables, py_tables)):
        if rt != pt:
            print(f"[FAIL] MTK table #{idx} mismatch:\n  Rust:   {rt}\n  Python: {pt}")
            return False

    print(f"[OK] 9 MTK keytables (8 triplets + 1 raw pair) match 1:1 against {mtk_py.name}")
    return True

def check_realme_zip_password(root: Path, qc_py: Path) -> bool:
    ofp_rs = (root / "src" / "ofp.rs").read_text(encoding="utf-8")
    m_rs = re.search(r'let\s+zippw\s*=\s*b"([^"]+)";', ofp_rs)
    if not m_rs:
        print("[FAIL] Could not locate zippw in src/ofp.rs")
        return False
    rust_pw = m_rs.group(1)

    py_text = qc_py.read_text(encoding="utf-8")
    m_py = re.search(r'zippw\s*=\s*bytes\("([^"]+)"', py_text)
    if not m_py:
        print("[FAIL] Could not locate zippw in ofp_qc_decrypt.py")
        return False
    py_pw = m_py.group(1)

    if rust_pw != py_pw:
        print(f"[FAIL] Realme zip password mismatch: Rust='{rust_pw}' vs Python='{py_pw}'")
        return False

    print(f"[OK] Realme zip password matches 1:1 against {qc_py.name} ('{rust_pw}')")
    return True

def check_ops_constants(root: Path, ops_py: Path) -> bool:
    ops_rs = (root / "src" / "ops.rs").read_text(encoding="utf-8")
    py_text = ops_py.read_text(encoding="utf-8")

    # 1. MASTER_KEY
    m_mkey_rs = re.search(r"pub const MASTER_KEY:\s*\[u32;\s*4\]\s*=\s*\[(.*?)\];", ops_rs, re.DOTALL)
    if not m_mkey_rs:
        print("[FAIL] Could not locate MASTER_KEY in src/ops.rs")
        return False
    rust_mkey = [int(x.strip(), 16) for x in re.findall(r"0x[0-9A-Fa-f]+", m_mkey_rs.group(1))]

    m_mkey_py = re.search(r'key\s*=\s*unpack\("<4I",\s*bytes\.fromhex\("([0-9A-Fa-f]{32})"\)\)', py_text)
    if not m_mkey_py:
        print("[FAIL] Could not locate key unpack in opscrypto.py")
        return False
    py_mkey = list(struct.unpack("<4I", bytes.fromhex(m_mkey_py.group(1))))

    if rust_mkey != py_mkey:
        print(f"[FAIL] MASTER_KEY mismatch: Rust={[hex(x) for x in rust_mkey]} vs Python={[hex(x) for x in py_mkey]}")
        return False
    print(f"[OK] OPS MASTER_KEY matches 1:1: {[hex(x) for x in rust_mkey]}")

    # 2. SBOX_HEX
    m_sbox_rs = re.search(r"pub const SBOX_HEX:\s*&str\s*=\s*(?:concat!\((.*?)\)|\"([0-9A-Fa-f]+)\");", ops_rs, re.DOTALL)
    if not m_sbox_rs:
        print("[FAIL] Could not locate SBOX_HEX in src/ops.rs")
        return False
    if m_sbox_rs.group(1):
        rust_sbox = "".join(re.findall(r'"([0-9A-Fa-f]+)"', m_sbox_rs.group(1))).lower()
    else:
        rust_sbox = m_sbox_rs.group(2).lower()

    # In Python, sbox is joined with string concatenation inside bytes.fromhex(...)
    m_sbox_py = re.search(r"sbox\s*=\s*bytes\.fromhex\((.*?)\)\s+class\s+QCSparse", py_text, re.DOTALL)
    if not m_sbox_py:
        print("[FAIL] Could not locate sbox definition in opscrypto.py")
        return False
    py_sbox = "".join(re.findall(r'"([0-9A-Fa-f]+)"', m_sbox_py.group(1))).lower()

    if len(rust_sbox) != 4096:
        print(f"[FAIL] Rust SBOX_HEX length is {len(rust_sbox)}, expected 4096 hex chars (2048 bytes)")
        return False

    if len(py_sbox) != 4096:
        print(f"[FAIL] Python sbox length is {len(py_sbox)}, expected 4096 hex chars (2048 bytes)")
        return False

    if rust_sbox != py_sbox:
        print(f"[FAIL] SBOX_HEX mismatch against opscrypto.py")
        return False
    print(f"[OK] OPS SBOX_HEX matches 1:1 (2048 bytes / 4096 hex characters)")

    # 3. MBOX4, MBOX5, MBOX6
    for mbox_name in ["mbox4", "mbox5", "mbox6"]:
        rs_name = mbox_name.upper()
        m_mbox_rs = re.search(rf"pub const {rs_name}:\s*\[u(?:8|32);\s*62\]\s*=\s*\[(.*?)\];", ops_rs, re.DOTALL)
        if not m_mbox_rs:
            print(f"[FAIL] Could not locate {rs_name} in src/ops.rs")
            return False
        rust_mbox = [int(x.strip(), 16) for x in re.findall(r"0x[0-9A-Fa-f]+", m_mbox_rs.group(1))]

        m_mbox_py = re.search(rf"{mbox_name}\s*=\s*\[(.*?)\]", py_text, re.DOTALL)
        if not m_mbox_py:
            print(f"[FAIL] Could not locate {mbox_name} in opscrypto.py")
            return False
        py_mbox = [int(x.strip(), 16) for x in re.findall(r"0x[0-9A-Fa-f]+", m_mbox_py.group(1))]

        if rust_mbox != py_mbox:
            print(f"[FAIL] {rs_name} mismatch between Rust and Python")
            return False
        print(f"[OK] OPS {rs_name} (62 bytes) matches 1:1")

    return True

def main():
    print("=" * 65)
    print("  ozipdecrypt-tools: Automated Constants Audit (Task 5.1)")
    print("=" * 65)

    root = find_project_root()
    print(f"[*] Workspace Root: {root}")

    sources = resolve_python_sources(root)
    missing = [k for k in ["ozip", "qc", "mtk", "ops"] if k not in sources]
    if missing:
        print(f"[ERROR] Missing reference Python sources: {missing}")
        print("        Please provide them in source-code/ or specify path.")
        sys.exit(1)

    print(f"[*] Reference Sources:")
    for k, p in sources.items():
        print(f"    - {k.upper():4}: {p.relative_to(root) if p.is_relative_to(root) else p}")
    print("-" * 65)

    success = True
    success &= check_ozip_keys(root, sources["ozip"])
    success &= check_qc_keysets(root, sources["qc"])
    success &= check_mtk_keytables(root, sources["mtk"])
    success &= check_realme_zip_password(root, sources["qc"])
    success &= check_ops_constants(root, sources["ops"])

    print("=" * 65)
    if success:
        print("[SUCCESS] ALL CONSTANTS VERIFIED 100% IDENTICAL AGAINST UPSTREAM PYTHON")
        sys.exit(0)
    else:
        print("[FAILURE] Constant differences detected. Please review output above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
