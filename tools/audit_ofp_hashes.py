import os
import hashlib
import xml.etree.ElementTree as ET
from Cryptodome.Cipher import AES

def swap_nibbles(b):
    return ((b & 0x0F) << 4) | ((b & 0xF0) >> 4)

def deobfuscate(data, mc):
    return bytearray([swap_nibbles(data[i] ^ mc[i]) for i in range(16)])

def aes_cfb(data, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    return cipher.decrypt(data)

def audit_persist():
    xml_path = 'samples/extracted_persist/ProFile.xml'
    tree = ET.parse(xml_path)
    root = tree.getroot()

    keyset = ['93856285', '82496285', '26487264', '82496285']
    userkey = bytearray.fromhex(keyset[0] + keyset[1])
    ivec = bytearray.fromhex(keyset[2] + keyset[3])
    mc = bytearray.fromhex('93856285824962852648726482496285')
    key = hashlib.md5(deobfuscate(userkey, mc)).hexdigest()[:16].encode()
    iv = hashlib.md5(deobfuscate(ivec, mc)).hexdigest()[:16].encode()

    print("=== AUDIT OF PERSIST.IMG AND PROFILE.XML CHECKSUMS ===")
    for item in root.findall('.//program'):
        fn = item.attrib.get('filename', '')
        if fn == 'persist.img':
            start_sector = int(item.attrib.get('FileOffsetInSrc', 0))
            rlength = int(item.attrib.get('SizeInByteInSrc', 0))
            xml_md5 = item.attrib.get('md5', '')
            xml_sha256 = item.attrib.get('sha256', '')
            is_sparse = item.attrib.get('sparse', '0')
            start = start_sector * 512

            print(f"File: {fn}")
            print(f"Offset: sector {start_sector} ({start} bytes)")
            print(f"Size: {rlength} bytes")
            print(f"Sparse attribute: {is_sparse}")
            print(f"XML expected MD5:    {xml_md5}")
            print(f"XML expected SHA256: {xml_sha256}")

            # Read raw payload from OFP
            with open('samples/CPH1901EX_11_A.22_210306_072baf86.ofp', 'rb') as f:
                f.seek(start)
                raw = f.read(rlength)

            # Decrypt header (0x40000 bytes)
            dec_size = min(0x40000, rlength)
            dec_head = aes_cfb(raw[:dec_size], key, iv)
            dec_full = dec_head + raw[dec_size:]

            # Check magic of decrypted persist
            # Android sparse image magic is 0x3AFF26ED (little-endian: 0xED, 0x26, 0xFF, 0x3A)
            magic = dec_full[:4]
            is_android_sparse = (magic == b'\x3a\xff\x26\xed' or magic == b'\xed\x26\xff\x3a')
            print(f"Header magic (first 4 bytes hex): {magic.hex()}")
            print(f"Is Android Sparse Magic (0xED26FF3A): {is_android_sparse}")

            computed_md5_head = hashlib.md5(dec_full[:0x40000]).hexdigest()
            computed_sha256_head = hashlib.sha256(dec_full[:0x40000]).hexdigest()
            computed_sha256_full = hashlib.sha256(dec_full).hexdigest()

            print(f"\nComputed MD5 (first 0x40000 bytes): {computed_md5_head}")
            print(f"MD5 match with ProFile.xml:       {computed_md5_head.lower() == xml_md5.lower()}")

            print(f"\nComputed SHA256 (first 0x40000 bytes): {computed_sha256_head}")
            print(f"Computed SHA256 (full file):          {computed_sha256_full}")
            print(f"SHA256 head match: {computed_sha256_head.lower() == xml_sha256.lower()}")
            print(f"SHA256 full match: {computed_sha256_full.lower() == xml_sha256.lower()}")
            break

if __name__ == '__main__':
    audit_persist()
