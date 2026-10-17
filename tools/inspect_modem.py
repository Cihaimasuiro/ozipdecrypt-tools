import struct
import os

def parse_fat16(path):
    with open(path, 'rb') as f:
        boot = f.read(512)
        bytes_per_sec = int.from_bytes(boot[11:13], 'little')
        sec_per_clus = boot[13]
        res_secs = int.from_bytes(boot[14:16], 'little')
        fat_count = boot[16]
        root_entries = int.from_bytes(boot[17:19], 'little')
        sec_per_fat = int.from_bytes(boot[22:24], 'little')
        
        fat_offset = res_secs * bytes_per_sec
        root_dir_offset = (res_secs + fat_count * sec_per_fat) * bytes_per_sec
        data_offset = root_dir_offset + (root_entries * 32)
        clus_size = sec_per_clus * bytes_per_sec

        # Read FAT
        f.seek(fat_offset)
        fat_data = f.read(sec_per_fat * bytes_per_sec)
        
        def get_next_cluster(c):
            if c * 2 + 2 <= len(fat_data):
                return struct.unpack_from('<H', fat_data, c * 2)[0]
            return 0xFFFF

        def read_cluster_chain(start_cluster):
            clusters = []
            curr = start_cluster
            while 0x0002 <= curr <= 0xFFEF:
                clusters.append(curr)
                curr = get_next_cluster(curr)
            data = bytearray()
            for c in clusters:
                offset = data_offset + (c - 2) * clus_size
                f.seek(offset)
                data.extend(f.read(clus_size))
            return bytes(data)

        def parse_dir(entries_data, prefix=""):
            files = []
            lfn_parts = {}
            for i in range(0, len(entries_data), 32):
                entry = entries_data[i:i+32]
                if not entry or entry[0] == 0:
                    break
                if entry[0] == 0xE5:
                    continue
                attr = entry[11]
                if attr == 0x0F: # LFN
                    seq = entry[0]
                    name_bytes = entry[1:11] + entry[14:26] + entry[28:32]
                    lfn_str = name_bytes.decode('utf-16le', errors='ignore').split('\x00')[0]
                    lfn_parts[seq & 0x1F] = lfn_str
                    continue
                
                if lfn_parts:
                    full_name = "".join(lfn_parts[k] for k in sorted(lfn_parts.keys()))
                    lfn_parts.clear()
                else:
                    base = entry[:8].decode('latin1', errors='replace').rstrip()
                    ext = entry[8:11].decode('latin1', errors='replace').rstrip()
                    full_name = f"{base}.{ext}" if ext else base
                
                if full_name in ('.', '..'):
                    continue
                
                size = struct.unpack_from('<I', entry, 28)[0]
                cluster = struct.unpack_from('<H', entry, 26)[0]
                is_dir = bool(attr & 0x10)
                path = f"{prefix}/{full_name}" if prefix else full_name
                
                files.append((path, is_dir, size, cluster))
                if is_dir and cluster >= 2:
                    dir_data = read_cluster_chain(cluster)
                    files.extend(parse_dir(dir_data, path))
            return files

        f.seek(root_dir_offset)
        root_data = f.read(root_entries * 32)
        return parse_dir(root_data)

if __name__ == '__main__':
    items = parse_fat16('samples/extracted_modem/NON-HLOS.bin')
    print(f"Total entries found: {len(items)}")
    wlan_items = [item for item in items if any(k in item[0].lower() for k in ['wlan', 'wifi', 'wcnss', 'nv', 'cfg', 'ini', 'fw'])]
    print("\n--- WLAN / Wi-Fi / Config Files in NON-HLOS.bin ---")
    for path, is_dir, size, clus in wlan_items:
        t = "DIR " if is_dir else "FILE"
        print(f"[{t}] {path} ({size:,} bytes)")
    
    print("\n--- Top-level folders & items ---")
    for path, is_dir, size, clus in items:
        if path.count('/') <= 1:
            t = "DIR " if is_dir else "FILE"
            print(f"[{t}] {path} ({size:,} bytes)")
