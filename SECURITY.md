# Security Policy

## Supported Versions

Only the latest release branch of `ozipdecrypt-tools` and `ozipdecrypt-core` receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3.0 | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability or security bug (such as path traversal, malicious container decompression, or memory safety issues):

1. **Do not open a public GitHub issue.**
2. Report the vulnerability privately via **[GitHub Private Vulnerability Reporting](https://github.com/Cihaimasuiro/ozipdecrypt-tools/security/advisories/new)**.
3. If GitHub Advisories is unavailable, contact the maintainer directly at the email listed on their GitHub profile.

### What to Include in Your Report

- Container type and sample format involved (`.ozip`, `.ofp`, `.ops`, `.zip`).
- Proof-of-concept file or step-by-step reproduction instructions.
- Potential impact (e.g., arbitrary file overwrite outside extraction folder, denial of service).
- Any proposed remediation or patches.

## Security Architecture & Defenses

- **Path Traversal Guard**: All partition and file extraction targets across OFP, OPS, and OZIP containers are validated via `safe_join`, rejecting absolute paths, `..` directory traversal, Windows drive prefixes or NTFS alternate data streams (`:`), and NUL bytes. Note: `.ozip` entries are currently flattened to their base filename, so duplicate filenames across different archive directories will overwrite each other within the target folder.
- **Resource Limits & Allocation Bounds**: Chunk-based streaming (1 MB chunks) prevents unbounded memory consumption on large partitions. Container manifests (Qualcomm XML manifest, OPS XML manifest, decrypt headers, and MediaTek encrypted partition headers) enforce strict length bounds (16 MB ceiling) and arithmetic overflow / file-boundary checks to prevent memory exhaustion from malformed files. The MediaTek secondary partition table enforces a hard count limit of 1,000 entries.
- **Strict Checksum Enforcements**: Inline checksum computation for supported formats with verification before final output promotion.
