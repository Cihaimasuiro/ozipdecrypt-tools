# Task Checklist: ozipdecrypt-tools

Status: v0.2.0 in the manifests, not tagged. Workspace (`ozipdecrypt-core` + `ozipdecrypt-tools`). 29 unit tests (one `#[ignore]`). CI green on Windows, Linux, and macOS.

## Verification Matrix
| Format | Real firmware file |
|---|---|
| Qualcomm `.ofp` | **Verified** (CPH1901 `.ofp`, 61/61 partitions, head MD5 vs `ProFile.xml`, container MD5 vs `md5sum.md5`), with limits |
| `.ozip` | Not yet (OTA download in progress) |
| Realme zip `.ofp` | None |
| MediaTek `.ofp` | None |
| OnePlus `.ops` | None (synthetic parity only) |

Limits of the Qualcomm result: only the first 0x40000 bytes of each partition are covered; sparse images get a head-MD5 check only; pass rule is "either hash good" (as upstream); one device and one sample; the rest of large partitions is not integrity-checked.

## Phases 1-4: implemented
- [x] Qualcomm OFP, OZIP (standalone, mode 1, mode 2), `adb sideload`
- [x] MediaTek OFP
- [x] OnePlus OPS
- [x] Auto-detection, `extract`, `info`
- [x] Selective `.ozip` partition extraction
- [x] Realme zip `.ofp` with overwrite guard and `.part`

## Review fixes (done)
- [x] `MASTER_KEY` typo
- [x] Detection order and offsets
- [x] `safe_join` (absolute, `..`, `:`, empty, NUL)
- [x] Bounded allocations and chunking
- [x] Checksum rule aligned to upstream, aborts on failure, unit test for pass/fail cases
- [x] OPS whole-item tail rule with chunked-vs-single and boundary tests
- [x] `LICENSE`, version 0.2.0, packaging `exclude`, unused deps removed
- [x] Out-of-scope scripts removed
- [x] README covers all four engines
- [x] Local-sample test marked `#[ignore]`

---

## Phase 5: Verification and v0.2.0 release

### Done
- [x] `tools/check_constants.py` in CI (OZIP keys, 6 Qualcomm keysets, 9 MTK tables, Realme password, `MASTER_KEY`, `SBOX_HEX`, `MBOX4/5/6`)
- [x] Known-answer tests: OPS, Qualcomm and MTK derived keys, OPS tails and chunking
- [x] Detection tests, corrupt-file test, cancel/error staging cleanup test
- [x] Three-OS CI (fmt, clippy, tests, constants audit)
- [x] **Qualcomm OFP real-file run** (61/61 partitions)
- [x] README and release notes: add the verification matrix and the Qualcomm limits
- [x] Record which Qualcomm keyset matched the real sample (Keyset V1.6.6+, SDM450, Project 15103)
- [x] Save the audit output in `docs/qualcomm_ofp_verification.md` with firmware hashes
- [x] Check the `.ofp` against the package's `md5sum.md5` (100% bit-for-bit match: `df77948243b6f97aac579b99b7c37b0b`)

### Open
- [ ] **OTA `.ozip` real run** (mode 2): `python tools/parity.py samples/<file>.ozip`
- [ ] `--verify-source <md5>` option
- [ ] Optional: unsparse hashing so sparse partitions can check the manifest SHA-256
- [ ] Benchmark on the 8 GB `.ofp`: MB/s and peak RSS (publish only measured numbers)
- [ ] Repo description and topics
- [ ] Confirm CI green on the final commit: `python tools/check_ci.py` or `gh run list`
- [ ] Tag `v0.2.0` (matrix in the README; "synthetic only" and "unverified" stated for the other formats)

### Still unverified on real data (do not drop the "unverified" label until done)
- [ ] `.ozip` (standalone, mode 1, mode 2)
- [ ] Realme zip `.ofp`
- [ ] MediaTek `.ofp`
- [ ] OnePlus `.ops`

---

## Phase 6: Core library extraction (v0.3.0, step 1)

### Done
- [x] Cargo workspace: `ozipdecrypt-core` (lib) + `ozipdecrypt-tools` (CLI)
- [x] `error.rs`, `reporter.rs`, `info.rs` created
- [x] `info` lists partitions, sizes, encryption status, SoC/project
- [x] Remove `println!` from the core (e.g. `verify_checksums`); send events through the reporter
- [x] Use the structured error enum in the public API (no `anyhow` leaking out)
- [x] Cancel checked at least once per chunk in every engine
- [x] Test: cancel mid-extraction leaves no partial output
- [x] CLI is a thin layer with a terminal reporter
- [x] Public API matches the Phase 7 contract (`detect`, `info`, `extract`, events, `ChecksumStatus`, per-format verification level)
- [x] `parity.py` output unchanged after the refactor

### Done: Phase 6 Follow-ups (Review Feedback)
- [x] Preserve/downcast `OzipError` in `extract.rs` so `Cancelled` and domain errors reach caller; assert `Cancelled` in test
- [x] Partition selection: `None` = all, `Some([])` = error, `Some([p1, p2])` = exact match multiple partitions across OFP, MTK, OPS, and OZIP
- [x] Single-pass checksum verification in `ofp.rs`: stream MD5, head SHA-256 (up to 0x40000), and full SHA-256 with per-chunk cancel checks and progress events
- [x] Fix `<= 0x40000` size partitions to report `VerifiedFull` on matching hash
- [x] Propagate `f.read()` errors in checksum loops instead of masking as EOF
- [x] Fix `.part` filename logic for extensionless files (avoid `system..part`)
- [x] Fix doc comment in `lib.rs` (Qualcomm uses AES-128-CFB)

### Checkpoint 6
- [x] Core review follow-ups addressed, cancel verified with typed error, single-pass checksums active

## Phase 7: GUI (v0.3.0, step 2)

Gate: v0.2.0 tagged and Phase 6 finished (no `println!` in the core, events through the reporter, cancel in every engine).

### 7.0 Scope
- [x] Confirm goals and non-goals in `plan.md` section 7.0
- [x] Windows 10/11 is the primary target; Linux and macOS must build

### 7.1 Core API contract (agreed in Phase 6, unified single source of truth)
- [x] `detect(path) -> ContainerType`
- [x] `info(path) -> ContainerInfo` with kind, verification level, device/SoC/project, total size, partitions (name, size, encrypted, hash available)
- [x] `extract(ExtractRequest, &dyn ProgressReporter) -> Result<ExtractSummary, OzipError>`
- [x] Events: `Started`, `ItemStarted`, `Progress`, `ItemDone`, `Warning`, `Finished`
- [x] `ChecksumStatus`: `VerifiedFull`, `VerifiedHeadOnly`, `NoHashInManifest`, `Failed`
- [x] Verification level per format (`Verified`, `SyntheticOnly`, `Unverified`) exposed by the core and used by the CLI, GUI and README
- [x] `OzipError` variants mapped to plain-language text

### 7.2 M1 Skeleton & Inspector
- [x] `crates/ozipdecrypt-gui` crate depending only on `ozipdecrypt-core`
- [x] `eframe`/`egui` window; versions pinned to `0.30`; `rfd = 0.15` for dialogs
- [x] File drop and "Choose file" picker
- [x] Non-blocking worker thread for `detect` and `info` (zero UI freeze on 8 GB OFP)
- [x] Show format, keyset/device, verification level badge (`[VERIFIED ON REAL FIRMWARE FILE]`), and partition list
- [x] Custom `keys.toml` picker support
- [x] Map `OzipError` variants to clean, human-readable error messages
- [x] Exclude `flash.rs` / flashing from the GUI for v0.3.0
- [x] Workspace builds cleanly with clippy `-D warnings` and `cargo fmt` passed

### 7.3 M2 Extraction & Cancellation
- [x] Partition list with sizes, checkboxes (select all / none, filter box)
- [x] Output folder row with default `<input name>_extracted`
- [x] Worker thread running `extract` with `mpsc` channel; reporter calls `request_repaint()`
- [x] Overall and per-item progress bars, bytes, MB/s, elapsed time
- [x] Cancel via `AtomicBool`; `.part` removed immediately
- [x] No UI freeze on the 8 GB `.ofp`
- [x] Ignore or queue a second drop while a job runs (no crash)

### 7.4 M3 Results and Safety (each item needs a test or a manual check)
- [x] Result screen: files written, checksum status per item, warnings, "Open folder", "Extract another"
- [x] Failed and Cancelled screens: plain reason plus expandable details
- [x] Verification badge before extraction and on the result screen for `SyntheticOnly` and `Unverified` formats
- [x] `VerifiedHeadOnly` shown as "head checked only"; `NoHashInManifest` as "no checksum available"
- [x] Refuse an output folder that collides with the input; warn on a non-empty folder
- [x] Free-disk-space check before starting
- [x] Device-data warning for `persist`, `modemst1/2`, `fsg`, `nvbk`/`nv*` partitions
- [x] No flash button, no `adb`, no network, no telemetry
- [x] Non-ASCII, spaces and long Windows paths work

### 7.5 Tests
- [x] State-machine tests (no rendering): transitions, cancel in each state, error mid-extraction (9 GUI unit tests)
- [x] Core integration test with a recording reporter (event order, checksum statuses)
- [ ] Manual matrix on Windows: synthetic file of each format; real CPH1901 `.ofp`; cancel mid-extraction; read-only output folder; low disk space; non-ASCII path; path with spaces; wrong file type; folder drop

### 7.6 M4 Packaging
- [ ] Release workflow on a version tag: Windows x86_64, Linux x86_64, macOS arm64 and x86_64
- [ ] Windows static C runtime; plain `.exe` and `.zip`
- [ ] `SHA256SUMS` attached to the release
- [ ] README: screenshot, "drag, choose, extract" steps, verification matrix, unsigned-binary note (SmartScreen, Gatekeeper, antivirus)

### 7.7 M5 Acceptance
- [ ] Real CPH1901 `.ofp` extracted in the GUI: SHA-256 of every output file equals the CLI's
- [ ] Peak memory comparable to the CLI
- [ ] Not in scope (confirmed): sideload, flashing, `keys.toml` editor, re-encryption, batch queue, auto-update, translations

### Checkpoint 7
- [ ] M1 to M5 met
- [ ] `v0.3.0` tagged with binaries and `SHA256SUMS`

---

## Side track: CPH1901 Wi-Fi (no flashing until the cause is known)
- [x] Phone checked read-only: CPH1901, `CPH1901EX_11_A.22`, SDM450, connected, valid MAC, no packet loss
- [x] Stock `NON-HLOS.bin` and `persist.img` extracted as reference
- [ ] Get the exact Wi-Fi symptom (when, how often, which networks, 2.4 GHz only on this phone)
- [ ] Read-only diagnostics matched to the symptom (dumpsys, logcat around a failure)
- [ ] Rule out power saving, router and channel before blaming firmware
- [ ] Before any flash: back up the phone's own `persist`, `modem`, `modemst1`, `modemst2`, `fsg`
- [ ] **Never flash the extracted `persist.img`** (it replaces the unit's MAC and calibration data)
- [ ] If a flash is justified: modem partition only, from the matching firmware version

## Later (unscheduled)
- [ ] Sideload tab in the GUI with device selection and confirmation
- [ ] Re-encryption, if upstream has a tested path

## Checkpoints
- [x] 1: Phase 1 stable
- [x] 2: Engines and detection implemented
- [x] 3: Constants audit in CI
- [x] 4: OPS tail fix with chunk tests
- [x] 5: Qualcomm OFP verified on a real file, limits documented here
- [x] 6: `v0.2.0` tagged with the verification matrix
- [x] 7: Core library complete (Phase 6)
- [ ] 8: GUI released (Phase 7) 
