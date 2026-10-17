# Implementation Plan: ozipdecrypt-tools

Status: v0.2.0 in the manifests, not yet tagged. Cargo workspace (`ozipdecrypt-core` library + `ozipdecrypt-tools` CLI). CI green on Windows, Linux, and macOS.

## Overview

One Rust toolkit that decrypts and unpacks Oppo/Realme/OnePlus firmware: `.ozip`, Qualcomm `.ofp`, MediaTek `.ofp` and OnePlus `.ops`. It is a port of B. Kerler's MIT-licensed Python tools.

- **v0.2.0 (CLI):** release with an honest verification table (below).
- **v0.3.0 (library + GUI):** finish the core library (progress, cancel, no printing), then a small pure-Rust GUI on top.

---

## Verification Matrix (the source of truth for what is proven)

| Format | Constants vs upstream | Known-answer tests | Real firmware file | Status |
|---|---|---|---|---|
| Qualcomm `.ofp` | Audited by script (6 keysets) | Derived key/IV for all 6 keysets | **Verified**: CPH1901 `.ofp`, 61 of 61 partitions extracted, head MD5 matched `ProFile.xml` for every encrypted partition, container MD5 matches package `md5sum.md5` | **Verified on real data, with the limits below** |
| `.ozip` (standalone, zip modes 1 and 2) | Audited (35 keys) | Synthetic v1, v2, multi-chunk | Not yet. OTA `.ozip` for CPH1901 (mode 2) is downloading | Synthetic only |
| Realme zip `.ofp` | Audited (password) | None | None | Unverified |
| MediaTek `.ofp` | Audited (8 triplets + 1 raw pair) | Derived keys, shuffles | None | Synthetic only |
| OnePlus `.ops` | Audited (`MASTER_KEY`, S-box, `MBOX4/5/6`) | `key_update`, stream vectors including tails, chunked-vs-single | None (synthetic parity only) | Synthetic only |

### Limits of the Qualcomm OFP verification
These are part of the result and are documented in README and `docs/qualcomm_ofp_verification.md`:
1. **The check covers the decryption, not the whole copy.** The cipher only touches the first 0x40000 bytes of each partition. The vendor MD5 is also over that head. A match proves keys, offsets, trailer parsing and CFB decryption. It does not prove the rest of a large partition (copied unchanged) is intact.
2. **Sparse images** (`system`, `vendor`, `userdata`, `persist`): the manifest SHA-256 is of the unsparsed partition, so it never matches the file. Only the head MD5 is checked, so about 256 KB of each is verified.
3. **Rule is "fail only if both hashes are bad"**, as in upstream's `checkhashfile`. A file passes if either hash matches. Rust is stricter than upstream in one respect: it aborts on failure, where upstream only prints a message.
4. **One device, one sample.** Verified on Oppo A7 CPH1901 (Snapdragon 450, Keyset V1.6.6+). Other keysets are covered by constants audit and derived-key vectors only.
5. **The per-partition pass results come from the project's own audit run.** Documented in `docs/qualcomm_ofp_verification.md`.
6. **Source integrity:** verified against the package vendor's bundled `md5sum.md5` (`df77948243b6f97aac579b99b7c37b0b`), verifying the 8.16 GB archive was not corrupted in transfer.

---

## Current Architecture

| Location | Responsibility |
|---|---|
| `crates/ozipdecrypt-core/src/ozip.rs` | `.ozip`: standalone, zip mode 1, zip mode 2, selective partition extraction |
| `.../ofp.rs` | Qualcomm `.ofp` (trailer, A57 fallback, XML manifest, extraction, checksum rules) and Realme zip `.ofp` |
| `.../ofp_mtk.rs` | MediaTek `.ofp` |
| `.../ops.rs` | OnePlus `.ops` (S-box + `MBOX4/5/6`, whole-item tail rule) |
| `.../detect.rs` | Container sniffing, fast on multi-GB inputs |
| `.../info.rs`, `error.rs`, `reporter.rs` | `ContainerInfo`, structured errors, progress/cancel trait |
| `.../crypto.rs` | Nibble swap, key shuffle, MD5 derivation, 35 OZIP keys, 6 Qualcomm keysets, `safe_join` |
| `crates/ozipdecrypt-tools/src/` | CLI (`ozip`, `ofp`, `ops`, `extract`, `info`, `sideload`), `flash.rs`, unit tests (29, one `#[ignore]` that needs a local 5 GB sample) |
| `tools/` | Dev only, excluded from the published crate: `check_constants.py`, `parity.py`, `audit_ofp_hashes.py`, `check_ci.py`, `inspect_modem.py`, `reference/` (4 upstream decryption scripts) |
| `.github/workflows/ci.yml` | fmt, clippy `-D warnings`, constants audit, tests on three operating systems |

"Pure Rust" refers to the shipped crates. Python is verification tooling only. `adb sideload` calls an external `adb`.

---

## Decisions

1. **Atomic output.** Refuse when input and output are the same file; write `<target>.part`, rename on success, remove it on error or cancel.
2. **Bounded streaming.** Fixed-size chunks. Check any length from a file before allocating.
3. **Untrusted input.** `safe_join` rejects absolute paths, `..`, any component with `:`, empty names and NUL. Checksum failure aborts.
4. **Match upstream exactly,** including quirks, with test vectors from upstream output. Where Rust is stricter (aborting on a bad hash), say so.
5. **Licensing.** MIT crate; `LICENSE` keeps Kerler's notice; `edl` is never ported; `backdoor.py` and the Frida script are removed.
6. **Pure-Rust GUI only** (`egui`/`eframe`), no web view.
7. **Never claim "verified" for a format without a real-file result.** The GUI shows the same notice.
8. **Device safety (CPH1901 work).** Extracted firmware is reference material. Never flash `persist.img` from a factory image: it replaces the unit's own Wi-Fi/Bluetooth MAC and calibration data. Back up the phone's own partitions before any flash.

---

## Phases

### Phases 1-4: implemented
All four engines, auto-detection, `extract`, `info`, selective `.ozip` extraction.

### Phase 5: Verification and v0.2.0 release (in progress)

Done:
- Constants audit in CI; known-answer tests; detection and corrupt-file tests; three-OS CI; packaging excludes; README updated; OPS whole-item tail fix with chunk-boundary tests
- Checksum rule matches upstream and has a unit test for pass and hard-fail cases
- **Qualcomm OFP verified on a real file** (see the matrix and limits)
- Verification matrix and limits added to README and release notes
- Keyset recorded (V1.6.6+ set, Snapdragon 450, Project 15103)
- Audit output documented in `docs/qualcomm_ofp_verification.md`
- Checked `.ofp` against package's `md5sum.md5` (100% bit-for-bit match: `df77948243b6f97aac579b99b7c37b0b`)

Open:
- OTA `.ozip` real run with `tools/parity.py` (mode 2)
- Benchmark: MB/s and peak RSS on the 8 GB `.ofp`
- `--verify-source` option (compare the container with a given MD5) so users don't have to do it by hand
- Optional: hash the full unsparsed image for sparse partitions so the manifest SHA-256 can be checked
- Tag `v0.2.0` (with verification matrix in release notes)

Release rule: v0.2.0 can be tagged now with the verification matrix in the README, since one format is verified on real data. Waiting for the `.ozip` result first is better if it arrives soon, because it covers the CPH1901 mode-2 path most users have. Any format still marked "Synthetic only" or "Unverified" must say so in the release notes.

### Phase 6: Core library extraction (v0.3.0, step 1)

Done:
- Cargo workspace: `ozipdecrypt-core` (lib) + `ozipdecrypt-tools` (CLI)
- `error.rs`, `reporter.rs`, `info.rs`, `extract.rs` created and integrated
- `info` lists partitions, sizes, encryption status, SoC/project
- Core library completely silent: zero `println!` calls, all events via `ProgressReporter`
- Structured error handling: `ChecksumStatus` (`VerifiedFull`, `VerifiedHeadOnly`, `NoHashInManifest`, `Failed`)
- Per-format verification level exposed (`Verified`, `SyntheticOnly`, `Unverified`)
- Unified `extract(ExtractRequest, &dyn ProgressReporter) -> Result<ExtractSummary>`
- Cancel checked per-chunk in every engine with atomic `.part` cleanup on error or cancel
- Test coverage: `test_cancel_mid_extraction_leaves_no_partial_output` and all 31 tests passing
- CLI is a thin layer using `TerminalReporter`; `parity.py` 100% bit-for-bit parity
- Public API contract matching Phase 7 section 7.2 requirements exactly

Phase 6 Follow-ups (Code Review Feedback, to complete before Phase 7):
1. Error downcasting in `extract()`: Preserve `OzipError` (`Cancelled`, `KeyNotFound`, `ChecksumMismatch`, etc.) rather than flattening to `Other("...")`. Assert `Cancelled` specifically in unit test.
2. Partition selection semantics: `None` = extract all; `Some([])` = error; `Some(list)` = extract all matching items with exact filename matching across OFP, MTK, OPS, and OZIP.
3. Single-pass checksums in `ofp.rs`: Compute MD5, head SHA-256 (first 0x40000), and full SHA-256 simultaneously in one pass with per-chunk cancellation and progress events.
4. Minor fixes: Handle `<= 0x40000` partitions as `VerifiedFull` on match, propagate `f.read()` errors in checksum loops, fix extensionless `.part` filename logic, and fix Qualcomm cipher doc to AES-128-CFB in `lib.rs`.

### Phase 7: GUI (v0.3.0, step 2)

`ozipdecrypt-gui`: a small pure-Rust desktop front end (`egui`/`eframe`) over `ozipdecrypt-core`. It does no cryptography of its own. If a behaviour is not in the core, the GUI does not have it.

**Gate (do not start 7.1 before this is true):** v0.2.0 is tagged, and Phase 6 is finished: no `println!` in the core, events go through the reporter, cancel works in every engine, and `parity.py` output is unchanged.

#### 7.0 Goals and non-goals
- Goal: a user with a firmware file can drag it in, see what it is and whether this tool has been verified for it, pick partitions, extract, and open the result folder, without a terminal.
- Primary platform: Windows 10/11. Linux and macOS must build and run, with lower testing effort.
- Non-goals for this release: sideload or any flashing, `keys.toml` editing (a picker for an existing file is fine), re-encryption, batch queues, a settings dialog beyond theme, auto-update, translations.

#### 7.1 Technical decisions
1. **Crate layout:** `crates/ozipdecrypt-gui` depends only on `ozipdecrypt-core`, never on the CLI crate. The GUI binary name is `ozipdecrypt-gui`.
2. **Toolkit:** `eframe`/`egui`, versions pinned in `Cargo.lock` and bumped deliberately. File dialogs through `rfd`. No async runtime and no web view.
3. **Threading:** one worker thread per job (`std::thread` plus an `mpsc` channel). The worker holds a reporter that sends events to the UI and calls `ctx.request_repaint()`. Cancel is an `AtomicBool` read by `is_cancelled()`. The UI thread never touches the filesystem except to read metadata for display.
4. **One source of truth for status text:** the core exposes the verification level per format (`Verified`, `SyntheticOnly`, `Unverified`, matching the matrix above) and a checksum status per item. The CLI, GUI and README read the same values.
5. **No printing in the core,** so the GUI shows only structured events, never scraped terminal text.

#### 7.2 Core API the GUI needs (to be agreed in Phase 6, not invented in the GUI)
- `detect(path) -> ContainerKind`
- `info(path) -> ContainerInfo`: kind, verification level, device or SoC and project where known, total size, and partitions (name, size, encrypted flag, hash available or not)
- `extract(ExtractRequest { input, out_dir, partitions: Option<Vec<String>> }, &dyn ProgressReporter) -> Result<ExtractSummary, CoreError>`
- Events: `Started`, `ItemStarted { name, size }`, `Progress { bytes_done, bytes_total }`, `ItemDone { name, checksum }`, `Warning(String)`, `Finished`
- `ChecksumStatus`: `VerifiedFull`, `VerifiedHeadOnly` (sparse images and anything covered only by the head hash), `NoHashInManifest`, `Failed`
- `CoreError` variants the UI maps to plain language: `KeyNotFound`, `UnsupportedContainer`, `Truncated`, `PathRejected`, `ChecksumMismatch`, `Cancelled`, `Io`

#### 7.3 Screens and state machine
`Idle -> Inspecting -> Ready -> Extracting -> Done | Failed | Cancelled`, and any end state returns to `Idle` or `Ready`.
- **Idle:** large drop area plus "Choose file". Text states what is supported.
- **Inspecting:** spinner. Inspection runs on the worker thread, since `info` is fast but a slow disk must not freeze the window.
- **Ready:** shows the file name and size, detected type, device/SoC, a verification badge, and the partition list with sizes. Checkboxes with select all / none and a filter box. Output folder row (default `<input name>_extracted` next to the input). "Extract" button.
- **Extracting:** overall progress bar, current item with its own bar, bytes and MB/s, elapsed time, Cancel button. Cancel stops at the next chunk and removes the `.part` file.
- **Done:** list of files written with checksum status per item, warnings, "Open folder", "Copy log", "Extract another".
- **Failed / Cancelled:** a short plain-language reason, the technical message under "Details", and the same buttons.

#### 7.4 Safety and trust rules (these are requirements, not polish)
1. **Verification badge on every file.** Formats marked `SyntheticOnly` or `Unverified` show an amber "not yet verified on real firmware" notice before extraction and again on the result screen. Qualcomm `.ofp` shows "verified on one real file (Oppo A7); see limits".
2. **Never claim more than the check proved.** `VerifiedHeadOnly` is shown as "head checked only", not as a green tick. `NoHashInManifest` is shown as "no checksum available".
3. **Never overwrite the input;** refuse an output folder equal to the input's folder when that would collide. Warn before writing into a non-empty folder and let the user choose.
4. **Disk space check** before starting: total selected size against free space on the output drive, with a clear message.
5. **Device-data warning:** when a partition named like `persist`, `modemst1/2`, `fsg`, `nvbk` or `nv*` is selected, show "Device-specific data. Never flash a factory copy onto a phone."
6. **No flash button, no adb.** The GUI never touches a device in this release.
7. **Path handling:** non-ASCII paths, spaces and long Windows paths work; names from inside containers always go through `safe_join` in the core.
8. **No network access** and no telemetry.

#### 7.5 Testing
- **State-machine tests** with no rendering: feed events, assert transitions and counters (including cancel at each state, and an error mid-extraction).
- **Core integration test** driving `extract` with a recording reporter, to check that the event order and checksum statuses match what the screens expect.
- **Compile in CI** on Windows, Linux and macOS (`cargo build -p ozipdecrypt-gui`, clippy `-D warnings`). Rendering tests are optional.
- **Manual matrix (Windows first):** small synthetic files of each format; the real CPH1901 `.ofp`; cancel mid-extraction; read-only output folder; low disk space; non-ASCII path; path with spaces; drag a folder or a wrong file type; file dropped while a job is running.
- **Acceptance:** extracting the real CPH1901 `.ofp` in the GUI gives the same SHA-256 for every output file as the CLI. Peak memory stays near the CLI's.

#### 7.6 Packaging and release
- CI release job on a version tag builds `ozipdecrypt-gui` and the CLI for Windows (x86_64), Linux (x86_64) and macOS (arm64 and x86_64), and attaches them to the GitHub release with a `SHA256SUMS` file.
- Windows: static C runtime so no redistributable is needed. Plain `.exe` and `.zip` first, no installer.
- Binaries are unsigned in this release. Say so in the README: Windows SmartScreen and macOS Gatekeeper will warn, and some antivirus tools flag decryption utilities. Code signing is a later decision.
- README: screenshot, a three-step "drag, choose, extract" guide, the verification matrix, and the unsigned-binary note.

#### 7.7 Milestones and exit criteria
| Milestone | Content | Exit criterion |
|---|---|---|
| M1 Skeleton & Inspection | Crate `crates/ozipdecrypt-gui`, window, file picker (`rfd`) + drag-and-drop, worker thread running `detect` and `info`, format/device/keyset display, verification badge, partition list, `keys.toml` picker, matching `OzipError` variants, no flashing | `cargo build --workspace` and clippy `-D warnings` pass; opens real CPH1901 `.ofp` without UI freeze and displays partitions; shows clear error on non-firmware file |
| M2 Extraction & Cancellation | Partition checkboxes (all/none/filter), output dir picker, worker thread running `extract`, per-chunk progress reporting (`ProgressEvent`), `AtomicBool` cancel, atomic `.part` cleanup | Cancelling extraction removes `.part` immediately; no UI freeze on large archives; outputs bit-identical to CLI |
| M3 Results and Safety | Done/Failed/Cancelled screens, checksum status per item (`VerifiedFull`, `VerifiedHeadOnly`, `NoHashInManifest`), disk space pre-check, device-data warnings (`persist`, `modemst*`, `fsg`) | All Section 7.4 safety rules verified by test or manual check |
| M4 Packaging | Release workflow for Windows, Linux, macOS, static C runtime on Windows, `SHA256SUMS`, README guide with screenshots | Tagged release build produces downloadable standalone binaries |
| M5 Acceptance | Real-file comparison with the CLI on CPH1901 `.ofp` | Identical SHA-256 for all 61 output partitions; tag `v0.3.0` |

#### 7.8 GUI-specific risks
| Risk | Impact | Mitigation |
|---|---|---|
| Interface hides the "unverified" status | High | badge is mandatory (7.4), covered by a state test |
| Core still blocks without checking cancel, so Cancel does nothing | Med | Phase 6 requires a cancel check per chunk and a test |
| `egui`/`eframe` API changes between versions | Med | pin versions, upgrade deliberately |
| File dialogs on Linux depend on desktop portals or GTK | Low | document the dependency; fall back to typing a path |
| Unsigned binary triggers SmartScreen or antivirus | Med | say so in the README; publish `SHA256SUMS`; consider signing later |
| Progress is inaccurate for sparse images or multi-GB copies | Low | base progress on bytes read from the input; label it as approximate |
| GUI drifts from the CLI's behaviour | Med | both call the same core API; acceptance test compares outputs |

### Phase 8: Later
Sideload tab with safeguards; re-encryption only if upstream has a tested path.

---

## Side Track: CPH1901 Wi-Fi

- The phone (CPH1901, build `CPH1901EX_11_A.22`, SDM450) was connected and healthy when checked: valid MAC, -47 dBm, 72 Mbps, no packet loss.
- No symptom is known yet, so **no flashing**.
- Steps: record the symptom (when, how often) and read-only `adb` diagnostics; if a modem mismatch is suspected, compare the installed modem build with the stock `NON-HLOS.bin`; back up the phone's own `persist`, `modem`, `modemst1/2`, `fsg` before any flash; flash only the modem partition if a flash is ever needed.
- The extracted `persist.img` is reference only.

---

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| "Verified" claimed for formats with only synthetic tests | High | verification matrix; README and GUI notices |
| Large partitions copied without full integrity check | Med | `md5sum.md5` check, `--verify-source`, optional sparse hashing |
| Output wrong on real files for the other formats | High | real-file runs for `.ozip`, `.ops`, MTK before dropping "unverified" |
| Flashing generic `persist` over a phone's own data | High | never flash it; back up first |
| Core still prints; GUI cannot show progress cleanly | Med | finish Phase 6 before GUI work |
| Platform-specific bugs | Med | three-OS CI |
| Crafted or truncated container | Med | `safe_join`, bounds checks, corrupt-file tests |
| GPLv3 / non-commercial taint from `edl` | High | external command only |

---

## Checkpoints

1. Phase 1 stable (done).
2. Engines and detection implemented (done).
3. Constants audit in CI (done).
4. OPS tail fix with chunk tests (done).
5. Qualcomm OFP verified on a real file, limits documented (done).
6. v0.2.0 tagged with the verification matrix.
7. Core library complete: no printing, cancel everywhere (Phase 6).
8. GUI released with prebuilt binaries (Phase 7).
