# Changelog

All notable changes to the Nupull project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.2] - Proposed Stable Release (Release Candidate: 1.0.2-rc.1)

### Security
- **Windows Reserved Device Protection (SEC-08)**: Hardened `_safe_resolve` in `unpack.py` and `_safe_export_path` in `export.py` to strictly reject Windows special device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) and paths with trailing dots or whitespace.
- **Prospective Decompression Bomb Guards (SEC-07)**: Enforced proactive size checks in solid NCZ decompression before writing data chunks to disk, preventing disk-exhaustion attacks.
- **Path Traversal Defenses**: Reinforced directory containment checks using strict relative path resolution across all extraction and export pathways.

### Performance
- **Streaming NSP Exporter (PERF-03)**: Redesigned installable NSP export to use layout-first streaming where metadata tables are precomputed in small RAM buffers (~50 KB) and extents stream directly from the NUP archive to disk, maintaining a process RSS delta under 4.5 MiB and Python heap under 2.2 MiB regardless of game size.
- **Bounded Memory Hashing (MEM-02)**: Implemented chunked SHA-256 streaming verification via `NupReader.hash_file()`, eliminating full-file memory allocations during deep verification.
- **Streaming Patch Engine**: Added `StreamingZstdReader` in `patch.py` to stream large untouched extents (>16 MiB) without buffering uncompressed data in RAM.

### Fixed
- **NCZ Solid Decompression on Bounded Slices**: Fixed an `UnpackError: read out of range` failure in `_RangeReader` when solid NCZ compressed streams end within a chunk smaller than the 128 KB zstd buffer.
- **BKTR Update Error Handling**: Resolved silent dropping of RomFS files when converting BKTR updates without a base game by raising an explicit, actionable `UnpackError`.
- **Path Object Handling in Pack**: Fixed a `TypeError` when `pathlib.Path` instances were passed to `pack(out_path, src)`.
- **Cooperative Cancellation**: Added cancellation callbacks throughout packing and extent-writing routines to ensure immediate cleanup of partial files.

### Reliability
- **Atomic Operations & Cleanup**: Guaranteed all-or-nothing container replacement using `.partial` staging, ensuring interrupted writes leave original files intact with zero residue.
- **Handle & Resource Safety**: Verified zero file descriptor leaks (`fd_diff = 0`) across repeated conversion and verification cycles.

### Testing & Quality Assurance
- **Expanded Regression Suite**: Increased regression checks to 165 automated test cases covering adversarial inputs, corrupt TOCs, and boundary conditions.
- **End-to-End Multi-Pathway Validator**: Created `tests/e2e_roundtrip.py` verifying 5 complete conversion pipelines:
  - Pathway 1: NSP → NUP → NSP (Byte-Identical & Semantically Lossless)
  - Pathway 2: XCI → NUP → Dump (Semantically Lossless)
  - Pathway 3: Atmosphere LayeredFS Mod Patching (Intentionally Transformed)
  - Pathway 4: NSZ → NUP → NSP (Byte-Identical & Lossless)
  - Pathway 5: Multi-Package All-in-One Consolidation (Semantically Lossless)
- **Endurance & Fault Injection Suite**: Created `tests/endurance_test.py` simulating mid-write interruptions, permission blocks, and concurrent multi-thread packing.
- **True Peak Memory Profiler**: Added `tests/benchmark_perf.py` utilizing high-frequency OS kernel sampling to verify bounded RSS scaling across workloads up to 1 GiB.

### Packaging & CI/CD
- **Two-Stage Hardened Release Workflow**: Separated build/verification from publication in GitHub Actions with read-only permissions during compilation and strict semver classification preventing release candidates from being marked as stable.
- **Unified Version Reporting**: Added `--version` CLI flag to `nupull` and GUI window title reporting synchronized with `tools/nup/nup/__init__.py`.
- **Automated Checksum Generation**: Integrated SHA-256 checksum generation for standalone executables and release archives.

---

## [1.0.1] - 2026-11-14

### Fixed
- Fixed memory streaming for large compressed entries.
- Resolved path resolution edge cases on Windows systems.
- Added GUI smoke test automation.

---

## [1.0.0] - 2026-11-13

### Added
- Initial release of the NUP (NX Package) container format reference implementation.
- Support for NSP, XCI, NSZ, XCZ container unpacking and consolidation.
- Desktop GUI application built with PyQt6.
- Command-line interface (`nupull` / `nup`).
