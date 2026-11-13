# Nupull — Modern NX Container Studio

<p align="center">
  <img src="assets/nupull.png" alt="Nupull Logo" width="140" height="140">
</p>

<p align="center">
  <strong>High-performance, All-in-One container format, batch converter, LayeredFS mod patcher, and bidirectional exporter for Nintendo Switch (1 & 2).</strong>
</p>

<p align="center">
  <a href="https://github.com/m7kor/nupull/actions"><img src="https://img.shields.io/badge/CI-passing-brightgreen?style=flat-square&logo=github" alt="CI Status"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?style=flat-square&logo=python" alt="Python Versions"></a>
  <a href="https://mypy-lang.org/"><img src="https://img.shields.io/badge/MyPy-strict%20clean-blueviolet?style=flat-square" alt="MyPy Strict"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
</p>

---

## Overview

**Nupull** is an open-source, clean-room container suite and desktop studio built around the **`.nup` (NX Package)** container specification. It solves the fragmentation of modern Switch game archives by unifying Base games, Updates, and all DLC addons into a single, high-speed, Zstandard-compressed, atomically verified container.

```
Base Game (v0)  +  Update (v458752)  +  DLC Addons (0..N)
┌────────────────────────────────────────────────────────┐
│               Unified .nup Container                   │
│  • ExeFS binaries & main.npdm (Build-ID indexed)       │
│  • Full RomFS hierarchy with content deduplication     │
│  • Per-file SHA-256 integrity verification             │
│  • Multi-threaded parallel Zstandard compression       │
└────────────────────────────────────────────────────────┘
```

---

## Key Features

- **🚀 All-in-One Container Architecture**: Consolidates base game, multiple title updates, and multiple DLCs into one single `.nup` container with zero redundant data.
- **⚡ High-Speed Direct Conversion (`nupull convert`)**: Directly convert raw dumps (`.nsp`, `.nsz`, `.xci`, `.xcz`) into `.nup` containers with in-memory virtual RomFS streaming (saving 50%+ temporary disk space).
- **📦 Multi-Game Batch Converter (`nupull batch`)**: Scans massive directories containing hundreds of mixed dumps, inspects CNMT content meta headers in milliseconds, automatically pairs Base games with their matching Updates and DLCs, and converts them in parallel across all CPU cores.
- **🎮 LayeredFS Mod Manager (`nupull patch`)**: Applies Atmosphere `contents/<tid>/...` or raw `romfs/exefs` mod directories directly into existing `.nup` containers with atomic verification—no need to extract gigabytes of data to disk.
- **🔄 Bidirectional Exporter (`nupull export`)**: Export `.nup` containers directly to Atmosphere SD card structure (`atmosphere/contents/<tid>/...` ready for MicroSD), standard multi-package dump layout (`base/`, `updates/`, `dlc/`), or repacked installable Nintendo Submission Packages (`.nsp`).
- **🛡️ 100% Atomic & Resilient**: All container creation and patching operations write to temporary `.partial` files and swap atomically. Interrupted runs, full disks, or crashes never corrupt existing data.
- **🖥️ Standalone Desktop GUI**: Beautiful, high-tech dark studio interface built with PyQt6, featuring live throughput metrics, ETA, cooperative cancellation, and native desktop execution.

---

## Installation & Quick Start

### 1. Download Standalone Executable (Windows)
Prebuilt standalone Windows binaries (`Nupull.exe`) that require no Python installation are available on the **[Releases](https://github.com/m7kor/nupull/releases)** page.

### 2. Install via pip
```bash
# Clone the repository
git clone https://github.com/m7kor/nupull.git
cd nupull

# Install package with GUI dependencies
pip install .[gui]
```

### 3. Launch the Desktop GUI
```bash
# Run via CLI launcher
nupull-gui

# Or run directly via Python
python nup_gui.py
```

---

## Desktop GUI Studio

The Nupull Desktop Studio organizes all workflows into clean, dedicated categories:

| Category | Tools & Tabs | Purpose |
|---|---|---|
| **Conversion Pipeline** | `Auto Build`, `Batch Convert`, `Unpack & Convert` | One-shot drag-and-drop builds, folder batch conversion, direct NSP/XCI streaming. |
| **Container Tools** | `Container Info`, `Deep Verify`, `Extract Tree`, `Edit Metadata`, `Pack Dump` | Inspect header metadata, verify SHA-256 hashes, extract files, update title information. |
| **Mods & Export** | `Mod Manager`, `Bidirectional Exporter` | In-place LayeredFS mod patching and exporting to Atmosphere SD card or `.nsp`. |

---

## Command-Line Interface (CLI)

Nupull includes a comprehensive, scriptable command-line interface:

### 1. Auto Build (One-Shot Scan, Pack, and Verify)
```bash
# Scan a dump directory, pack it, and verify in one shot
nupull auto ./my_game_dump ./my_game.nup

# Force atomic overwrite of existing container
nupull auto ./my_game_dump ./my_game.nup --force
```

### 2. Batch Convert Folder of Mixed Dumps
```bash
# Scan directory, group bases with updates & DLCs, and convert in parallel
nupull batch ./SwitchDumps ./OutputContainers --threads -1

# Fast conversion (skip deep SHA-256 recomputation)
nupull batch ./SwitchDumps ./OutputContainers --fast
```

### 3. LayeredFS Mod Patching
```bash
# Apply a translation or texture mod directly to a container in-place
nupull patch ./game.nup ./mod_directory

# Apply mod and output to a new container
nupull patch ./game.nup ./mod_directory ./game_modded.nup
```

### 4. Bidirectional Exporter
```bash
# Export container to Atmosphere SD card structure on a MicroSD card (e.g. E:\)
nupull export ./game.nup E:\ --format atmosphere

# Export container back to an installable .nsp package
nupull export ./game.nup ./repacked_game.nsp --format nsp
```

### 5. Direct Single Dump Conversion
```bash
# Stream an NSP, NSZ, XCI, or XCZ directly into a .nup container
nupull convert ./SuperGame.nsp ./SuperGame.nup
```

### 6. Verification and Inspection
```bash
# Display container structure, title IDs, and metadata
nupull info ./game.nup

# Verify container structural integrity and SHA-256 hash tree
nupull verify ./game.nup --deep
```

---

## Container Format Specification

For detailed binary layouts, node structures, header flags, and compression algorithms, see **[SPEC.md](SPEC.md)**.

---

## Security & Clean-Room Legal Notice

- **No Proprietary Keys**: Nupull is a clean-room, open-source container implementation. It **does not bundle, embed, or distribute** any proprietary Nintendo cryptographic keys (`prod.keys`, `title.keys`, master keys).
- **Bring Your Own Keys (BYOK)**: Operations that decrypt official NCA partitions require user-supplied keys dumped from their own hardware (placed in `~/.switch/prod.keys` or specified via `--keys`).
- **Independent Tooling**: This project is not affiliated with, endorsed, or sponsored by Nintendo. All trademarks belong to their respective owners.
- **Fair Use & Archival**: Intended strictly for personal archival, homebrew execution, and game modding on legally owned software backups.

---

## License

Nupull is released under the **[MIT License](LICENSE)**.
