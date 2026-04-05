# checkARB

> Qualcomm Anti-Rollback (ARB) Metadata Analysis GUI

[中文](README_CN.md) · English

## Built-in Tools

| Tool | Description |
|------|-------------|
| **arbscan** | Extract OEM ARB metadata from bootloader images (e.g. xbl_config.img), with JSON output |
| **arb_inspector** | Parse ELF/MBN firmware images for ARB values, metadata versions, and segment hashes (source embedded) |
| **arbextract** | Extract ARB-related information from firmware images to a target directory |

## Features

- Visual GUI with bottom tab bar for quick tool switching
- File picker + config panel + scrollable output
- arbscan: optional device model / update label annotations, auto-generate JSON
- arb_inspector: debug mode with detailed segment parsing output
- Bilingual UI (Chinese / English), switchable via menu or top-right corner
- Built-in license viewer (MIT / Apache 2.0)

## Build

```bash
cargo build --release
```

Output: `target/release/checkARB.exe`

## Dependencies

- Rust 1.70+
- `egui` / `eframe` — GUI
- `sha2` / `digest` — SHA-256 hashing
- `rfd` — File dialogs
- `serde` / `serde_json` — JSON serialization
- `egui_zhcn_fonts` — Chinese font support

## Related Projects

- [arbscan](https://github.com/syedinsaf/arbscan) — Qualcomm bootloader ARB scanner
- [arbextract](https://github.com/koaaN/arbextract) — ARB metadata extraction CLI
- [arb_inspector_next](https://github.com/Dere3046/arb_inspector_next) — ELF/MBN ARB inspector (source embedded here)

## Licenses

| Tool | License | Author |
|------|---------|--------|
| arbscan | Apache 2.0 | [Syed Insaf](https://github.com/syedinsaf) |
| arbextract | MIT | [Jonas Salo](https://github.com/koaaN) |
| arb_inspector_next | MIT | [Dere](https://github.com/Dere3046) |
