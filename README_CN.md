# checkARB

> 高通防回滚 (ARB) 元数据分析 GUI 工具集

[English](README.md) · 中文

## 内置工具

| 工具 | 说明 |
|------|------|
| **arbscan** | 从 bootloader 镜像（如 xbl_config.img）提取 OEM ARB 元数据，支持 JSON 输出 |
| **arb_inspector** | 解析 ELF/MBN 格式固件镜像，提取 ARB 值、元数据版本、段哈希（源码内嵌） |
| **arbextract** | 从固件镜像中提取 ARB 相关信息到指定目录 |

## 功能

- 可视化 GUI，底部标签栏快速切换工具
- 文件选择器 + 参数配置面板 + 输出滚动显示
- arbscan 可选设备型号/更新标签注释，自动生成 JSON
- arb_inspector 支持调试模式，输出段解析详情
- 多语言支持（中文 / 英文），菜单及右上角切换
- 内置许可证查看（MIT / Apache 2.0）

## 编译

```bash
cargo build --release
```

产物：`target/release/checkARB.exe`

## 依赖

- Rust 1.70+
- `egui` / `eframe` — GUI
- `sha2` / `digest` — 哈希计算
- `rfd` — 文件对话框
- `serde` / `serde_json` — JSON 序列化
- `egui_zhcn_fonts` — 中文字体支持

## 相关项目

- [arbscan](https://github.com/syedinsaf/arbscan) — Qualcomm bootloader ARB 扫描器
- [arbextract](https://github.com/koaaN/arbextract) — ARB 元数据提取 CLI
- [arb_inspector_next](https://github.com/Dere3046/arb_inspector_next) — ELF/MBN ARB 检查器（源码已内嵌）

## 许可证

| 工具 | 许可证 | 作者 |
|------|--------|------|
| arbscan | Apache 2.0 | [Syed Insaf](https://github.com/syedinsaf) |
| arbextract | MIT | [Jonas Salo](https://github.com/koaaN) |
| arb_inspector_next | MIT | [Dere](https://github.com/Dere3046) |
