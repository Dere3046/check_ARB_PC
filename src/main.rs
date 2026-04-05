#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

mod inspector;

// Embedded resources as byte arrays
const ARBSCAN_EXE: &[u8] = include_bytes!("../resources/arbscan.exe");
const ARBEXTRACT_EXE: &[u8] = include_bytes!("../resources/arbextract.exe");

const LICENSE_ARBEXTRACT: &str = include_str!("../resources/LICENSE_arbextract.txt");
const LICENSE_ARBSCAN: &str = include_str!("../resources/LICENSE_arbscan.txt");
const LICENSE_INSPECTOR: &str = include_str!("../resources/LICENSE_inspector.txt");

// Language support
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    Chinese,
    English,
}

impl Language {
    fn label(&self) -> &'static str {
        match self {
            Language::Chinese => "中文",
            Language::English => "English",
        }
    }
}

// Translation system using array indices
struct Tr {
    lang: Language,
}

impl Tr {
    fn new(lang: Language) -> Self {
        Self { lang }
    }

    fn get(&self, idx: usize) -> &'static str {
        match self.lang {
            Language::Chinese => ZH[idx],
            Language::English => EN[idx],
        }
    }
}

// Translation arrays
const ZH: [&str; 59] = [
    "文件", "退出", "工具", "帮助", "许可证", "关于",
    "🏠 首页", "🔍 arbscan", "📊 arb_inspector", "📦 arbextract", "📜 许可证",
    "checkARB - ARB 分析工具", "Qualcomm Anti-Rollback (ARB) 元数据分析工具集", "内置工具",
    "从 Qualcomm bootloader 镜像（如 xbl_config.img）中提取 OEM ARB 元数据",
    "检查固件镜像（ELF 或 MBN 格式）中的 ARB 值",
    "提取固件镜像中的 ARB 相关信息",
    "打开", "⚠️ 重要提示", "ARB 值是安全回滚下限，不是更新计数器。一旦增加，无法降低。请勿刷入低于当前 ARB 值的固件。",
    "🔍 arbscan - Bootloader 镜像分析", "选择 xbl_config.img 文件:", "浏览...",
    "已选择:", "可选 - JSON 输出注释:", "设备型号:", "更新标签:",
    "▶ 开始分析", "输出:", "📄 JSON 输出:", "JSON 已保存到:",
    "错误: 请选择一个有效的 bootloader 镜像文件", "正在分析...\n", "错误: 无法运行 arbscan",
    "📊 arb_inspector - ARB 值检查", "选择固件镜像文件 (ELF/MBN):", "选项:",
    "调试模式 (--debug)", "快速扫描 (--quick)", "查看版本 (-v)",
    "▶ 开始检查", "输出:",
    "错误: 请选择一个有效的固件镜像文件", "正在检查...\n",
    "📦 arbextract - ARB 信息提取", "选择输入文件:", "输出目录:",
    "输出到:", "▶ 开始提取", "输出:",
    "错误: 请选择一个有效的文件", "正在提取...\n", "错误: 无法运行 arbextract",
    "📜 许可证", "选择工具:",
    "arbextract (MIT)", "arbscan (Apache 2.0)", "arb_inspector (MIT)",
    "语言 / Language",
];

const EN: [&str; 59] = [
    "File", "Exit", "Tools", "Help", "Licenses", "About",
    "🏠 Home", "🔍 arbscan", "📊 arb_inspector", "📦 arbextract", "📜 Licenses",
    "checkARB - ARB Analysis Tool", "Qualcomm Anti-Rollback (ARB) Metadata Analysis Suite", "Built-in Tools",
    "Extract OEM ARB metadata from Qualcomm bootloader images (e.g., xbl_config.img)",
    "Check ARB values in firmware images (ELF or MBN format)",
    "Extract ARB-related information from firmware images",
    "Open", "⚠️ Important Notice", "The ARB value is a security rollback floor, not an update counter. Once increased, it cannot be lowered. Do not flash firmware with a lower ARB value.",
    "🔍 arbscan - Bootloader Image Analysis", "Select xbl_config.img file:", "Browse...",
    "Selected:", "Optional - JSON Output Annotations:", "Device Model:", "Update Label:",
    "▶ Start Analysis", "Output:", "📄 JSON Output:", "JSON saved to:",
    "Error: Please select a valid bootloader image file", "Analyzing...\n", "Error: Failed to run arbscan",
    "📊 arb_inspector - ARB Value Check", "Select firmware image file (ELF/MBN):", "Options:",
    "Debug Mode (--debug)", "Quick Scan (--quick)", "Show Version (-v)",
    "▶ Start Check", "Output:",
    "Error: Please select a valid firmware image file", "Checking...\n",
    "📦 arbextract - ARB Information Extraction", "Select input file:", "Output directory:",
    "Output to:", "▶ Start Extraction", "Output:",
    "Error: Please select a valid file", "Extracting...\n", "Error: Failed to run arbextract",
    "📜 Licenses", "Select tool:",
    "arbextract (MIT)", "arbscan (Apache 2.0)", "arb_inspector (MIT)",
    "语言 / Language",
];

// Translation key constants
mod K {
    pub const MENU_FILE: usize = 0;
    pub const MENU_EXIT: usize = 1;
    pub const MENU_TOOLS: usize = 2;
    pub const MENU_HELP: usize = 3;
    pub const MENU_LICENSES: usize = 4;
    pub const MENU_ABOUT: usize = 5;
    pub const TAB_HOME: usize = 6;
    pub const TAB_ARBSCAN: usize = 7;
    pub const TAB_INSPECTOR: usize = 8;
    pub const TAB_ARBEXTRACT: usize = 9;
    pub const TAB_LICENSES: usize = 10;
    pub const HOME_TITLE: usize = 11;
    pub const HOME_SUBTITLE: usize = 12;
    pub const HOME_TOOLS: usize = 13;
    pub const HOME_ARBSCAN_DESC: usize = 14;
    pub const HOME_INSPECTOR_DESC: usize = 15;
    pub const HOME_ARBEXTRACT_DESC: usize = 16;
    pub const HOME_OPEN: usize = 17;
    pub const HOME_WARN_TITLE: usize = 18;
    pub const HOME_WARN_TEXT: usize = 19;
    pub const ARBSCAN_TITLE: usize = 20;
    pub const ARBSCAN_SELECT: usize = 21;
    pub const ARBSCAN_BROWSE: usize = 22;
    pub const ARBSCAN_SELECTED: usize = 23;
    pub const ARBSCAN_JSON_TITLE: usize = 24;
    pub const ARBSCAN_DEVICE: usize = 25;
    pub const ARBSCAN_LABEL: usize = 26;
    pub const ARBSCAN_RUN: usize = 27;
    pub const ARBSCAN_OUT: usize = 28;
    pub const ARBSCAN_JSON_OUT: usize = 29;
    pub const ARBSCAN_JSON_SAVED: usize = 30;
    pub const ARBSCAN_ERR_NOFILE: usize = 31;
    pub const ARBSCAN_ANALYZING: usize = 32;
    pub const ARBSCAN_ERR_RUN: usize = 33;
    pub const INSP_TITLE: usize = 34;
    pub const INSP_SELECT: usize = 35;
    pub const INSP_OPTS: usize = 36;
    pub const INSP_DBG: usize = 37;
    pub const INSP_QUICK: usize = 38;
    pub const INSP_VERB: usize = 39;
    pub const INSP_RUN: usize = 40;
    pub const INSP_OUT: usize = 41;
    pub const INSP_ERR_NOFILE: usize = 42;
    pub const INSP_CHECKING: usize = 43;
    pub const EXTR_TITLE: usize = 44;
    pub const EXTR_IN: usize = 45;
    pub const EXTR_OUTDIR: usize = 46;
    pub const EXTR_OUTTO: usize = 47;
    pub const EXTR_RUN: usize = 48;
    pub const EXTR_OUT: usize = 49;
    pub const EXTR_ERR_NOFILE: usize = 50;
    pub const EXTR_EXTRACTING: usize = 51;
    pub const EXTR_ERR_RUN: usize = 52;
    pub const LIC_TITLE: usize = 53;
    pub const LIC_SELECT: usize = 54;
    pub const LIC_ARBEXTRACT: usize = 55;
    pub const LIC_ARBSCAN: usize = 56;
    pub const LIC_INSPECTOR: usize = 57;
    pub const LANG: usize = 58;
}

#[derive(Debug, Clone, PartialEq)]
enum Tab {
    Home,
    Arbscan,
    Inspector,
    Extract,
    Licenses,
}

struct App {
    tab: Tab,
    lang: Language,
    tr: Tr,

    // Arbscan
    arbscan_file: PathBuf,
    arbscan_device: String,
    arbscan_label: String,
    arbscan_out: String,
    arbscan_json: Option<String>,

    // Inspector
    insp_file: PathBuf,
    insp_debug: bool,
    insp_out: String,

    // Extract
    extr_file: PathBuf,
    extr_outdir: PathBuf,
    extr_out: String,

    // Licenses
    lic_idx: usize,

    // Temp
    tmp: PathBuf,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        egui_zhcn_fonts::add_sys_ui_fonts(&cc.egui_ctx);
        Self::default()
    }

    fn t(&self) -> &Tr {
        &self.tr
    }

    fn set_lang(&mut self, l: Language) {
        self.lang = l;
        self.tr = Tr::new(l);
    }

    fn run_arbscan(&mut self) {
        if self.arbscan_file.as_os_str().is_empty() || !self.arbscan_file.exists() {
            self.arbscan_out = self.t().get(K::ARBSCAN_ERR_NOFILE).into();
            return;
        }
        self.arbscan_out = self.t().get(K::ARBSCAN_ANALYZING).into();
        self.arbscan_json = None;

        let p = self.tmp.join("arbscan.exe");
        if !p.exists() {
            fs::write(&p, ARBSCAN_EXE).ok();
        }

        match Command::new(&p).arg(&self.arbscan_file).output() {
            Ok(o) => {
                let out = String::from_utf8_lossy(&o.stdout);
                let err = String::from_utf8_lossy(&o.stderr);
                self.arbscan_out = format!("=== arbscan ===\n{}\n{}", out, err);

                if !self.arbscan_device.is_empty() || !self.arbscan_label.is_empty() {
                    let (mut maj, mut min, mut arb) = (0u32, 0u32, 0u32);
                    for line in out.lines() {
                        if line.contains("Major Version") {
                            maj = line.split(':').nth(1).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                        }
                        if line.contains("Minor Version") {
                            min = line.split(':').nth(1).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                        }
                        if line.contains("ARB") {
                            arb = line.split(':').nth(1).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                        }
                    }
                    let json = serde_json::json!({
                        "device_model": self.arbscan_device,
                        "update_label": self.arbscan_label,
                        "image": self.arbscan_file.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default(),
                        "major": maj, "minor": min, "arb": arb
                    });
                    if let Ok(s) = serde_json::to_string_pretty(&json) {
                        let jp = self.arbscan_file.parent().unwrap_or_else(|| std::path::Path::new("."))
                            .join(format!("{}_arb.json", self.arbscan_file.file_stem().map(|f| f.to_string_lossy().to_string()).unwrap_or_default()));
                        if fs::write(&jp, &s).is_ok() {
                            self.arbscan_json = Some(format!("{} {}\n\n{}", self.t().get(K::ARBSCAN_JSON_SAVED), jp.display(), s));
                        }
                    }
                }
            }
            Err(_) => self.arbscan_out = self.t().get(K::ARBSCAN_ERR_RUN).into(),
        }
    }

    fn run_inspector(&mut self) {
        if self.insp_file.as_os_str().is_empty() || !self.insp_file.exists() {
            self.insp_out = self.tr.get(K::INSP_ERR_NOFILE).to_string();
            return;
        }
        self.insp_out = self.tr.get(K::INSP_CHECKING).to_string();

        let path = self.insp_file.to_string_lossy().to_string();
        let full_mode = false; // Quick mode by default
        let debug = self.insp_debug;

        match inspector::inspect_image(&path, debug, full_mode) {
            Ok(result) => {
                let mut out = String::new();
                out.push_str("=== arb_inspector_next ===\n\n");
                out.push_str(&format!("文件: {}\n", path));
                out.push_str(&format!("格式: {}\n", result.elf_class));

                if full_mode {
                    out.push_str(&format!("入口点: 0x{:x}\n", result.e_entry));
                    out.push_str(&format!("机器: 0x{:x}\n", result.e_machine));
                    out.push_str(&format!("类型: 0x{:x}\n", result.e_type));
                    out.push_str(&format!("标志: 0x{:x}\n", result.e_flags));
                    out.push_str(&format!("程序头数量: {}\n\n", result.e_phnum));
                }

                if let Some(arb) = result.arb {
                    out.push_str(&format!("ARB (Anti-Rollback): {}\n", arb));
                } else {
                    out.push_str("ARB (Anti-Rollback): 未找到\n");
                }

                if let Some(ref ht) = result.hash_table_info {
                    out.push_str(&format!("OEM 元数据版本: {}\n",
                        ht.oem_metadata_version.as_deref().unwrap_or("未知")));
                    if let Some(oem_arb) = ht.oem_arb {
                        out.push_str(&format!("OEM ARB: {}\n", oem_arb));
                    }
                    out.push_str(&format!("哈希表条目: {}\n", ht.hash_count));
                }

                if !result.computed_hashes.is_empty() {
                    out.push_str(&format!("\n计算的段哈希: {} 个\n", result.computed_hashes.len()));
                }

                if debug && !result.debug_output.is_empty() {
                    out.push_str(&format!("\n--- 调试输出 ---\n{}", result.debug_output));
                }

                self.insp_out = out;
            }
            Err(e) => self.insp_out = format!("错误: {}\n\n提示: 支持 ELF 格式的 Qualcomm bootloader 镜像", e),
        }
    }

    fn run_extract(&mut self) {
        if self.extr_file.as_os_str().is_empty() || !self.extr_file.exists() {
            self.extr_out = self.t().get(K::EXTR_ERR_NOFILE).into();
            return;
        }
        self.extr_out = self.t().get(K::EXTR_EXTRACTING).into();

        let p = self.tmp.join("arbextract.exe");
        if !p.exists() {
            fs::write(&p, ARBEXTRACT_EXE).ok();
        }

        let outdir = if self.extr_outdir.as_os_str().is_empty() {
            self.extr_file.parent().unwrap_or_else(|| std::path::Path::new(".")).into()
        } else {
            self.extr_outdir.clone()
        };
        fs::create_dir_all(&outdir).ok();

        let run = |args: Vec<&str>| Command::new(&p).args(&args).output();
        match run(vec![self.extr_file.to_str().unwrap_or(""), "-o", outdir.to_str().unwrap_or(".")]) {
            Ok(o) => {
                self.extr_out = format!("=== arbextract ===\n{}\n{}",
                    String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
            }
            Err(_) => match run(vec![self.extr_file.to_str().unwrap_or("")]) {
                Ok(o) => {
                    self.extr_out = format!("=== arbextract ===\n{}\n{}",
                        String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
                }
                Err(_) => self.extr_out = self.t().get(K::EXTR_ERR_RUN).into(),
            },
        }
    }
}

impl Default for App {
    fn default() -> Self {
        let tmp = std::env::temp_dir().join("checkARB_tools");
        fs::create_dir_all(&tmp).ok();
        Self {
            tab: Tab::Home,
            lang: Language::Chinese,
            tr: Tr::new(Language::Chinese),
            arbscan_file: PathBuf::new(),
            arbscan_device: String::new(),
            arbscan_label: String::new(),
            arbscan_out: String::new(),
            arbscan_json: None,
            insp_file: PathBuf::new(),
            insp_debug: false,
            insp_out: String::new(),
            extr_file: PathBuf::new(),
            extr_outdir: PathBuf::new(),
            extr_out: String::new(),
            lic_idx: K::LIC_ARBEXTRACT,
            tmp,
        }
    }
}

// UI Action enum to handle menu clicks
enum UiAction {
    None,
    SetTab(Tab),
    SetLang(Language),
    Exit,
    RunArbscan,
    RunInspector,
    RunExtract,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut action = UiAction::None;
        let mut picked_arbscan_file: Option<PathBuf> = None;
        let mut picked_insp_file: Option<PathBuf> = None;
        let mut picked_extr_file: Option<PathBuf> = None;
        let mut picked_extr_dir: Option<PathBuf> = None;
        let mut new_lic_idx: Option<usize> = None;
        
        let t = &self.tr;
        let cur_tab = self.tab.clone();
        let cur_lang = self.lang;
        let cur_lic = self.lic_idx;
        let arbscan_file = self.arbscan_file.clone();
        let insp_file = self.insp_file.clone();
        let extr_file = self.extr_file.clone();
        let extr_outdir = self.extr_outdir.clone();
        let arbscan_out = self.arbscan_out.clone();
        let arbscan_json = self.arbscan_json.clone();
        let insp_out = self.insp_out.clone();
        let mut insp_debug = self.insp_debug;
        let extr_out = self.extr_out.clone();
        let mut arbscan_device = self.arbscan_device.clone();
        let mut arbscan_label = self.arbscan_label.clone();

        // Top panel with menu
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button(t.get(K::MENU_FILE), |ui| {
                    if ui.button(t.get(K::MENU_EXIT)).clicked() {
                        ui.close_menu();
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                
                ui.menu_button(t.get(K::MENU_TOOLS), |ui| {
                    if ui.button("arbscan").clicked() {
                        action = UiAction::SetTab(Tab::Arbscan);
                        ui.close_menu();
                    }
                    if ui.button("arb_inspector").clicked() {
                        action = UiAction::SetTab(Tab::Inspector);
                        ui.close_menu();
                    }
                    if ui.button("arbextract").clicked() {
                        action = UiAction::SetTab(Tab::Extract);
                        ui.close_menu();
                    }
                });
                
                ui.menu_button(t.get(K::MENU_HELP), |ui| {
                    if ui.button(t.get(K::MENU_LICENSES)).clicked() {
                        action = UiAction::SetTab(Tab::Licenses);
                        ui.close_menu();
                    }
                    if ui.button(t.get(K::MENU_ABOUT)).clicked() {
                        action = UiAction::SetTab(Tab::Home);
                        ui.close_menu();
                    }
                });

                ui.separator();
                ui.menu_button(t.get(K::LANG), |ui| {
                    if ui.selectable_label(cur_lang == Language::Chinese, "中文").clicked() {
                        action = UiAction::SetLang(Language::Chinese);
                        ui.close_menu();
                    }
                    if ui.selectable_label(cur_lang == Language::English, "English").clicked() {
                        action = UiAction::SetLang(Language::English);
                        ui.close_menu();
                    }
                });
            });
        });

        // Bottom panel with tabs
        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let tabs = [
                    (Tab::Home, t.get(K::TAB_HOME)),
                    (Tab::Arbscan, t.get(K::TAB_ARBSCAN)),
                    (Tab::Inspector, t.get(K::TAB_INSPECTOR)),
                    (Tab::Extract, t.get(K::TAB_ARBEXTRACT)),
                    (Tab::Licenses, t.get(K::TAB_LICENSES)),
                ];
                for (tab, label) in &tabs {
                    let active = cur_tab == *tab;
                    if ui.add(egui::Button::new(*label).fill(if active {
                        ui.visuals().selection.bg_fill
                    } else {
                        ui.visuals().widgets.noninteractive.bg_fill
                    })).clicked() {
                        action = UiAction::SetTab(tab.clone());
                    }
                }
            });
        });

        // Central content
        egui::CentralPanel::default().show(ctx, |ui| {
            match cur_tab {
                Tab::Home => {
                    ui.vertical_centered(|ui| {
                        ui.add_space(30.0);
                        ui.heading(t.get(K::HOME_TITLE));
                        ui.label(t.get(K::HOME_SUBTITLE));
                        ui.add_space(15.0);
                        ui.group(|ui| {
                            ui.heading(t.get(K::HOME_TOOLS));
                            ui.horizontal_wrapped(|ui| {
                                ui.heading("🔍");
                                ui.vertical(|ui| {
                                    ui.strong("arbscan");
                                    ui.label(t.get(K::HOME_ARBSCAN_DESC));
                                    if ui.button(t.get(K::HOME_OPEN)).clicked() { action = UiAction::SetTab(Tab::Arbscan); }
                                });
                            });
                            ui.separator();
                            ui.horizontal_wrapped(|ui| {
                                ui.heading("📊");
                                ui.vertical(|ui| {
                                    ui.strong("arb_inspector");
                                    ui.label(t.get(K::HOME_INSPECTOR_DESC));
                                    if ui.button(t.get(K::HOME_OPEN)).clicked() { action = UiAction::SetTab(Tab::Inspector); }
                                });
                            });
                            ui.separator();
                            ui.horizontal_wrapped(|ui| {
                                ui.heading("📦");
                                ui.vertical(|ui| {
                                    ui.strong("arbextract");
                                    ui.label(t.get(K::HOME_ARBEXTRACT_DESC));
                                    if ui.button(t.get(K::HOME_OPEN)).clicked() { action = UiAction::SetTab(Tab::Extract); }
                                });
                            });
                        });
                        ui.add_space(15.0);
                        ui.group(|ui| {
                            ui.heading(t.get(K::HOME_WARN_TITLE));
                            ui.label(t.get(K::HOME_WARN_TEXT));
                        });
                    });
                }
                Tab::Arbscan => {
                    ui.horizontal(|ui| {
                        if ui.button("← 返回首页").clicked() { action = UiAction::SetTab(Tab::Home); }
                        ui.separator();
                        if ui.button("✕ 退出").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                    });
                    ui.separator();
                    ui.heading(t.get(K::ARBSCAN_TITLE));
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(t.get(K::ARBSCAN_SELECT));
                        if ui.button(t.get(K::ARBSCAN_BROWSE)).clicked() {
                            if let Some(p) = rfd::FileDialog::new().pick_file() { picked_arbscan_file = Some(p); }
                        }
                    });
                    if !arbscan_file.as_os_str().is_empty() {
                        ui.label(format!("{} {}", t.get(K::ARBSCAN_SELECTED), arbscan_file.display()));
                    }
                    ui.add_space(8.0);
                    ui.group(|ui| {
                        ui.label(t.get(K::ARBSCAN_JSON_TITLE));
                        ui.horizontal(|ui| { ui.label(t.get(K::ARBSCAN_DEVICE)); ui.text_edit_singleline(&mut arbscan_device); });
                        ui.horizontal(|ui| { ui.label(t.get(K::ARBSCAN_LABEL)); ui.text_edit_singleline(&mut arbscan_label); });
                    });
                    ui.add_space(8.0);
                    if ui.button(t.get(K::ARBSCAN_RUN)).clicked() { action = UiAction::RunArbscan; }
                    ui.add_space(8.0);
                    if !arbscan_out.is_empty() {
                        ui.group(|ui| {
                            ui.label(t.get(K::ARBSCAN_OUT));
                            let mut o = arbscan_out.clone();
                            egui::ScrollArea::vertical().min_scrolled_height(150.0).show(ui, |ui| {
                                ui.add(egui::TextEdit::multiline(&mut o).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                            });
                        });
                    }
                    if let Some(json) = &arbscan_json {
                        ui.add_space(8.0);
                        ui.group(|ui| {
                            ui.label(t.get(K::ARBSCAN_JSON_OUT));
                            let mut j = json.clone();
                            egui::ScrollArea::vertical().min_scrolled_height(100.0).show(ui, |ui| {
                                ui.add(egui::TextEdit::multiline(&mut j).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                            });
                        });
                    }
                }
                Tab::Inspector => {
                    ui.horizontal(|ui| {
                        if ui.button("← 返回首页").clicked() { action = UiAction::SetTab(Tab::Home); }
                        ui.separator();
                        if ui.button("✕ 退出").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                    });
                    ui.separator();
                    ui.heading(t.get(K::INSP_TITLE));
                    ui.separator();

                    ui.horizontal(|ui| {
                        ui.label(t.get(K::INSP_SELECT));
                        if ui.button(t.get(K::ARBSCAN_BROWSE)).clicked() {
                            if let Some(p) = rfd::FileDialog::new().pick_file() { picked_insp_file = Some(p); }
                        }
                    });
                    if !insp_file.as_os_str().is_empty() {
                        ui.label(format!("{} {}", t.get(K::ARBSCAN_SELECTED), insp_file.display()));
                    }

                    ui.add_space(8.0);
                    ui.group(|ui| {
                        ui.checkbox(&mut insp_debug, "调试模式 (--debug)");
                    });

                    ui.add_space(8.0);
                    if ui.button(t.get(K::INSP_RUN)).clicked() { action = UiAction::RunInspector; }

                    ui.add_space(8.0);
                    if !insp_out.is_empty() {
                        ui.group(|ui| {
                            ui.label(t.get(K::INSP_OUT));
                            let mut o = insp_out.clone();
                            egui::ScrollArea::vertical().min_scrolled_height(150.0).show(ui, |ui| {
                                ui.add(egui::TextEdit::multiline(&mut o).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                            });
                        });
                    }
                }
                Tab::Extract => {
                    ui.horizontal(|ui| {
                        if ui.button("← 返回首页").clicked() { action = UiAction::SetTab(Tab::Home); }
                        ui.separator();
                        if ui.button("✕ 退出").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                    });
                    ui.separator();
                    ui.heading(t.get(K::EXTR_TITLE));
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(t.get(K::EXTR_IN));
                        if ui.button(t.get(K::ARBSCAN_BROWSE)).clicked() {
                            if let Some(p) = rfd::FileDialog::new().pick_file() { picked_extr_file = Some(p); }
                        }
                    });
                    if !extr_file.as_os_str().is_empty() {
                        ui.label(format!("{} {}", t.get(K::ARBSCAN_SELECTED), extr_file.display()));
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label(t.get(K::EXTR_OUTDIR));
                        if ui.button(t.get(K::ARBSCAN_BROWSE)).clicked() {
                            if let Some(p) = rfd::FileDialog::new().pick_folder() { picked_extr_dir = Some(p); }
                        }
                    });
                    if !extr_outdir.as_os_str().is_empty() {
                        ui.label(format!("{} {}", t.get(K::EXTR_OUTTO), extr_outdir.display()));
                    }
                    ui.add_space(8.0);
                    if ui.button(t.get(K::EXTR_RUN)).clicked() { action = UiAction::RunExtract; }
                    ui.add_space(8.0);
                    if !extr_out.is_empty() {
                        ui.group(|ui| {
                            ui.label(t.get(K::EXTR_OUT));
                            let mut o = extr_out.clone();
                            egui::ScrollArea::vertical().min_scrolled_height(150.0).show(ui, |ui| {
                                ui.add(egui::TextEdit::multiline(&mut o).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                            });
                        });
                    }
                }
                Tab::Licenses => {
                    ui.horizontal(|ui| {
                        if ui.button("← 返回首页").clicked() { action = UiAction::SetTab(Tab::Home); }
                        ui.separator();
                        if ui.button("✕ 退出").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                    });
                    ui.separator();
                    ui.heading(t.get(K::LIC_TITLE));
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(t.get(K::LIC_SELECT));
                        let opts = [K::LIC_ARBEXTRACT, K::LIC_ARBSCAN, K::LIC_INSPECTOR];
                        for opt in &opts {
                            if ui.selectable_label(cur_lic == *opt, t.get(*opt)).clicked() { new_lic_idx = Some(*opt); }
                        }
                    });
                    ui.add_space(8.0);
                    let lic = match cur_lic {
                        K::LIC_ARBEXTRACT => LICENSE_ARBEXTRACT,
                        K::LIC_ARBSCAN => LICENSE_ARBSCAN,
                        K::LIC_INSPECTOR => LICENSE_INSPECTOR,
                        _ => LICENSE_ARBEXTRACT,
                    };
                    let mut lic = lic.to_string();
                    ui.group(|ui| {
                        egui::ScrollArea::vertical().min_scrolled_height(280.0).show(ui, |ui| {
                            ui.add(egui::TextEdit::multiline(&mut lic).desired_width(f32::INFINITY).font(egui::TextStyle::Small));
                        });
                    });
                }
            }
        });

        // Apply picked values
        if let Some(p) = picked_arbscan_file { self.arbscan_file = p; }
        if let Some(p) = picked_insp_file { self.insp_file = p; }
        if let Some(p) = picked_extr_file { self.extr_file = p; }
        if let Some(p) = picked_extr_dir { self.extr_outdir = p; }
        if let Some(idx) = new_lic_idx { self.lic_idx = idx; }
        
        // Update text fields
        self.arbscan_device = arbscan_device;
        self.arbscan_label = arbscan_label;
        self.insp_debug = insp_debug;

        // Handle actions
        match action {
            UiAction::SetTab(tb) => self.tab = tb,
            UiAction::SetLang(l) => self.set_lang(l),
            UiAction::RunArbscan => self.run_arbscan(),
            UiAction::RunInspector => self.run_inspector(),
            UiAction::RunExtract => self.run_extract(),
            _ => {}
        }
    }
}

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "checkARB",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([900.0, 700.0])
                .with_min_inner_size([700.0, 500.0]),
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
