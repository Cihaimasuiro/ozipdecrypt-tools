use eframe::egui;
use ozipdecrypt_core::{
    describe_container_with_keys, ContainerInfo, ContainerType, KeyConfig, OzipError,
    VerificationLevel,
};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

pub enum WorkerMessage {
    InspectionDone {
        path: PathBuf,
        result: std::result::Result<ContainerInfo, String>,
    },
}

#[derive(Debug, Clone)]
pub enum AppState {
    Idle,
    Inspecting {
        path: PathBuf,
    },
    Ready {
        path: PathBuf,
        info: ContainerInfo,
    },
    Error {
        path: Option<PathBuf>,
        message: String,
        details: Option<String>,
    },
}

pub struct OzipGuiApp {
    state: AppState,
    keys: KeyConfig,
    keys_path: Option<PathBuf>,
    tx: Sender<WorkerMessage>,
    rx: Receiver<WorkerMessage>,
    filter_text: String,
}

impl OzipGuiApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel();
        Self {
            state: AppState::Idle,
            keys: KeyConfig::default(),
            keys_path: None,
            tx,
            rx,
            filter_text: String::new(),
        }
    }

    fn start_inspection(&mut self, path: PathBuf, ctx: &egui::Context) {
        self.state = AppState::Inspecting { path: path.clone() };
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let keys = self.keys.clone();

        std::thread::spawn(move || {
            let res = describe_container_with_keys(&path, &keys).map_err(|e| {
                if let Some(ozip_err) = e.downcast_ref::<OzipError>() {
                    map_ozip_error(ozip_err)
                } else {
                    e.to_string()
                }
            });

            let _ = tx.send(WorkerMessage::InspectionDone { path, result: res });
            ctx.request_repaint();
        });
    }

    fn pick_file(&mut self, ctx: &egui::Context) {
        if let Some(file) = rfd::FileDialog::new()
            .add_filter("Supported Firmware", &["ozip", "ofp", "ops", "zip"])
            .add_filter("All Files", &["*"])
            .pick_file()
        {
            self.start_inspection(file, ctx);
        }
    }

    fn pick_keys_file(&mut self) {
        if let Some(file) = rfd::FileDialog::new()
            .add_filter("TOML Keys Config", &["toml"])
            .pick_file()
        {
            match KeyConfig::load_or_default(&file) {
                Ok(cfg) => {
                    self.keys = cfg;
                    self.keys_path = Some(file);
                }
                Err(e) => {
                    self.state = AppState::Error {
                        path: Some(file),
                        message: "Failed to load keys file".to_string(),
                        details: Some(e.to_string()),
                    };
                }
            }
        }
    }

    pub fn handle_worker_message(&mut self, msg: WorkerMessage) {
        match msg {
            WorkerMessage::InspectionDone { path, result } => match result {
                Ok(info) => {
                    if info.container_type == ContainerType::Unknown {
                        self.state = AppState::Error {
                            path: Some(path),
                            message: "Unrecognized firmware container".to_string(),
                            details: Some(
                                "The selected file does not match any known Oppo, Realme, or OnePlus firmware signatures."
                                    .to_string(),
                            ),
                        };
                    } else {
                        self.state = AppState::Ready { path, info };
                    }
                }
                Err(err_msg) => {
                    self.state = AppState::Error {
                        path: Some(path),
                        message: "Inspection failed".to_string(),
                        details: Some(err_msg),
                    };
                }
            },
        }
    }
}

pub fn map_ozip_error(ozip_err: &OzipError) -> String {
    match ozip_err {
        OzipError::UnsupportedContainer(p) => {
            format!(
                "Unsupported or unrecognized firmware format: {}",
                p.display()
            )
        }
        OzipError::KeyNotFound(details) => {
            format!("Decryption key not found: {}", details)
        }
        OzipError::Truncated(msg) => {
            format!("Container is truncated or damaged: {}", msg)
        }
        OzipError::PathRejected(msg) => {
            format!("Unsafe path detected: {}", msg)
        }
        OzipError::FileExists(p) => {
            format!("Output file already exists: {}", p.display())
        }
        OzipError::Format { format, message } => {
            format!("Format error in {}: {}", format, message)
        }
        OzipError::ChecksumMismatch {
            item,
            expected,
            calculated,
        } => {
            format!(
                "Integrity check mismatch on '{}': expected {}, calculated {}",
                item, expected, calculated
            )
        }
        OzipError::Io(io_err) => format!("I/O Error: {}", io_err),
        OzipError::Xml(xml_err) => format!("XML Error: {}", xml_err),
        OzipError::Zip(zip_err) => format!("ZIP Error: {}", zip_err),
        OzipError::Hex(hex_err) => format!("Hex decode error: {}", hex_err),
        OzipError::Toml(toml_err) => format!("TOML parsing error: {}", toml_err),
        OzipError::Cancelled => "Operation cancelled.".to_string(),
        OzipError::Other(msg) => msg.clone(),
    }
}

impl eframe::App for OzipGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Process messages from background worker
        while let Ok(msg) = self.rx.try_recv() {
            self.handle_worker_message(msg);
        }

        // 2. Handle file drag and drop
        ctx.input(|i| {
            if !i.raw.dropped_files.is_empty() {
                if let Some(file) = i.raw.dropped_files.first() {
                    if let Some(ref path) = file.path {
                        if !matches!(self.state, AppState::Inspecting { .. }) {
                            self.start_inspection(path.clone(), ctx);
                        }
                    }
                }
            }
        });

        let mut action_reset = false;
        let mut action_pick_file = false;
        let mut action_pick_keys = false;

        // 3. Render Top Panel
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("ozipdecrypt");
                ui.label(format!("v{}", env!("CARGO_PKG_VERSION")));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Load keys.toml").clicked() {
                        action_pick_keys = true;
                    }
                    if let Some(ref kp) = self.keys_path {
                        let fname = kp
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("keys.toml");
                        ui.label(format!("Keys: {}", fname));
                    } else {
                        ui.label("Keys: Standard (embedded)");
                    }

                    if !matches!(self.state, AppState::Idle) && ui.button("Close File").clicked() {
                        action_reset = true;
                    }
                });
            });
        });

        // 4. Render Central Panel
        egui::CentralPanel::default().show(ctx, |ui| match &self.state {
            AppState::Idle => {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.label(egui::RichText::new("Drag and drop firmware container here").size(18.0));
                    ui.label("Supported: Oppo/Realme .ozip, Qualcomm Snapdragon .ofp, MediaTek .ofp, OnePlus .ops");
                    ui.add_space(20.0);

                    if ui.button(egui::RichText::new("Choose Firmware File...").size(15.0)).clicked() {
                        action_pick_file = true;
                    }
                    ui.add_space(30.0);

                    ui.group(|ui| {
                        ui.set_max_width(540.0);
                        ui.label(egui::RichText::new("Verification & Safety Notice").strong());
                        ui.label("• Qualcomm .ofp: Verified on real Oppo A7 (CPH1901) firmware file; see limits in docs.");
                        ui.label("• .ozip / MTK .ofp / OPS: Verified on synthetic test vectors with 100% bit-for-bit cipher parity.");
                        ui.label("• Flashing safety: Flashing tools are excluded. Factory persist images must NEVER be flashed.");
                    });
                });
            }

            AppState::Inspecting { path } => {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    ui.spinner();
                    ui.add_space(15.0);
                    ui.label(format!("Inspecting {}...", path.file_name().and_then(|s| s.to_str()).unwrap_or("firmware")));
                    ui.label("Reading container headers and manifest without blocking UI...");
                });
            }

            AppState::Ready { path, info } => {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("Unknown");
                        ui.label(egui::RichText::new(fname).strong().size(16.0));
                        ui.label(format!("Size: {} ({})", format_bytes(info.file_size), info.container_type));
                        if let Some(ref cpu) = info.chipset {
                            ui.label(format!("Platform / Chipset: {}", cpu));
                        }
                        if let Some(ref prj) = info.project {
                            ui.label(format!("Project ID: {}", prj));
                        }
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        match info.verification_level {
                            VerificationLevel::Verified => {
                                ui.colored_label(egui::Color32::from_rgb(80, 200, 120), "[VERIFIED ON REAL FIRMWARE FILE]");
                            }
                            VerificationLevel::SyntheticOnly => {
                                ui.colored_label(egui::Color32::from_rgb(230, 160, 50), "[SYNTHETIC TESTED ONLY]");
                            }
                            VerificationLevel::Unverified => {
                                ui.colored_label(egui::Color32::from_rgb(200, 70, 70), "[UNVERIFIED]");
                            }
                        }
                    });
                });

                ui.separator();

                // Partition Table Filter and Header
                ui.horizontal(|ui| {
                    ui.label(format!("Partitions ({} items):", info.partitions.len()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.filter_text).hint_text("Filter partitions..."));
                    });
                });

                ui.add_space(5.0);

                // Partition List
                let filtered: Vec<&ozipdecrypt_core::PartitionMeta> = info
                    .partitions
                    .iter()
                    .filter(|p| {
                        if self.filter_text.trim().is_empty() {
                            true
                        } else {
                            p.name.to_lowercase().contains(&self.filter_text.to_lowercase())
                        }
                    })
                    .collect();

                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    egui::Grid::new("partition_grid")
                        .striped(true)
                        .min_col_width(70.0)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("#").strong());
                            ui.label(egui::RichText::new("Partition Name").strong());
                            ui.label(egui::RichText::new("Size").strong());
                            ui.label(egui::RichText::new("Encrypted").strong());
                            ui.label(egui::RichText::new("Checksum").strong());
                            ui.end_row();

                            for (idx, p) in filtered.iter().enumerate() {
                                ui.label(format!("{}", idx + 1));
                                ui.label(&p.name);
                                ui.label(format_bytes(p.size));
                                ui.label(if p.is_encrypted { "Yes" } else { "No" });
                                ui.label(if p.has_checksum { "Manifest Hash" } else { "None" });
                                ui.end_row();
                            }
                        });
                });

                ui.separator();
                ui.label(egui::RichText::new("Milestone M1 Status: Container inspected and validated. Partition extraction and progress controls will be wired in Milestone M2.").italics().size(12.0));
            }

            AppState::Error { path, message, details } => {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.colored_label(egui::Color32::from_rgb(230, 80, 80), egui::RichText::new("Inspection Error").size(18.0));
                    ui.add_space(10.0);
                    if let Some(p) = path {
                        ui.label(format!("File: {}", p.display()));
                    }
                    ui.label(message);

                    if let Some(d) = details {
                        ui.add_space(15.0);
                        ui.group(|ui| {
                            ui.set_max_width(550.0);
                            ui.label(egui::RichText::new(d).monospace());
                        });
                    }

                    ui.add_space(20.0);
                    if ui.button("Choose Another File").clicked() {
                        action_reset = true;
                    }
                });
            }
        });

        if action_reset {
            self.state = AppState::Idle;
            self.filter_text.clear();
        }
        if action_pick_file {
            self.pick_file(ctx);
        }
        if action_pick_keys {
            self.pick_keys_file();
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozipdecrypt_core::VerificationLevel;

    fn make_test_app() -> OzipGuiApp {
        let (tx, rx) = channel();
        OzipGuiApp {
            state: AppState::Idle,
            keys: KeyConfig::default(),
            keys_path: None,
            tx,
            rx,
            filter_text: String::new(),
        }
    }

    #[test]
    fn test_map_ozip_error_formatting() {
        let err_unsupported = OzipError::UnsupportedContainer(PathBuf::from("test.bin"));
        assert!(map_ozip_error(&err_unsupported).contains("Unsupported or unrecognized"));

        let err_key = OzipError::KeyNotFound("test key".to_string());
        assert!(map_ozip_error(&err_key).contains("Decryption key not found"));

        let err_checksum = OzipError::ChecksumMismatch {
            item: "boot.img".to_string(),
            expected: "aaa".to_string(),
            calculated: "bbb".to_string(),
        };
        assert!(map_ozip_error(&err_checksum).contains("Integrity check mismatch"));

        let err_cancel = OzipError::Cancelled;
        assert_eq!(map_ozip_error(&err_cancel), "Operation cancelled.");
    }

    #[test]
    fn test_handle_worker_message_success_transitions_to_ready() {
        let mut app = make_test_app();
        let path = PathBuf::from("firmware.ofp");
        let info = ContainerInfo {
            container_type: ContainerType::OfpQualcomm,
            details: "Qualcomm OFP".to_string(),
            file_size: 1048576,
            chipset: Some("SDM450".to_string()),
            project: Some("18041".to_string()),
            verification_level: VerificationLevel::Verified,
            partitions: vec![],
        };

        app.handle_worker_message(WorkerMessage::InspectionDone {
            path: path.clone(),
            result: Ok(info),
        });

        match &app.state {
            AppState::Ready { path: p, info: i } => {
                assert_eq!(p, &path);
                assert_eq!(i.container_type, ContainerType::OfpQualcomm);
                assert_eq!(i.verification_level, VerificationLevel::Verified);
            }
            other => panic!("Expected AppState::Ready, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_worker_message_unknown_container_transitions_to_error() {
        let mut app = make_test_app();
        let path = PathBuf::from("unknown.bin");
        let info = ContainerInfo {
            container_type: ContainerType::Unknown,
            details: "Unknown".to_string(),
            file_size: 100,
            chipset: None,
            project: None,
            verification_level: VerificationLevel::Unverified,
            partitions: vec![],
        };

        app.handle_worker_message(WorkerMessage::InspectionDone {
            path,
            result: Ok(info),
        });

        match &app.state {
            AppState::Error { message, .. } => {
                assert_eq!(message, "Unrecognized firmware container");
            }
            other => panic!("Expected AppState::Error, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_worker_message_err_transitions_to_error() {
        let mut app = make_test_app();
        let path = PathBuf::from("corrupt.ozip");

        app.handle_worker_message(WorkerMessage::InspectionDone {
            path,
            result: Err("Header corrupted".to_string()),
        });

        match &app.state {
            AppState::Error {
                message, details, ..
            } => {
                assert_eq!(message, "Inspection failed");
                assert_eq!(details.as_deref(), Some("Header corrupted"));
            }
            other => panic!("Expected AppState::Error, got {:?}", other),
        }
    }

    #[test]
    fn test_format_bytes_utility() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }
}
