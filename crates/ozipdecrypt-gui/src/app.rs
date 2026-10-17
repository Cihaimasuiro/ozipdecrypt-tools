use eframe::egui;
use ozipdecrypt_core::{
    describe_container_with_keys, extract, ChecksumStatus, ContainerInfo, ContainerType,
    ExtractRequest, ExtractSummary, KeyConfig, OzipError, ProgressEvent, ProgressReporter,
    VerificationLevel,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub enum WorkerMessage {
    InspectionDone {
        path: PathBuf,
        result: std::result::Result<ContainerInfo, String>,
    },
    Progress(ProgressEvent),
    ExtractionDone {
        result: std::result::Result<ExtractSummary, OzipError>,
        elapsed: Duration,
    },
}

pub struct GuiReporter {
    tx: Sender<WorkerMessage>,
    ctx: egui::Context,
    cancelled: Arc<AtomicBool>,
    last_progress_sent: Mutex<Instant>,
    pending_progress: Mutex<Option<(u64, u64)>>,
}

impl GuiReporter {
    pub fn new(tx: Sender<WorkerMessage>, ctx: egui::Context, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            tx,
            ctx,
            cancelled,
            last_progress_sent: Mutex::new(
                Instant::now()
                    .checked_sub(Duration::from_secs(1))
                    .unwrap_or_else(Instant::now),
            ),
            pending_progress: Mutex::new(None),
        }
    }
}

impl ProgressReporter for GuiReporter {
    fn on_event(&self, event: ProgressEvent) {
        match &event {
            ProgressEvent::Progress {
                bytes_done,
                bytes_total,
            } => {
                let now = Instant::now();
                if let Ok(mut pending) = self.pending_progress.lock() {
                    *pending = Some((*bytes_done, *bytes_total));
                }
                if let Ok(mut last) = self.last_progress_sent.lock() {
                    // Throttle per-chunk progress to 50ms intervals or final byte completion
                    if now.duration_since(*last) >= Duration::from_millis(50)
                        || bytes_done == bytes_total
                    {
                        *last = now;
                        if let Ok(mut pending) = self.pending_progress.lock() {
                            *pending = None;
                        }
                        let _ = self.tx.send(WorkerMessage::Progress(event));
                        self.ctx.request_repaint();
                    }
                }
            }
            ProgressEvent::ItemDone { .. } => {
                // Ensure any pending throttled progress is forwarded before ItemDone so progress bar reaches 100%
                if let Ok(mut pending) = self.pending_progress.lock() {
                    if let Some((done, total)) = pending.take() {
                        let _ = self
                            .tx
                            .send(WorkerMessage::Progress(ProgressEvent::Progress {
                                bytes_done: done,
                                bytes_total: total,
                            }));
                    }
                }
                let _ = self.tx.send(WorkerMessage::Progress(event));
                self.ctx.request_repaint();
            }
            ProgressEvent::Finished => {
                // Flush any pending progress before final finish event
                if let Ok(mut pending) = self.pending_progress.lock() {
                    if let Some((done, total)) = pending.take() {
                        let _ = self
                            .tx
                            .send(WorkerMessage::Progress(ProgressEvent::Progress {
                                bytes_done: done,
                                bytes_total: total,
                            }));
                    }
                }
                let _ = self.tx.send(WorkerMessage::Progress(event));
                self.ctx.request_repaint();
            }
            _ => {
                // Always forward lifecycle events (Started, ItemStarted, Warning) immediately
                let _ = self.tx.send(WorkerMessage::Progress(event));
                self.ctx.request_repaint();
            }
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
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
        out_dir: PathBuf,
        selected_partitions: HashSet<String>,
        disk_warning: Option<String>,
    },
    Extracting {
        path: PathBuf,
        out_dir: PathBuf,
        total_items: usize,
        items_done: usize,
        current_item: String,
        current_item_size: u64,
        bytes_done: u64,
        bytes_total: u64,
        start_time: Instant,
        speed_mb_s: f64,
        warnings: Vec<String>,
        cancelling: bool,
    },
    Done {
        path: PathBuf,
        out_dir: PathBuf,
        summary: ExtractSummary,
        elapsed: Duration,
        warnings: Vec<String>,
    },
    Cancelled {
        path: PathBuf,
        out_dir: PathBuf,
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
    cancel_flag: Option<Arc<AtomicBool>>,
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
            cancel_flag: None,
        }
    }

    fn start_inspection(&mut self, path: PathBuf, ctx: &egui::Context) {
        self.state = AppState::Inspecting { path: path.clone() };
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let keys = self.keys.clone();

        std::thread::spawn(move || {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                describe_container_with_keys(&path, &keys)
            }))
            .map_err(|panic_err| {
                let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_err.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Internal worker panic".to_string()
                };
                format!("Worker thread panicked during inspection: {}", msg)
            })
            .and_then(|r| {
                r.map_err(|e| {
                    if let Some(ozip_err) = e.downcast_ref::<OzipError>() {
                        map_ozip_error(ozip_err)
                    } else {
                        e.to_string()
                    }
                })
            });

            let _ = tx.send(WorkerMessage::InspectionDone { path, result: res });
            ctx.request_repaint();
        });
    }

    fn start_extraction(
        &mut self,
        path: PathBuf,
        out_dir: PathBuf,
        selected: Vec<String>,
        ctx: &egui::Context,
    ) {
        let cancel_flag = Arc::new(AtomicBool::new(false));
        self.cancel_flag = Some(cancel_flag.clone());
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let keys = self.keys.clone();

        self.state = AppState::Extracting {
            path: path.clone(),
            out_dir: out_dir.clone(),
            total_items: selected.len(),
            items_done: 0,
            current_item: String::new(),
            current_item_size: 0,
            bytes_done: 0,
            bytes_total: 0,
            start_time: Instant::now(),
            speed_mb_s: 0.0,
            warnings: Vec::new(),
            cancelling: false,
        };

        let reporter = GuiReporter::new(tx.clone(), ctx.clone(), cancel_flag);

        std::thread::spawn(move || {
            let req = ExtractRequest {
                input: path,
                out_dir,
                partitions: Some(selected),
            };

            let start = Instant::now();
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                extract(&req, &keys, &reporter)
            }))
            .map_err(|panic_err| {
                let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_err.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Internal worker panic".to_string()
                };
                OzipError::Other(format!("Worker thread panicked during extraction: {}", msg))
            })
            .and_then(|r| r);
            let elapsed = start.elapsed();

            let _ = tx.send(WorkerMessage::ExtractionDone {
                result: res,
                elapsed,
            });
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
                        let default_out_dir = if let Some(parent) = path.parent() {
                            let stem = path
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("firmware");
                            parent.join(format!("{}_extracted", stem))
                        } else {
                            PathBuf::from("extracted")
                        };
                        let selected_partitions: HashSet<String> =
                            info.partitions.iter().map(|p| p.name.clone()).collect();
                        self.state = AppState::Ready {
                            path,
                            info,
                            out_dir: default_out_dir,
                            selected_partitions,
                            disk_warning: None,
                        };
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
            WorkerMessage::Progress(event) => {
                if let AppState::Extracting {
                    total_items,
                    items_done,
                    current_item,
                    current_item_size,
                    bytes_done,
                    bytes_total,
                    start_time,
                    speed_mb_s,
                    warnings,
                    ..
                } = &mut self.state
                {
                    match event {
                        ProgressEvent::Started {
                            total_items: tot,
                            total_bytes: bytes,
                        } => {
                            *total_items = tot;
                            *bytes_total = bytes;
                        }
                        ProgressEvent::ItemStarted { name, size } => {
                            *current_item = name;
                            *current_item_size = size;
                        }
                        ProgressEvent::Progress {
                            bytes_done: done,
                            bytes_total: total,
                        } => {
                            *bytes_done = done;
                            if total > 0 {
                                *bytes_total = total;
                            }
                            let secs = start_time.elapsed().as_secs_f64();
                            if secs > 0.05 {
                                *speed_mb_s = (*bytes_done as f64 / 1_048_576.0) / secs;
                            }
                        }
                        ProgressEvent::ItemDone { .. } => {
                            *items_done += 1;
                        }
                        ProgressEvent::Warning(w) => {
                            warnings.push(w);
                        }
                        ProgressEvent::Finished => {}
                    }
                }
            }
            WorkerMessage::ExtractionDone { result, elapsed } => {
                self.cancel_flag = None;
                match result {
                    Ok(summary) => {
                        if let AppState::Extracting {
                            path,
                            out_dir,
                            warnings,
                            ..
                        } = &self.state
                        {
                            self.state = AppState::Done {
                                path: path.clone(),
                                out_dir: out_dir.clone(),
                                summary,
                                elapsed,
                                warnings: warnings.clone(),
                            };
                        }
                    }
                    Err(OzipError::Cancelled) => {
                        if let AppState::Extracting { path, out_dir, .. } = &self.state {
                            self.state = AppState::Cancelled {
                                path: path.clone(),
                                out_dir: out_dir.clone(),
                            };
                        }
                    }
                    Err(err) => {
                        let p = match &self.state {
                            AppState::Extracting { path, .. } => Some(path.clone()),
                            _ => None,
                        };
                        let err_msg = map_ozip_error(&err);
                        self.state = AppState::Error {
                            path: p,
                            message: "Extraction failed".to_string(),
                            details: Some(err_msg),
                        };
                    }
                }
            }
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
                "Integrity check failed for partition '{}': expected SHA-256 {}, but calculated {}",
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

/// Heuristic check for sensitive device-specific partitions (e.g. calibration, NVRAM, radio).
/// This is solely used to drive the user warning banner preventing accidental flashing of factory images.
pub fn is_device_specific_partition(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("persist")
        || lower.contains("modemst1")
        || lower.contains("modemst2")
        || lower.contains("fsg")
        || lower.contains("nvbk")
        || lower.starts_with("nv")
}

pub fn normalize_path(p: &Path) -> PathBuf {
    if let Ok(canon) = p.canonicalize() {
        return canon;
    }
    use std::path::Component;
    let mut components = Vec::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                components.pop();
            }
            c => components.push(c),
        }
    }
    components.into_iter().collect()
}

pub fn paths_collide(out_dir: &Path, input: &Path) -> bool {
    let norm_out = normalize_path(out_dir);
    let norm_in = normalize_path(input);

    let s_out = norm_out
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase();
    let s_in = norm_in
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase();

    if s_out == s_in {
        return true;
    }
    if let Some(parent) = norm_in.parent() {
        let s_parent = parent
            .to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase();
        if s_out == s_parent {
            return true;
        }
    }
    false
}

#[cfg(windows)]
fn get_free_disk_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    let target = if path.exists() {
        path.to_path_buf()
    } else if let Some(parent) = path.parent() {
        parent.to_path_buf()
    } else {
        path.to_path_buf()
    };
    let mut root: Vec<u16> = target.as_os_str().encode_wide().collect();
    root.push(0);
    let mut free_bytes_available: u64 = 0;
    let mut total_number_of_bytes: u64 = 0;
    let mut total_number_of_free_bytes: u64 = 0;
    extern "system" {
        fn GetDiskFreeSpaceExW(
            lpDirectoryName: *const u16,
            lpFreeBytesAvailableToCaller: *mut u64,
            lpTotalNumberOfBytes: *mut u64,
            lpTotalNumberOfFreeBytes: *mut u64,
        ) -> i32;
    }
    let success = unsafe {
        GetDiskFreeSpaceExW(
            root.as_ptr(),
            &mut free_bytes_available,
            &mut total_number_of_bytes,
            &mut total_number_of_free_bytes,
        )
    };
    if success != 0 {
        Some(free_bytes_available)
    } else {
        None
    }
}

#[cfg(not(windows))]
fn get_free_disk_space(_path: &Path) -> Option<u64> {
    None
}

fn open_folder(path: &Path) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer").arg(path).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(path).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

impl eframe::App for OzipGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Process messages from background worker (with disconnect handling)
        loop {
            match self.rx.try_recv() {
                Ok(msg) => self.handle_worker_message(msg),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // Note: self.tx is retained by OzipGuiApp, so Disconnected cannot fire under normal operation.
                    // catch_unwind in the spawned worker threads is the real guard against worker crashes/panics.
                    // This match arm remains as a secondary defensive fallback.
                    if matches!(
                        self.state,
                        AppState::Inspecting { .. } | AppState::Extracting { .. }
                    ) {
                        self.cancel_flag = None;
                        self.state = AppState::Error {
                            path: None,
                            message: "Worker disconnected unexpectedly".to_string(),
                            details: Some(
                                "The background task terminated without sending a completion message."
                                    .to_string(),
                            ),
                        };
                    }
                    break;
                }
            }
        }

        // 2. Handle file drag and drop (ignored during extraction or inspection)
        ctx.input(|i| {
            if !i.raw.dropped_files.is_empty() {
                if let Some(file) = i.raw.dropped_files.first() {
                    if let Some(ref path) = file.path {
                        if !matches!(
                            self.state,
                            AppState::Extracting { .. } | AppState::Inspecting { .. }
                        ) {
                            self.start_inspection(path.clone(), ctx);
                        }
                    }
                }
            }
        });

        let mut action_reset = false;
        let mut action_pick_file = false;
        let mut action_pick_keys = false;
        let mut action_pick_out_dir = false;
        let mut action_select_all = false;
        let mut action_select_none = false;
        let mut action_toggle_partition: Option<String> = None;
        let mut action_start_extract: Option<(PathBuf, PathBuf, Vec<String>)> = None;
        let mut action_cancel_extract = false;
        let mut action_open_folder: Option<PathBuf> = None;
        let mut action_back_to_ready = false;

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

                    if !matches!(self.state, AppState::Idle | AppState::Extracting { .. })
                        && ui.button("Close File").clicked()
                    {
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
                        ui.label("• .ozip / MTK .ofp / OPS: Synthetic tests only; not yet verified on real firmware files.");
                        ui.label("• Flashing safety: Flashing tools are excluded. Factory persist images must NEVER be flashed.");
                    });
                });
            }

            AppState::Inspecting { path } => {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    ui.spinner();
                    ui.add_space(15.0);
                    ui.label(format!(
                        "Inspecting {}...",
                        path.file_name().and_then(|s| s.to_str()).unwrap_or("firmware")
                    ));
                    ui.label("Reading container headers and manifest without blocking UI...");
                });
            }

            AppState::Ready {
                path,
                info,
                out_dir,
                selected_partitions,
                disk_warning,
            } => {
                // Header details
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("Unknown");
                        ui.label(egui::RichText::new(fname).strong().size(16.0));
                        ui.label(format!(
                            "Size: {} ({})",
                            format_bytes(info.file_size),
                            info.container_type
                        ));
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
                                ui.colored_label(
                                    crate::theme::OK,
                                    "Verified on a real firmware file",
                                );
                            }
                            VerificationLevel::SyntheticOnly => {
                                ui.colored_label(
                                    crate::theme::WARN,
                                    "Synthetic tests only",
                                );
                            }
                            VerificationLevel::Unverified => {
                                ui.colored_label(
                                    crate::theme::BAD,
                                    "Unverified",
                                );
                            }
                        }
                    });
                });

                ui.add_space(4.0);
                {
                    let strip: Vec<(&str, u64, bool)> = info
                        .partitions
                        .iter()
                        .map(|p| (p.name.as_str(), p.size, selected_partitions.contains(&p.name)))
                        .collect();
                    crate::theme::partition_strip(ui, &strip);
                }
                ui.add_space(4.0);

                // Output Folder Selection Row
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Destination:").strong());
                    ui.label(egui::RichText::new(out_dir.display().to_string()).monospace());
                    if ui.button("Browse...").clicked() {
                        action_pick_out_dir = true;
                    }
                });

                // Safety check: collision with input
                let is_collision = paths_collide(out_dir, path);
                if is_collision {
                    ui.colored_label(
                        egui::Color32::from_rgb(230, 80, 80),
                        "Destination folder cannot be the same as the input file or its parent directory.",
                    );
                }

                if let Some(w) = disk_warning {
                    ui.colored_label(crate::theme::WARN, w);
                }

                // Device-specific partition safety warning
                let dangerous: Vec<&String> = selected_partitions
                    .iter()
                    .filter(|name| is_device_specific_partition(name))
                    .collect();
                if !dangerous.is_empty() {
                    ui.group(|ui| {
                        ui.colored_label(
                            crate::theme::WARN,
                            format!(
                                "⚠ Notice: Device-specific data partition(s) selected: {}. Never flash a factory copy onto a phone.",
                                dangerous.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                            ),
                        );
                    });
                }

                ui.add_space(3.0);

                // Partition Table Header & Controls
                let total_selected_size: u64 = info
                    .partitions
                    .iter()
                    .filter(|p| selected_partitions.contains(&p.name))
                    .map(|p| p.size)
                    .sum();

                ui.horizontal(|ui| {
                    ui.label(format!(
                        "Partitions: {} / {} selected ({})",
                        selected_partitions.len(),
                        info.partitions.len(),
                        format_bytes(total_selected_size)
                    ));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.filter_text)
                                .hint_text("Filter partitions..."),
                        );
                        if ui.button("Select None").clicked() {
                            action_select_none = true;
                        }
                        if ui.button("Select All").clicked() {
                            action_select_all = true;
                        }
                    });
                });

                ui.add_space(3.0);

                // Filtered Partition Grid
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

                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .show(ui, |ui| {
                        egui::Grid::new("partition_grid")
                            .striped(true)
                            .min_col_width(60.0)
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Extract").strong());
                                ui.label(egui::RichText::new("#").strong());
                                ui.label(egui::RichText::new("Partition Name").strong());
                                ui.label(egui::RichText::new("Size").strong());
                                ui.label(egui::RichText::new("Encrypted").strong());
                                ui.label(egui::RichText::new("Checksum").strong());
                                ui.end_row();

                                for (idx, p) in filtered.iter().enumerate() {
                                    let mut is_checked = selected_partitions.contains(&p.name);
                                    if ui.checkbox(&mut is_checked, "").changed() {
                                        action_toggle_partition = Some(p.name.clone());
                                    }
                                    ui.label(format!("{}", idx + 1));
                                    ui.label(&p.name);
                                    ui.label(format_bytes(p.size));
                                    ui.label(if p.is_encrypted { "Yes" } else { "No" });
                                    ui.label(if p.has_checksum {
                                        "Manifest Hash"
                                    } else {
                                        "None"
                                    });
                                    ui.end_row();
                                }
                            });
                    });

                ui.separator();

                // Actions row
                ui.horizontal(|ui| {
                    if ui.button("Close File").clicked() {
                        action_reset = true;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let can_extract = !selected_partitions.is_empty() && !is_collision;
                        let btn_text = format!(
                            "Extract Selected ({} partitions)",
                            selected_partitions.len()
                        );
                        if ui
                            .add_enabled(
                                can_extract,
                                egui::Button::new(egui::RichText::new(btn_text).strong()),
                            )
                            .clicked()
                        {
                            let mut selected_list: Vec<String> =
                                selected_partitions.iter().cloned().collect();
                            selected_list.sort();
                            action_start_extract =
                                Some((path.clone(), out_dir.clone(), selected_list));
                        }
                    });
                });
            }

            AppState::Extracting {
                path: _,
                out_dir,
                total_items,
                items_done,
                current_item,
                current_item_size,
                bytes_done,
                bytes_total,
                start_time,
                speed_mb_s,
                warnings: _,
                cancelling,
            } => {
                ui.vertical(|ui| {
                    ui.heading("Extracting Firmware...");
                    ui.label(format!("Destination: {}", out_dir.display()));
                    ui.add_space(15.0);

                    let fraction = if *bytes_total > 0 {
                        (*bytes_done as f32 / *bytes_total as f32).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };

                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .show_percentage()
                            .animate(true),
                    );

                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "Progress: {} / {} ({:.1}%)",
                            format_bytes(*bytes_done),
                            format_bytes(*bytes_total),
                            fraction * 100.0
                        ));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(format!(
                                "Avg Speed: {:.1} MB/s | Elapsed: {} | Item: {} / {}",
                                *speed_mb_s,
                                format_duration(start_time.elapsed()),
                                *items_done,
                                *total_items
                            ));
                        });
                    });

                    ui.add_space(15.0);
                    ui.group(|ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Writing:").strong());
                            ui.label(egui::RichText::new(current_item).monospace());
                            ui.label(format!("({})", format_bytes(*current_item_size)));
                        });
                    });

                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        if *cancelling {
                            ui.colored_label(
                                crate::theme::WARN,
                                "Cancelling... waiting for chunk to stop and clean up partial file",
                            );
                        } else if ui
                            .button(
                                egui::RichText::new("Cancel Extraction")
                                    .color(egui::Color32::from_rgb(230, 80, 80)),
                            )
                            .clicked()
                        {
                            action_cancel_extract = true;
                        }
                    });
                });
            }

            AppState::Done {
                path,
                out_dir,
                summary,
                elapsed,
                warnings,
            } => {
                ui.vertical(|ui| {
                    ui.colored_label(
                        crate::theme::OK,
                        egui::RichText::new("✓ Extraction Complete").size(20.0).strong(),
                    );
                    ui.add_space(5.0);
                    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("firmware");
                    ui.label(format!("Source: {}", fname));
                    ui.label(format!(
                        "Extracted {} item(s) totaling {} in {}",
                        summary.items.len(),
                        format_bytes(summary.total_bytes),
                        format_duration(*elapsed)
                    ));
                    ui.label(format!("Destination: {}", out_dir.display()));

                    if !warnings.is_empty() {
                        ui.add_space(5.0);
                        ui.group(|ui| {
                            ui.colored_label(
                                crate::theme::WARN,
                                egui::RichText::new("Warnings:").strong(),
                            );
                            for w in warnings {
                                ui.label(w);
                            }
                        });
                    }

                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("Extracted Files & Integrity Status:").strong());

                    egui::ScrollArea::vertical()
                        .max_height(240.0)
                        .show(ui, |ui| {
                            egui::Grid::new("done_grid")
                                .striped(true)
                                .min_col_width(80.0)
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("#").strong());
                                    ui.label(egui::RichText::new("File Name").strong());
                                    ui.label(egui::RichText::new("Size").strong());
                                    ui.label(egui::RichText::new("Integrity Check").strong());
                                    ui.end_row();

                                    for (idx, item) in summary.items.iter().enumerate() {
                                        ui.label(format!("{}", idx + 1));
                                        ui.label(&item.name);
                                        ui.label(format_bytes(item.size));
                                        match item.checksum {
                                            ChecksumStatus::VerifiedFull => {
                                                ui.colored_label(
                                                    crate::theme::OK,
                                                    "[Verified full]",
                                                );
                                            }
                                            ChecksumStatus::VerifiedHeadOnly => {
                                                ui.colored_label(
                                                    crate::theme::WARN,
                                                    "[Head checked only]",
                                                );
                                            }
                                            ChecksumStatus::NoHashInManifest => {
                                                ui.colored_label(
                                                    egui::Color32::from_rgb(150, 150, 150),
                                                    "[No checksum available]",
                                                );
                                            }
                                            ChecksumStatus::Failed => {
                                                ui.colored_label(
                                                    egui::Color32::from_rgb(230, 80, 80),
                                                    "[Failed]",
                                                );
                                            }
                                        }
                                        ui.end_row();
                                    }
                                });
                        });

                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Open Output Folder").clicked() {
                            action_open_folder = Some(out_dir.clone());
                        }
                        if ui.button("Extract Another File").clicked() {
                            action_reset = true;
                        }
                    });
                });
            }

            AppState::Cancelled { path: _, out_dir } => {
                ui.vertical_centered(|ui| {
                    ui.add_space(50.0);
                    ui.colored_label(
                        crate::theme::WARN,
                        egui::RichText::new("Extraction Cancelled").size(20.0).strong(),
                    );
                    ui.add_space(10.0);
                    ui.label("The operation was stopped by user request.");
                    ui.label("Incomplete (.part) files have been automatically removed from destination.");
                    ui.add_space(20.0);

                    ui.horizontal(|ui| {
                        if ui.button("Open Output Folder").clicked() {
                            action_open_folder = Some(out_dir.clone());
                        }
                        if ui.button("Back to Firmware Inspector").clicked() {
                            action_back_to_ready = true;
                        }
                        if ui.button("Choose Another File").clicked() {
                            action_reset = true;
                        }
                    });
                });
            }

            AppState::Error {
                path,
                message,
                details,
            } => {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.colored_label(
                        egui::Color32::from_rgb(230, 80, 80),
                        egui::RichText::new("Error").size(18.0),
                    );
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

        // 5. Apply deferred actions
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
        if action_pick_out_dir {
            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                if let AppState::Ready { out_dir, .. } = &mut self.state {
                    *out_dir = folder;
                }
            }
        }
        if action_select_all {
            if let AppState::Ready {
                info,
                selected_partitions,
                ..
            } = &mut self.state
            {
                selected_partitions.extend(info.partitions.iter().map(|p| p.name.clone()));
            }
        }
        if action_select_none {
            if let AppState::Ready {
                selected_partitions,
                ..
            } = &mut self.state
            {
                selected_partitions.clear();
            }
        }
        if let Some(name) = action_toggle_partition {
            if let AppState::Ready {
                selected_partitions,
                ..
            } = &mut self.state
            {
                if selected_partitions.contains(&name) {
                    selected_partitions.remove(&name);
                } else {
                    selected_partitions.insert(name);
                }
            }
        }
        if let Some((p, out, sel)) = action_start_extract {
            // Pre-check free disk space
            let total_selected_size: u64 = if let AppState::Ready { info, .. } = &self.state {
                info.partitions
                    .iter()
                    .filter(|part| sel.contains(&part.name))
                    .map(|part| part.size)
                    .sum()
            } else {
                0
            };

            let mut proceed = true;
            if let Some(free_bytes) = get_free_disk_space(&out) {
                if free_bytes < total_selected_size {
                    if let AppState::Ready { disk_warning, .. } = &mut self.state {
                        *disk_warning = Some(format!(
                            "Warning: Low disk space! Destination has {} free, but {} selected.",
                            format_bytes(free_bytes),
                            format_bytes(total_selected_size)
                        ));
                    }
                    proceed = false;
                }
            }

            if proceed {
                self.start_extraction(p, out, sel, ctx);
            }
        }
        if action_cancel_extract {
            if let Some(ref flag) = self.cancel_flag {
                flag.store(true, Ordering::Relaxed);
            }
            if let AppState::Extracting { cancelling, .. } = &mut self.state {
                *cancelling = true;
            }
        }
        if let Some(folder) = action_open_folder {
            open_folder(&folder);
        }
        if action_back_to_ready {
            if let AppState::Cancelled { path, .. } = &self.state {
                self.start_inspection(path.clone(), ctx);
            }
        }
    }
}

pub fn format_bytes(bytes: u64) -> String {
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

pub fn format_duration(dur: Duration) -> String {
    let total_secs = dur.as_secs();
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    format!("{:02}:{:02}", mins, secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozipdecrypt_core::{ExtractItemSummary, PartitionMeta, VerificationLevel};

    fn make_test_app() -> OzipGuiApp {
        let (tx, rx) = channel();
        OzipGuiApp {
            state: AppState::Idle,
            keys: KeyConfig::default(),
            keys_path: None,
            tx,
            rx,
            filter_text: String::new(),
            cancel_flag: None,
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
        let msg = map_ozip_error(&err_checksum);
        assert!(msg.contains("Integrity check failed for partition 'boot.img'"));
        assert!(msg.contains("expected SHA-256 aaa, but calculated bbb"));

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
            partitions: vec![PartitionMeta {
                name: "boot.img".to_string(),
                size: 67108864,
                is_encrypted: true,
                has_checksum: true,
                checksum: Some("abcdef".to_string()),
            }],
        };

        app.handle_worker_message(WorkerMessage::InspectionDone {
            path: path.clone(),
            result: Ok(info),
        });

        match &app.state {
            AppState::Ready {
                path: p,
                info: i,
                out_dir,
                selected_partitions,
                ..
            } => {
                assert_eq!(p, &path);
                assert_eq!(i.container_type, ContainerType::OfpQualcomm);
                assert_eq!(i.verification_level, VerificationLevel::Verified);
                assert_eq!(out_dir, &PathBuf::from("firmware_extracted"));
                assert!(selected_partitions.contains("boot.img"));
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
    fn test_extraction_progress_updates_and_done() {
        let mut app = make_test_app();
        app.state = AppState::Extracting {
            path: PathBuf::from("firmware.ofp"),
            out_dir: PathBuf::from("firmware_extracted"),
            total_items: 2,
            items_done: 0,
            current_item: String::new(),
            current_item_size: 0,
            bytes_done: 0,
            bytes_total: 0,
            start_time: Instant::now(),
            speed_mb_s: 0.0,
            warnings: vec![],
            cancelling: false,
        };

        // 1. Started event
        app.handle_worker_message(WorkerMessage::Progress(ProgressEvent::Started {
            total_items: 2,
            total_bytes: 2000,
        }));
        if let AppState::Extracting {
            total_items,
            bytes_total,
            ..
        } = &app.state
        {
            assert_eq!(*total_items, 2);
            assert_eq!(*bytes_total, 2000);
        } else {
            panic!("Expected Extracting state");
        }

        // 2. ItemStarted event
        app.handle_worker_message(WorkerMessage::Progress(ProgressEvent::ItemStarted {
            name: "boot.img".to_string(),
            size: 1000,
        }));
        if let AppState::Extracting {
            current_item,
            current_item_size,
            ..
        } = &app.state
        {
            assert_eq!(current_item, "boot.img");
            assert_eq!(*current_item_size, 1000);
        } else {
            panic!("Expected Extracting state");
        }

        // 3. Progress event
        app.handle_worker_message(WorkerMessage::Progress(ProgressEvent::Progress {
            bytes_done: 500,
            bytes_total: 2000,
        }));
        if let AppState::Extracting { bytes_done, .. } = &app.state {
            assert_eq!(*bytes_done, 500);
        } else {
            panic!("Expected Extracting state");
        }

        // 4. ExtractionDone event
        let summary = ExtractSummary {
            container_type: ContainerType::OfpQualcomm,
            items: vec![
                ExtractItemSummary {
                    name: "boot.img".to_string(),
                    size: 1000,
                    checksum: ChecksumStatus::VerifiedFull,
                },
                ExtractItemSummary {
                    name: "system.img".to_string(),
                    size: 1000,
                    checksum: ChecksumStatus::VerifiedHeadOnly,
                },
            ],
            total_bytes: 2000,
        };

        app.handle_worker_message(WorkerMessage::ExtractionDone {
            result: Ok(summary),
            elapsed: Duration::from_secs(5),
        });

        match &app.state {
            AppState::Done {
                summary, elapsed, ..
            } => {
                assert_eq!(summary.items.len(), 2);
                assert_eq!(summary.total_bytes, 2000);
                assert_eq!(elapsed.as_secs(), 5);
            }
            other => panic!("Expected AppState::Done, got {:?}", other),
        }
    }

    #[test]
    fn test_extraction_cancelled_transitions_to_cancelled_state_typed() {
        let mut app = make_test_app();
        app.state = AppState::Extracting {
            path: PathBuf::from("firmware.ofp"),
            out_dir: PathBuf::from("firmware_extracted"),
            total_items: 2,
            items_done: 0,
            current_item: "boot.img".to_string(),
            current_item_size: 1000,
            bytes_done: 500,
            bytes_total: 2000,
            start_time: Instant::now(),
            speed_mb_s: 0.0,
            warnings: vec![],
            cancelling: true,
        };

        // Typed OzipError::Cancelled matching:
        app.handle_worker_message(WorkerMessage::ExtractionDone {
            result: Err(OzipError::Cancelled),
            elapsed: Duration::from_secs(1),
        });

        match &app.state {
            AppState::Cancelled { path, out_dir } => {
                assert_eq!(path, &PathBuf::from("firmware.ofp"));
                assert_eq!(out_dir, &PathBuf::from("firmware_extracted"));
            }
            other => panic!("Expected AppState::Cancelled, got {:?}", other),
        }
    }

    #[test]
    fn test_paths_collide() {
        let file = PathBuf::from("D:/firmware/update.ofp");
        let parent = PathBuf::from("D:/firmware");
        let dest_same = PathBuf::from("D:/firmware/update.ofp");
        let dest_child = PathBuf::from("D:/firmware/update_extracted");
        let dest_other = PathBuf::from("E:/extracted");

        assert!(paths_collide(&dest_same, &file));
        assert!(paths_collide(&parent, &file));
        assert!(!paths_collide(&dest_child, &file));
        assert!(!paths_collide(&dest_other, &file));
    }

    #[test]
    fn test_gui_reporter_throttles_progress_events() {
        let (tx, rx) = channel();
        let ctx = egui::Context::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let reporter = GuiReporter::new(tx, ctx, cancel);

        // Send Started (immediate)
        reporter.on_event(ProgressEvent::Started {
            total_items: 1,
            total_bytes: 10000,
        });

        // Send two Progress events in immediate microsecond succession
        reporter.on_event(ProgressEvent::Progress {
            bytes_done: 100,
            bytes_total: 10000,
        });
        reporter.on_event(ProgressEvent::Progress {
            bytes_done: 200,
            bytes_total: 10000,
        });

        // Send ItemDone (immediate)
        reporter.on_event(ProgressEvent::ItemDone {
            name: "test.img".to_string(),
            checksum: ChecksumStatus::VerifiedFull,
        });

        let mut received = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            received.push(msg);
        }

        // Must receive Started, the first Progress, and ItemDone. Second rapid Progress should be throttled.
        assert!(received.len() >= 3);
        assert!(matches!(
            received[0],
            WorkerMessage::Progress(ProgressEvent::Started { .. })
        ));
        assert!(matches!(
            received.last().unwrap(),
            WorkerMessage::Progress(ProgressEvent::ItemDone { .. })
        ));
    }

    #[test]
    fn test_device_specific_partition_detector() {
        assert!(is_device_specific_partition("persist.img"));
        assert!(is_device_specific_partition("modemst1.img"));
        assert!(is_device_specific_partition("modemst2.img"));
        assert!(is_device_specific_partition("fsg.img"));
        assert!(is_device_specific_partition("nvdata.img"));
        assert!(is_device_specific_partition("nvram"));
        assert!(is_device_specific_partition("nvbk"));
        assert!(!is_device_specific_partition("boot.img"));
        assert!(!is_device_specific_partition("system.img"));
        assert!(!is_device_specific_partition("vendor.img"));
    }

    #[test]
    fn test_format_duration_utility() {
        assert_eq!(format_duration(Duration::from_secs(0)), "00:00");
        assert_eq!(format_duration(Duration::from_secs(45)), "00:45");
        assert_eq!(format_duration(Duration::from_secs(65)), "01:05");
        assert_eq!(format_duration(Duration::from_secs(3665)), "61:05");
    }

    #[test]
    fn test_format_bytes_utility() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }
}
