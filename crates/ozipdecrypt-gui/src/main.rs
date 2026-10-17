#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;

use app::OzipGuiApp;
use eframe::egui;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ozipdecrypt - Oppo / Realme / OnePlus Firmware Decryptor")
            .with_inner_size([780.0, 540.0])
            .with_min_inner_size([540.0, 400.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "ozipdecrypt-gui",
        native_options,
        Box::new(|cc| {
            // Apply default dark visuals
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(OzipGuiApp::new(cc)))
        }),
    )
}
