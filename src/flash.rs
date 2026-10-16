use anyhow::{bail, Context, Result};
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug)]
struct AdbDevice {
    serial: String,
    state: String,
}

pub fn adb_sideload(zip_path: &Path) -> Result<()> {
    println!("[*] Checking for connected Android devices via ADB...");
    let devices_output = Command::new("adb")
        .arg("devices")
        .output()
        .context("Failed to execute 'adb'. Ensure Android SDK Platform-Tools is installed and in your PATH.")?;

    let stdout = String::from_utf8_lossy(&devices_output.stdout);
    let mut devices = Vec::new();

    for line in stdout.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            devices.push(AdbDevice {
                serial: parts[0].to_string(),
                state: parts[1].to_string(),
            });
        }
    }

    if devices.is_empty() {
        bail!(
            "No Android device detected by ADB.\n\
             To sideload firmware:\n\
             1. Power off the phone.\n\
             2. Hold Power + Volume Down until Recovery appears.\n\
             3. Select: English -> Install from storage device -> Install from ADB.\n\
             4. Connect USB cable to PC and ensure drivers are installed, then rerun."
        );
    }

    // Check for unauthorized devices
    for dev in &devices {
        if dev.state == "unauthorized" {
            bail!(
                "Device '{}' is UNAUTHORIZED.\n\
                 Please check your phone screen and tap 'Always allow from this computer'.",
                dev.serial
            );
        }
    }

    // Find device in sideload mode
    let target_device = if let Some(sideload_dev) = devices.iter().find(|d| d.state == "sideload") {
        println!("[+] Found device {} in 'sideload' mode.", sideload_dev.serial);
        sideload_dev.serial.clone()
    } else if let Some(os_dev) = devices.iter().find(|d| d.state == "device") {
        println!("[!] Device {} is running in standard Android OS mode.", os_dev.serial);
        print!("[?] Would you like to reboot {} into Recovery mode now? [y/N]: ", os_dev.serial);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes") {
            println!("[*] Rebooting {} into Recovery mode...", os_dev.serial);
            let _ = Command::new("adb")
                .arg("-s")
                .arg(&os_dev.serial)
                .arg("reboot")
                .arg("recovery")
                .status();
            bail!(
                "Device {} rebooted to Recovery.\n\
                 Once in Recovery, select: 'Install from storage device' -> 'Install from ADB', then rerun.",
                os_dev.serial
            );
        } else {
            bail!("Aborted. Manually enter Recovery mode ('Install from ADB') and rerun.");
        }
    } else {
        bail!(
            "No device in 'sideload' mode found. Connected devices:\n{:?}\n\
             Please enter Recovery mode ('Install from ADB') first.",
            devices
        );
    };

    println!("[*] Starting ADB sideload of {} to {}...", zip_path.display(), target_device);
    let status = Command::new("adb")
        .arg("-s")
        .arg(&target_device)
        .arg("sideload")
        .arg(zip_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to run 'adb sideload'")?;

    if !status.success() {
        bail!("adb sideload exited with error code: {}", status);
    }

    println!("[+] Sideload finished! Tap 'Reboot' on your device screen.");
    Ok(())
}
