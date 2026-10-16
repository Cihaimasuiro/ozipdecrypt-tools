use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::{Command, Stdio};

pub fn adb_sideload(zip_path: &Path) -> Result<()> {
    println!("[*] Checking for connected Android device...");
    let devices_output = Command::new("adb")
        .arg("devices")
        .output()
        .context("Failed to execute 'adb'. Ensure Android SDK Platform-Tools is installed and in your PATH.")?;

    let stdout = String::from_utf8_lossy(&devices_output.stdout);
    if stdout.contains("sideload") {
        println!("[+] Device detected in 'sideload' mode.");
    } else if stdout.contains("\tdevice") {
        println!("[!] Device detected in standard Android OS mode.");
        println!("[*] Rebooting device into Recovery mode for sideloading...");
        let _ = Command::new("adb").arg("reboot").arg("recovery").status();
        bail!(
            "Device was rebooted into Recovery mode.\n\
             Once in Recovery, select: 'Install from storage device' -> 'Install from ADB', then rerun this command."
        );
    } else {
        bail!(
            "No device detected in 'sideload' state.\n\
             On your Oppo A7:\n\
             1. Power off the phone.\n\
             2. Hold Power + Volume Down until Recovery appears.\n\
             3. Select: English -> Install from storage device -> Install from ADB.\n\
             4. Connect USB cable and rerun this command."
        );
    }

    println!("[*] Starting ADB sideload of {}...", zip_path.display());
    let status = Command::new("adb")
        .arg("sideload")
        .arg(zip_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to run 'adb sideload'")?;

    if !status.success() {
        bail!("adb sideload exited with error code: {}", status);
    }

    println!("[+] Sideload finished! Tap 'Reboot' on your Oppo phone screen.");
    Ok(())
}
