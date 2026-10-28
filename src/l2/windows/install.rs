//! Installation of SoftEther's signed SeLow and Neo6 (VPN127) drivers, shipped in `drivers\`
//! next to the executable (copied unchanged from SoftEtherVPN_Stable/src/bin/hamcore/DriverPackages).
//! Requires administrator rights.

use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use super::ffi::{self, GUID, HDEVINFO, devinfo_data, wide};
use super::{CLIENT_ADAPTER_NAME, NEO_INSTANCE, neo, reg, selow};
use crate::log::Logger;

pub struct DriverStatus {
    pub selow: bool,
    pub neo: bool,
}

pub fn status() -> DriverStatus {
    DriverStatus { selow: selow::is_available(), neo: neo::is_installed() }
}

pub fn drivers_dir() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_default();
    let dir = exe_dir.join("drivers");
    if dir.exists() { dir } else { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("drivers") }
}

/// Driver architecture matching this build ("x64" or "x86"); file names use it.
const ARCH: &str = if cfg!(target_arch = "x86") { "x86" } else { "x64" };

/// Windows cannot install drivers from a 32-bit process on 64-bit Windows (and would need the
/// x64 drivers anyway).
fn check_arch() -> io::Result<()> {
    let wow64 = std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|a| !a.eq_ignore_ascii_case("x86"));
    if cfg!(target_arch = "x86") && wow64 {
        return Err(io::Error::other(
            "this is the 32-bit EasyEther; on 64-bit Windows please use the 64-bit (x64) version",
        ));
    }
    Ok(())
}

/// Full path of a Windows tool. We run elevated from a user-writable folder, so never let
/// the process search that folder or PATH for `netcfg.exe` & co.
pub fn system_tool(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join(name)
}

/// Runs a system tool quietly; on failure its output becomes the error message.
pub fn run(program: &str, args: &[&str]) -> io::Result<()> {
    let out = Command::new(system_tool(program)).args(args).output()?;
    if out.status.success() {
        return Ok(());
    }
    let mut text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        text.push(' ');
        text.push_str(err.trim());
    }
    Err(io::Error::other(format!("{program} failed: {}", text.trim())))
}

/// Installs whatever is missing and logs one result line.
pub fn install_all(log: &Logger) -> io::Result<()> {
    check_arch()?;
    let st = status();
    let mut restart = false;
    if !st.selow {
        restart |= install_selow().map_err(|e| io::Error::new(e.kind(), format!("SeLow: {e}")))?;
    }
    if !st.neo {
        restart |= install_neo().map_err(|e| io::Error::new(e.kind(), format!("virtual adapter: {e}")))?;
    }
    if restart {
        log.warn("Drivers installed. Restart Windows to finish the installation.");
    } else {
        log.info("Drivers installed successfully.");
    }
    Ok(())
}

/// Removes the virtual adapter, unregisters SeLow and deletes both driver packages
/// from the Windows driver store. Logs one result line.
pub fn uninstall_all(log: &Logger) -> io::Result<()> {
    check_arch()?;
    let mut problems = Vec::new();
    if let Err(e) = remove_devices(&format!("NeoAdapter_{NEO_INSTANCE}")) {
        problems.push(format!("virtual adapter: {e}"));
    }
    // Fails harmlessly when SeLow is not registered.
    let _ = run("netcfg.exe", &["-u", "SeLow"]);
    let _ = run("sc.exe", &["stop", "SeLow"]);
    for inf in [format!("Neo6_{ARCH}_{NEO_INSTANCE}.inf"), format!("SeLow_{ARCH}.inf")] {
        if let Err(e) = delete_driver_package(&inf) {
            problems.push(format!("{inf}: {e}"));
        }
    }
    if problems.is_empty() {
        log.info("Drivers uninstalled. A Windows restart may be needed to unload SeLow completely.");
        Ok(())
    } else {
        Err(io::Error::other(problems.join("; ")))
    }
}

/// Deletes every driver-store package (oemNN.inf) whose original INF name matches.
fn delete_driver_package(original_inf: &str) -> io::Result<()> {
    let out = Command::new(system_tool("pnputil.exe")).arg("/enum-drivers").output()?;
    // Labels are localized; the oemNN.inf and original file names are not.
    let text = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n").to_lowercase();
    let wanted = original_inf.to_lowercase();
    for block in text.split("\n\n").filter(|b| b.contains(&wanted)) {
        if let Some(oem) = block.split_whitespace().find(|w| w.starts_with("oem") && w.ends_with(".inf")) {
            run("pnputil.exe", &["/delete-driver", oem, "/uninstall", "/force"])?;
        }
    }
    Ok(())
}

/// Returns true when a restart is needed before the driver works.
fn install_selow() -> io::Result<bool> {
    let inf = drivers_dir().join("selow").join(format!("SeLow_{ARCH}.inf"));
    if !inf.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{} not found", inf.display())));
    }
    // Remove a stale registration first (ignore errors: usually it is simply not installed).
    let _ = run("netcfg.exe", &["-u", "SeLow"]);
    run("netcfg.exe", &["-l", &inf.to_string_lossy(), "-c", "p", "-i", "SeLow"])?;
    // Same marker SoftEther writes, so a SoftEther installer recognises the version.
    let _ = reg::set_u32(r"SYSTEM\CurrentControlSet\services\SeLow", "SlVersion_Win10", 48);
    let _ = run("sc.exe", &["start", "SeLow"]);
    for _ in 0..40 {
        if selow::is_available() {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(true)
}

struct DevInfoSet(HDEVINFO);

impl Drop for DevInfoSet {
    fn drop(&mut self) {
        // SAFETY: the set was created by SetupAPI and is destroyed once.
        unsafe { ffi::SetupDiDestroyDeviceInfoList(self.0) };
    }
}

fn check(ok: ffi::BOOL, what: &str) -> io::Result<()> {
    if ok == 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{what}: {e}")));
    }
    Ok(())
}

/// Removes leftover device nodes with the given hardware id (present or not).
fn remove_devices(hwid: &str) -> io::Result<usize> {
    // SAFETY: SetupAPI calls with valid arguments; buffers outlive the calls.
    unsafe {
        let set = ffi::SetupDiGetClassDevsW(std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), ffi::DIGCF_ALLCLASSES);
        if set == ffi::INVALID_HANDLE_VALUE as HDEVINFO {
            return Err(io::Error::last_os_error());
        }
        let set = DevInfoSet(set);
        let mut removed = 0;
        let mut i = 0;
        loop {
            let mut data = devinfo_data();
            if ffi::SetupDiEnumDeviceInfo(set.0, i, &mut data) == 0 {
                break;
            }
            i += 1;
            let mut buf = [0u16; 512];
            let mut ty = 0u32;
            if ffi::SetupDiGetDeviceRegistryPropertyW(
                set.0,
                &data,
                ffi::SPDRP_HARDWAREID,
                &mut ty,
                buf.as_mut_ptr().cast(),
                (buf.len() * 2) as u32,
                std::ptr::null_mut(),
            ) == 0
            {
                continue;
            }
            let ids = String::from_utf16_lossy(&buf);
            if ids.split('\0').any(|id| id.eq_ignore_ascii_case(hwid)) && ffi::SetupDiRemoveDevice(set.0, &mut data) != 0 {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// Returns true when Windows asks for a restart.
fn install_neo() -> io::Result<bool> {
    let inf = drivers_dir().join("neo").join(format!("Neo6_{ARCH}_{NEO_INSTANCE}.inf"));
    if !inf.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{} not found", inf.display())));
    }
    let hwid = format!("NeoAdapter_{NEO_INSTANCE}");
    remove_devices(&hwid)?;

    let inf_w = wide(&inf.to_string_lossy());
    let hwid_w = wide(&hwid);
    let instance_id;
    let mut reboot = 0;
    // SAFETY: SetupAPI calls with valid arguments; buffers outlive the calls.
    unsafe {
        let mut class_guid = GUID::default();
        let mut class_name = [0u16; 256];
        check(
            ffi::SetupDiGetINFClassW(inf_w.as_ptr(), &mut class_guid, class_name.as_mut_ptr(), 256, std::ptr::null_mut()),
            "SetupDiGetINFClass",
        )?;
        let set = ffi::SetupDiCreateDeviceInfoList(&class_guid, std::ptr::null_mut());
        if set == ffi::INVALID_HANDLE_VALUE as HDEVINFO {
            return Err(io::Error::last_os_error());
        }
        let set = DevInfoSet(set);
        let mut data = devinfo_data();
        check(
            ffi::SetupDiCreateDeviceInfoW(
                set.0,
                class_name.as_ptr(),
                &class_guid,
                std::ptr::null(),
                std::ptr::null_mut(),
                ffi::DICD_GENERATE_ID,
                &mut data,
            ),
            "SetupDiCreateDeviceInfo",
        )?;
        // REG_MULTI_SZ: the id followed by an extra terminating NUL.
        let mut multi = hwid_w.clone();
        multi.push(0);
        check(
            ffi::SetupDiSetDeviceRegistryPropertyW(
                set.0,
                &mut data,
                ffi::SPDRP_HARDWAREID,
                multi.as_ptr().cast(),
                (multi.len() * 2) as u32,
            ),
            "SetupDiSetDeviceRegistryProperty",
        )?;
        check(ffi::SetupDiCallClassInstaller(ffi::DIF_REGISTERDEVICE, set.0, &data), "DIF_REGISTERDEVICE")?;

        if ffi::UpdateDriverForPlugAndPlayDevicesW(
            std::ptr::null_mut(),
            hwid_w.as_ptr(),
            inf_w.as_ptr(),
            ffi::INSTALLFLAG_FORCE,
            &mut reboot,
        ) == 0
        {
            let e = io::Error::last_os_error();
            ffi::SetupDiCallClassInstaller(ffi::DIF_REMOVE, set.0, &data);
            return Err(io::Error::new(e.kind(), format!("UpdateDriverForPlugAndPlayDevices: {e}")));
        }
        let mut id = [0u16; 512];
        ffi::SetupDiGetDeviceInstanceIdW(set.0, &data, id.as_mut_ptr(), id.len() as u32, std::ptr::null_mut());
        let end = id.iter().position(|&c| c == 0).unwrap_or(id.len());
        instance_id = String::from_utf16_lossy(&id[..end]);
    }
    configure_neo(&instance_id);
    Ok(reboot != 0)
}

/// Gives the adapter a stable MAC (the driver default changes on every load) and a
/// recognisable connection name. Best effort: failures here are not fatal.
fn configure_neo(instance_id: &str) {
    let mut mac = [0u8; 6];
    let _ = getrandom::fill(&mut mac);
    mac[0] = 0x5E; // same locally-administered style prefix SoftEther uses
    let mac_str: String = mac.iter().map(|b| format!("{b:02X}")).collect();
    if reg::set_adapter_param(CLIENT_ADAPTER_NAME, "NetworkAddress", &mac_str).is_ok() && !instance_id.is_empty() {
        let _ = run("pnputil.exe", &["/restart-device", instance_id]);
    }
    // The connection appears a moment after installation.
    for _ in 0..20 {
        if let Some(guid) = reg::guid_by_desc(CLIENT_ADAPTER_NAME) {
            if let Some(old) = reg::connection_name(&guid) {
                if old != "EasyEther" {
                    let _ = run(
                        "netsh.exe",
                        &["interface", "set", "interface", &format!("name={old}"), "newname=EasyEther"],
                    );
                }
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
