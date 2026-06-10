use std::env;
use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tun_rs::DeviceBuilder;

include!(concat!(env!("OUT_DIR"), "/embedded_wintun.rs"));

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const PE_MACHINE_AMD64: u16 = 0x8664;
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const PE_MACHINE_ARM64: u16 = 0xaa64;

#[derive(Debug, Default)]
pub struct TunPlatformConfig {
    #[cfg_attr(not(windows), allow(dead_code))]
    pub wintun_file: Option<String>,
}

pub fn prepare_tun_builder(builder: DeviceBuilder) -> Result<DeviceBuilder> {
    let platform = preflight_tun_platform()?;
    Ok(apply_platform_config(builder, platform))
}

#[derive(Debug)]
pub struct DnsConfigGuard {
    restore_commands: Vec<CommandSpec>,
}

impl DnsConfigGuard {
    fn new(restore_commands: Vec<CommandSpec>) -> Self {
        Self { restore_commands }
    }
}

impl Drop for DnsConfigGuard {
    fn drop(&mut self) {
        for command in self.restore_commands.iter().rev() {
            if let Err(err) = run_command(command) {
                eprintln!("dns: failed to restore system DNS: {err:#}");
            }
        }
    }
}

pub fn configure_system_dns(if_name: &str, dns_ip: Ipv4Addr) -> Result<DnsConfigGuard> {
    configure_system_dns_for_platform(if_name, dns_ip)
}

pub fn preflight_system_dns() -> Result<()> {
    preflight_system_dns_for_platform()
}

pub fn preflight_route_management() -> Result<()> {
    preflight_route_management_for_platform()
}

#[cfg(windows)]
fn apply_platform_config(mut builder: DeviceBuilder, platform: TunPlatformConfig) -> DeviceBuilder {
    #[cfg(windows)]
    if let Some(wintun_file) = platform.wintun_file {
        builder = builder.wintun_file(wintun_file);
    }
    builder
}

#[cfg(not(windows))]
fn apply_platform_config(builder: DeviceBuilder, _platform: TunPlatformConfig) -> DeviceBuilder {
    builder
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandSpec {
    program: String,
    args: Vec<String>,
}

impl CommandSpec {
    fn new(program: impl Into<String>, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

fn run_command(command: &CommandSpec) -> Result<String> {
    let output = Command::new(&command.program)
        .args(&command.args)
        .output()
        .with_context(|| format!("failed to execute {}", command.program))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "command failed: {} {}\nstdout: {}\nstderr: {}",
            command.program,
            command.args.join(" "),
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "macos")]
fn preflight_system_dns_for_platform() -> Result<()> {
    let services =
        macos_network_services().context("failed to inspect macOS network services for DNS")?;
    if services.is_empty() {
        bail!("no enabled macOS network services found for DNS configuration");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn preflight_system_dns_for_platform() -> Result<()> {
    ensure_command_available("resolvectl").context(
        "resolvectl is required for --dns on Linux; install systemd-resolved or omit --dns",
    )
}

#[cfg(windows)]
fn preflight_system_dns_for_platform() -> Result<()> {
    ensure_command_available("netsh").context(
        "netsh is required for --dns on Windows; omit --dns if resolver takeover is not needed",
    )
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn preflight_system_dns_for_platform() -> Result<()> {
    bail!(
        "automatic DNS configuration is not implemented for {}; omit --dns",
        env::consts::OS
    );
}

#[cfg(target_os = "macos")]
fn preflight_route_management_for_platform() -> Result<()> {
    ensure_command_available("route").context("route is required to add target routes on macOS")
}

#[cfg(target_os = "linux")]
fn preflight_route_management_for_platform() -> Result<()> {
    ensure_command_available("ip")
        .context("ip is required to add target routes on Linux; install iproute2")
}

#[cfg(windows)]
fn preflight_route_management_for_platform() -> Result<()> {
    ensure_command_available("route")
        .context("route.exe is required to add target routes on Windows")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn preflight_route_management_for_platform() -> Result<()> {
    bail!(
        "route management is not implemented for {}; supported targets are Windows, macOS, and Linux",
        env::consts::OS
    );
}

#[cfg(target_os = "macos")]
fn configure_system_dns_for_platform(_if_name: &str, dns_ip: Ipv4Addr) -> Result<DnsConfigGuard> {
    let services = macos_network_services()?;
    if services.is_empty() {
        bail!("no enabled macOS network services found for DNS configuration");
    }

    let mut restore_commands = Vec::new();
    for service in services {
        let previous = macos_service_dns_servers(&service)?;
        let set_command = macos_set_dns_command(&service, &[dns_ip.to_string()]);
        run_command(&set_command)
            .with_context(|| format!("failed to set DNS servers for macOS service {service}"))?;
        restore_commands.push(macos_restore_dns_command(&service, &previous));
        eprintln!("dns: set macOS service {service} resolver to {dns_ip}");
    }

    Ok(DnsConfigGuard::new(restore_commands))
}

#[cfg(target_os = "linux")]
fn configure_system_dns_for_platform(if_name: &str, dns_ip: Ipv4Addr) -> Result<DnsConfigGuard> {
    let set_dns = linux_set_dns_command(if_name, dns_ip);
    let set_domain = linux_set_route_domain_command(if_name);
    let restore = linux_restore_dns_command(if_name);

    run_command(&set_dns).context("failed to configure systemd-resolved DNS server")?;
    if let Err(err) =
        run_command(&set_domain).context("failed to configure systemd-resolved route-only domain")
    {
        let _ = run_command(&restore);
        return Err(err);
    }

    eprintln!("dns: set systemd-resolved link {if_name} resolver to {dns_ip}");
    Ok(DnsConfigGuard::new(vec![restore]))
}

#[cfg(windows)]
fn configure_system_dns_for_platform(if_name: &str, dns_ip: Ipv4Addr) -> Result<DnsConfigGuard> {
    let set_dns = windows_set_dns_command(if_name, dns_ip);
    let restore = windows_restore_dns_command(if_name);
    run_command(&set_dns).context("failed to configure Windows interface DNS server")?;
    eprintln!("dns: set Windows interface {if_name} resolver to {dns_ip}");
    Ok(DnsConfigGuard::new(vec![restore]))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn configure_system_dns_for_platform(_if_name: &str, _dns_ip: Ipv4Addr) -> Result<DnsConfigGuard> {
    bail!(
        "automatic DNS configuration is not implemented for {}; omit --dns",
        env::consts::OS
    );
}

#[cfg(target_os = "macos")]
fn macos_network_services() -> Result<Vec<String>> {
    let output = run_command(&CommandSpec::new(
        "networksetup",
        ["-listallnetworkservices"],
    ))?;
    Ok(parse_macos_network_services(&output))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_macos_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let service = line.trim();
            if service.is_empty() || service.starts_with("An asterisk") || service.starts_with('*')
            {
                None
            } else {
                Some(service.to_owned())
            }
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn macos_service_dns_servers(service: &str) -> Result<Vec<String>> {
    let output = run_command(&CommandSpec::new(
        "networksetup",
        ["-getdnsservers", service],
    ))?;
    Ok(parse_macos_dns_servers(&output))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_macos_dns_servers(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("There aren't any DNS Servers")
                && !line.starts_with("There are no DNS Servers")
        })
        .map(str::to_owned)
        .collect()
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn macos_set_dns_command(service: &str, servers: &[String]) -> CommandSpec {
    let mut args = vec!["-setdnsservers".to_owned(), service.to_owned()];
    if servers.is_empty() {
        args.push("Empty".to_owned());
    } else {
        args.extend(servers.iter().cloned());
    }
    CommandSpec::new("networksetup", args)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn macos_restore_dns_command(service: &str, previous_servers: &[String]) -> CommandSpec {
    macos_set_dns_command(service, previous_servers)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_set_dns_command(if_name: &str, dns_ip: Ipv4Addr) -> CommandSpec {
    CommandSpec::new(
        "resolvectl",
        ["dns".to_owned(), if_name.to_owned(), dns_ip.to_string()],
    )
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_set_route_domain_command(if_name: &str) -> CommandSpec {
    CommandSpec::new("resolvectl", ["domain", if_name, "~."])
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_restore_dns_command(if_name: &str) -> CommandSpec {
    CommandSpec::new("resolvectl", ["revert", if_name])
}

#[cfg_attr(not(windows), allow(dead_code))]
fn windows_set_dns_command(if_name: &str, dns_ip: Ipv4Addr) -> CommandSpec {
    CommandSpec::new(
        "netsh",
        [
            "interface".to_owned(),
            "ipv4".to_owned(),
            "set".to_owned(),
            "dnsservers".to_owned(),
            format!("name={if_name}"),
            "static".to_owned(),
            dns_ip.to_string(),
            "primary".to_owned(),
        ],
    )
}

#[cfg_attr(not(windows), allow(dead_code))]
fn windows_restore_dns_command(if_name: &str) -> CommandSpec {
    CommandSpec::new(
        "netsh",
        [
            "interface".to_owned(),
            "ipv4".to_owned(),
            "set".to_owned(),
            "dnsservers".to_owned(),
            format!("name={if_name}"),
            "source=dhcp".to_owned(),
        ],
    )
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
fn ensure_command_available(command: &str) -> Result<()> {
    if command_exists_in_path(command, env::var_os("PATH"), cfg!(windows)) {
        Ok(())
    } else {
        bail!("required command not found in PATH: {command}")
    }
}

#[cfg_attr(not(any(target_os = "linux", windows, test)), allow(dead_code))]
fn command_exists_in_path(command: &str, path: Option<OsString>, windows: bool) -> bool {
    let command_path = Path::new(command);
    if command_path.components().count() > 1 {
        return command_path.is_file();
    }

    let Some(path) = path else {
        return false;
    };

    for dir in env::split_paths(&path) {
        let candidate = dir.join(command);
        if candidate.is_file() {
            return true;
        }
        if windows && command_path.extension().is_none() {
            for extension in ["exe", "com", "bat", "cmd"] {
                if dir.join(format!("{command}.{extension}")).is_file() {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(windows)]
fn preflight_tun_platform() -> Result<TunPlatformConfig> {
    if !windows_is_process_elevated().context("failed to determine Windows elevation")? {
        bail!("administrator privileges are required to create TUN devices and routes on Windows");
    }

    let Some(wintun_file) = find_wintun_dll()? else {
        bail!(
            "wintun.dll was not found; place an architecture-matching wintun.dll beside rustle.exe or set RUSTLE_WINTUN_DLL"
        );
    };

    Ok(TunPlatformConfig {
        wintun_file: Some(wintun_file.to_string_lossy().into_owned()),
    })
}

#[cfg(target_os = "linux")]
fn preflight_tun_platform() -> Result<TunPlatformConfig> {
    if !unix_is_effective_root() {
        bail!(
            "root privileges are required to create TUN devices and routes on Linux; run Rustle with sudo"
        );
    }
    if !linux_tun_device_available() {
        bail!("Linux TUN device /dev/net/tun is unavailable; load the tun kernel module or run on a host with TUN support");
    }
    Ok(TunPlatformConfig::default())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn preflight_tun_platform() -> Result<TunPlatformConfig> {
    if !unix_is_effective_root() {
        bail!(
            "root privileges are required to create TUN devices and routes on {}; run Rustle with sudo",
            env::consts::OS
        );
    }
    Ok(TunPlatformConfig::default())
}

#[cfg(not(any(unix, windows)))]
fn preflight_tun_platform() -> Result<TunPlatformConfig> {
    bail!(
        "TUN privilege preflight is not implemented for {}; supported targets are Windows, macOS, and Linux",
        env::consts::OS
    );
}

#[cfg(target_os = "linux")]
fn linux_tun_device_available() -> bool {
    use std::os::unix::fs::FileTypeExt;

    std::fs::metadata("/dev/net/tun")
        .map(|metadata| metadata.file_type().is_char_device())
        .unwrap_or(false)
}

#[cfg(windows)]
fn find_wintun_dll() -> Result<Option<PathBuf>> {
    let env_path = env::var_os("RUSTLE_WINTUN_DLL").map(PathBuf::from);
    let exe_path = env::current_exe().ok();
    let cwd = env::current_dir().context("failed to read current directory")?;

    if let Some(path) = wintun_candidate_paths(env_path, exe_path, cwd)
        .into_iter()
        .find(|path| path.is_file())
    {
        validate_wintun_dll_arch(&path)?;
        return Ok(Some(path));
    }

    materialize_embedded_wintun_dll()
}

#[cfg(windows)]
fn materialize_embedded_wintun_dll() -> Result<Option<PathBuf>> {
    let Some(bytes) = EMBEDDED_WINTUN_DLL else {
        return Ok(None);
    };
    validate_wintun_arch_bytes(bytes, env::consts::ARCH, "embedded Wintun DLL")?;

    let path = embedded_wintun_path(env::temp_dir(), bytes, env::consts::ARCH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create embedded Wintun directory {}",
                parent.display()
            )
        })?;
    }
    if path.is_file() {
        let existing = std::fs::read(&path).with_context(|| {
            format!(
                "failed to read existing embedded Wintun DLL {}",
                path.display()
            )
        })?;
        if existing == bytes {
            return Ok(Some(path));
        }
    }
    std::fs::write(&path, bytes)
        .with_context(|| format!("failed to write embedded Wintun DLL to {}", path.display()))?;
    Ok(Some(path))
}

#[cfg(windows)]
fn validate_wintun_dll_arch(path: &Path) -> Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read Wintun DLL {}", path.display()))?;
    validate_wintun_arch_bytes(
        &bytes,
        env::consts::ARCH,
        &format!("Wintun DLL {}", path.display()),
    )
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn validate_wintun_arch_bytes(bytes: &[u8], target_arch: &str, source: &str) -> Result<()> {
    let expected = expected_windows_pe_machine(target_arch)
        .with_context(|| format!("unsupported Windows target architecture {target_arch}"))?;
    let actual = pe_machine_from_bytes(bytes)
        .with_context(|| format!("{source} is not a valid PE/COFF DLL"))?;
    if actual != expected {
        bail!(
            "{source} architecture mismatch: expected {}, found {}",
            pe_machine_name(expected),
            pe_machine_name(actual)
        );
    }
    Ok(())
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn expected_windows_pe_machine(target_arch: &str) -> Option<u16> {
    match target_arch {
        "x86_64" => Some(PE_MACHINE_AMD64),
        "aarch64" => Some(PE_MACHINE_ARM64),
        _ => None,
    }
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn pe_machine_from_bytes(bytes: &[u8]) -> Result<u16> {
    if bytes.len() < 0x40 {
        bail!("file is too small for a DOS header");
    }
    if &bytes[..2] != b"MZ" {
        bail!("missing MZ DOS signature");
    }

    let pe_offset =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let machine_offset = pe_offset
        .checked_add(4)
        .ok_or_else(|| anyhow::anyhow!("PE header offset overflowed"))?;
    let machine_end = machine_offset
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("PE machine offset overflowed"))?;
    if bytes.len() < machine_end {
        bail!("file is too small for a PE header");
    }
    if &bytes[pe_offset..machine_offset] != b"PE\0\0" {
        bail!("missing PE signature");
    }

    Ok(u16::from_le_bytes([
        bytes[machine_offset],
        bytes[machine_offset + 1],
    ]))
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn pe_machine_name(machine: u16) -> String {
    match machine {
        PE_MACHINE_AMD64 => "x86_64".to_owned(),
        PE_MACHINE_ARM64 => "aarch64".to_owned(),
        other => format!("unknown PE machine 0x{other:04x}"),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn embedded_wintun_path(temp_dir: PathBuf, bytes: &[u8], target_arch: &str) -> PathBuf {
    temp_dir
        .join("rustle")
        .join(format!("wintun-{target_arch}-{}.dll", sha256_hex(bytes)))
}

#[cfg_attr(not(test), allow(dead_code))]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    lower_hex(digest.as_ref())
}

#[cfg_attr(not(test), allow(dead_code))]
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg_attr(not(test), allow(dead_code))]
fn wintun_candidate_paths(
    env_path: Option<PathBuf>,
    exe_path: Option<PathBuf>,
    cwd: PathBuf,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env_path {
        candidates.push(path);
    }
    if let Some(exe_path) = exe_path {
        if let Some(exe_dir) = exe_path.parent() {
            candidates.push(exe_dir.join("wintun.dll"));
        }
    }
    candidates.push(cwd.join("wintun.dll"));
    dedupe_paths(candidates)
}

#[cfg_attr(not(test), allow(dead_code))]
fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut unique = Vec::new();
    for path in paths {
        if !unique
            .iter()
            .any(|existing: &PathBuf| same_path(existing, &path))
        {
            unique.push(path);
        }
    }
    unique
}

#[cfg(not(windows))]
fn same_path(left: &Path, right: &Path) -> bool {
    left == right
}

#[cfg(windows)]
fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(unix)]
fn unix_is_effective_root() -> bool {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    // SAFETY: geteuid has no preconditions and does not modify memory.
    unsafe { geteuid() == 0 }
}

#[cfg(windows)]
fn windows_is_process_elevated() -> std::io::Result<bool> {
    use std::ffi::c_void;
    use std::mem;
    use std::ptr;

    type Bool = i32;
    type Dword = u32;
    type Handle = *mut c_void;

    const TOKEN_QUERY: Dword = 0x0008;
    const TOKEN_ELEVATION_CLASS: Dword = 20;

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: Dword,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(
            process_handle: Handle,
            desired_access: Dword,
            token_handle: *mut Handle,
        ) -> Bool;
        fn GetTokenInformation(
            token_handle: Handle,
            token_information_class: Dword,
            token_information: *mut c_void,
            token_information_length: Dword,
            return_length: *mut Dword,
        ) -> Bool;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(object: Handle) -> Bool;
    }

    struct OwnedHandle(Handle);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: the handle was returned by OpenProcessToken and is closed exactly once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    let mut token = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle valid for OpenProcessToken.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: token is a valid out pointer.
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let token = OwnedHandle(token);

    let mut elevation = TokenElevation {
        token_is_elevated: 0,
    };
    let mut returned = 0;
    // SAFETY: all pointers are valid for the provided sizes for the duration of the call.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TOKEN_ELEVATION_CLASS,
            (&mut elevation as *mut TokenElevation).cast(),
            mem::size_of::<TokenElevation>() as Dword,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(elevation.token_is_elevated != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wintun_candidates_prefer_env_then_exe_dir_then_cwd() {
        let env_path = Some(PathBuf::from("/driver/wintun.dll"));
        let exe_path = Some(PathBuf::from("/opt/rustle/rustle.exe"));
        let cwd = PathBuf::from("/home/alice");

        assert_eq!(
            wintun_candidate_paths(env_path, exe_path, cwd),
            vec![
                PathBuf::from("/driver/wintun.dll"),
                PathBuf::from("/opt/rustle").join("wintun.dll"),
                PathBuf::from("/home/alice").join("wintun.dll")
            ]
        );
    }

    #[test]
    fn wintun_candidates_dedupe_matching_paths() {
        let exe_dir = PathBuf::from("/opt/rustle");
        let wintun = exe_dir.join("wintun.dll");

        assert_eq!(
            wintun_candidate_paths(
                Some(wintun.clone()),
                Some(exe_dir.join("rustle.exe")),
                exe_dir
            ),
            vec![wintun]
        );
    }

    #[cfg(windows)]
    #[test]
    fn wintun_candidates_dedupe_case_insensitive_windows_paths() {
        assert!(same_path(
            Path::new(r"C:\Rustle\wintun.dll"),
            Path::new(r"c:\rustle\WINTUN.DLL")
        ));
    }

    #[test]
    fn embedded_wintun_path_is_content_and_arch_addressed() {
        let first = embedded_wintun_path(PathBuf::from("/tmp"), b"first", "x86_64");
        let first_again = embedded_wintun_path(PathBuf::from("/tmp"), b"first", "x86_64");
        let second = embedded_wintun_path(PathBuf::from("/tmp"), b"second", "x86_64");
        let arm = embedded_wintun_path(PathBuf::from("/tmp"), b"first", "aarch64");

        assert_eq!(first, first_again);
        assert_ne!(first, second);
        assert_ne!(first, arm);
        assert_eq!(
            first.parent().map(Path::to_path_buf),
            Some(PathBuf::from("/tmp").join("rustle"))
        );
        let file_name = first
            .file_name()
            .and_then(|name| name.to_str())
            .expect("embedded Wintun filename is UTF-8");
        assert!(file_name.starts_with("wintun-x86_64-"));
        assert!(file_name.ends_with(".dll"));
        assert!(file_name.len() > "wintun-x86_64-.dll".len());
    }

    #[test]
    fn pe_machine_parser_reads_wintun_architectures() {
        assert_eq!(
            pe_machine_from_bytes(&fake_pe_dll(PE_MACHINE_AMD64)).unwrap(),
            PE_MACHINE_AMD64
        );
        assert_eq!(
            pe_machine_from_bytes(&fake_pe_dll(PE_MACHINE_ARM64)).unwrap(),
            PE_MACHINE_ARM64
        );
    }

    #[test]
    fn wintun_arch_validation_rejects_mismatched_dll() {
        let err =
            validate_wintun_arch_bytes(&fake_pe_dll(PE_MACHINE_ARM64), "x86_64", "test Wintun DLL")
                .expect_err("arm64 DLL must not validate for x86_64 target");
        assert!(err.to_string().contains("architecture mismatch"));
        assert!(err.to_string().contains("expected x86_64"));
        assert!(err.to_string().contains("found aarch64"));
    }

    #[test]
    fn wintun_arch_validation_rejects_non_pe_dll() {
        let err = validate_wintun_arch_bytes(b"not a dll", "x86_64", "test Wintun DLL")
            .expect_err("non-PE DLL must be rejected");
        assert!(err.to_string().contains("not a valid PE/COFF DLL"));
    }

    fn fake_pe_dll(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x80];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    #[test]
    fn command_path_lookup_finds_plain_command() {
        let dir = env::temp_dir().join(format!("rustle-command-path-{}-plain", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let command = dir.join("resolvectl");
        std::fs::write(&command, "").unwrap();

        assert!(command_exists_in_path(
            "resolvectl",
            Some(dir.clone().into_os_string()),
            false
        ));

        std::fs::remove_file(command).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn command_path_lookup_finds_windows_extension() {
        let dir = env::temp_dir().join(format!(
            "rustle-command-path-{}-windows",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let command = dir.join("netsh.exe");
        std::fs::write(&command, "").unwrap();

        assert!(command_exists_in_path(
            "netsh",
            Some(dir.clone().into_os_string()),
            true
        ));
        assert!(!command_exists_in_path(
            "netsh",
            Some(dir.clone().into_os_string()),
            false
        ));

        std::fs::remove_file(command).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn macos_network_services_parser_skips_disabled_and_header_lines() {
        let output = "\
An asterisk (*) denotes that a network service is disabled.
Wi-Fi
*Thunderbolt Bridge
USB 10/100/1000 LAN
";

        assert_eq!(
            parse_macos_network_services(output),
            vec!["Wi-Fi".to_owned(), "USB 10/100/1000 LAN".to_owned()]
        );
    }

    #[test]
    fn macos_dns_parser_treats_empty_message_as_no_servers() {
        assert!(parse_macos_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
        assert_eq!(
            parse_macos_dns_servers("1.1.1.1\n8.8.8.8\n"),
            vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()]
        );
    }

    #[test]
    fn macos_dns_restore_command_uses_empty_for_empty_previous_state() {
        assert_eq!(
            macos_restore_dns_command("Wi-Fi", &[]),
            CommandSpec::new("networksetup", ["-setdnsservers", "Wi-Fi", "Empty"])
        );
        assert_eq!(
            macos_restore_dns_command("Wi-Fi", &["1.1.1.1".to_owned(), "8.8.8.8".to_owned()]),
            CommandSpec::new(
                "networksetup",
                ["-setdnsservers", "Wi-Fi", "1.1.1.1", "8.8.8.8"]
            )
        );
    }

    #[test]
    fn linux_dns_commands_target_resolved_link() {
        assert_eq!(
            linux_set_dns_command("tun0", Ipv4Addr::new(10, 255, 255, 53)),
            CommandSpec::new("resolvectl", ["dns", "tun0", "10.255.255.53"])
        );
        assert_eq!(
            linux_set_route_domain_command("tun0"),
            CommandSpec::new("resolvectl", ["domain", "tun0", "~."])
        );
        assert_eq!(
            linux_restore_dns_command("tun0"),
            CommandSpec::new("resolvectl", ["revert", "tun0"])
        );
    }

    #[test]
    fn windows_dns_commands_target_named_interface() {
        assert_eq!(
            windows_set_dns_command("Rustle", Ipv4Addr::new(10, 255, 255, 53)),
            CommandSpec::new(
                "netsh",
                [
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    "name=Rustle",
                    "static",
                    "10.255.255.53",
                    "primary",
                ]
            )
        );
        assert_eq!(
            windows_restore_dns_command("Rustle"),
            CommandSpec::new(
                "netsh",
                [
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    "name=Rustle",
                    "source=dhcp",
                ]
            )
        );
    }
}
