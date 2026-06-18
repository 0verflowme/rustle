use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::Ipv4Net;

use crate::ssh_control::resolve_ssh_target;
use crate::{tcp_core, SshArgs};

pub(crate) fn parse_target_cidr(input: &str) -> std::result::Result<Ipv4Net, String> {
    if let Ok(cidr) = input.parse::<Ipv4Net>() {
        return Ok(cidr);
    }

    let (addr, prefix) = input
        .split_once('/')
        .ok_or_else(|| format!("target CIDR must be IPv4/prefix, got {input}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| format!("target CIDR prefix must be 0..=32, got {input}"))?;
    if prefix > 32 {
        return Err(format!("target CIDR prefix must be <= 32, got {input}"));
    }

    let parts = parse_abbreviated_ipv4_octets(addr, input)?;
    let ip = Ipv4Addr::new(parts[0], parts[1], parts[2], parts[3]);
    Ipv4Net::new(ip, prefix).map_err(|err| format!("invalid target CIDR {input}: {err}"))
}

pub(crate) fn parse_abbreviated_ipv4_octets(
    addr: &str,
    original: &str,
) -> std::result::Result<[u8; 4], String> {
    let raw_parts = addr.split('.').collect::<Vec<_>>();
    if raw_parts.is_empty() || raw_parts.len() > 4 {
        return Err(format!(
            "invalid abbreviated IPv4 address in target CIDR {original}"
        ));
    }

    let mut octets = [0_u8; 4];
    for (index, part) in raw_parts.iter().enumerate() {
        if part.is_empty() {
            return Err(format!(
                "invalid abbreviated IPv4 address in target CIDR {original}"
            ));
        }
        octets[index] = part
            .parse::<u8>()
            .map_err(|_| format!("invalid IPv4 octet {part:?} in target CIDR {original}"))?;
    }
    Ok(octets)
}

pub(crate) fn expand_target_routes(targets: &[Ipv4Net]) -> Result<Vec<Ipv4Net>> {
    if targets.is_empty() {
        bail!("at least one target CIDR is required");
    }
    let mut expanded = Vec::with_capacity(targets.len().saturating_add(1));
    for target in targets {
        if target.prefix_len() == 0 {
            expanded.push("0.0.0.0/1".parse().expect("valid split default route"));
            expanded.push("128.0.0.0/1".parse().expect("valid split default route"));
        } else if !expanded.contains(target) {
            expanded.push(*target);
        }
    }

    if expanded.len() > smoltcp::config::IFACE_MAX_ROUTE_COUNT {
        bail!(
            "too many target CIDRs: {} requested, maximum is {}",
            expanded.len(),
            smoltcp::config::IFACE_MAX_ROUTE_COUNT
        );
    }
    Ok(expanded)
}

pub(crate) fn ssh_control_ip_to_protect(
    ssh: &SshArgs,
    targets: &[Ipv4Net],
) -> Result<Option<Ipv4Addr>> {
    let ssh_addr = resolve_ssh_target(ssh)?.addr;
    let addrs = ssh_addr
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve SSH server address {ssh_addr}"))?;

    for addr in addrs {
        if let IpAddr::V4(ip) = addr.ip() {
            for target in targets {
                if target.contains(&ip) {
                    return Ok(Some(ip));
                }
            }
        }
    }

    Ok(None)
}

pub(crate) fn target_route_parts(targets: &[Ipv4Net]) -> Vec<tcp_core::Ipv4NetParts> {
    targets
        .iter()
        .map(|target| tcp_core::Ipv4NetParts::new(target.network(), target.prefix_len()))
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExistingRoute {
    pub(crate) gateway: Option<Ipv4Addr>,
    pub(crate) if_name: Option<String>,
    pub(crate) if_index: Option<u32>,
}

pub(crate) trait ControlRouteCommandExecutor {
    fn lookup_route_to(&self, target: Ipv4Addr) -> Result<ExistingRoute>;
    fn run_control_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Addr,
        route: &ExistingRoute,
    ) -> Result<()>;
}

#[derive(Clone, Copy)]
pub(crate) struct SystemControlRouteCommandExecutor;

impl ControlRouteCommandExecutor for SystemControlRouteCommandExecutor {
    fn lookup_route_to(&self, target: Ipv4Addr) -> Result<ExistingRoute> {
        lookup_existing_route_to(target)
    }

    fn run_control_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Addr,
        route: &ExistingRoute,
    ) -> Result<()> {
        run_control_route_command(action, target, route)
    }
}

pub(crate) struct ControlRouteGuard<
    E: ControlRouteCommandExecutor = SystemControlRouteCommandExecutor,
> {
    target: Ipv4Addr,
    route: ExistingRoute,
    executor: E,
}

impl<E: ControlRouteCommandExecutor> ControlRouteGuard<E> {
    fn add(target: Ipv4Addr, route: ExistingRoute, executor: E) -> Result<Self> {
        executor.run_control_route_command(RouteAction::Add, target, &route)?;
        Ok(Self {
            target,
            route,
            executor,
        })
    }
}

impl<E: ControlRouteCommandExecutor> Drop for ControlRouteGuard<E> {
    fn drop(&mut self) {
        if let Err(err) =
            self.executor
                .run_control_route_command(RouteAction::Delete, self.target, &self.route)
        {
            eprintln!(
                "route: failed to delete SSH control host route {}: {err:#}",
                self.target
            );
        } else {
            eprintln!("route: deleted SSH control host route {}", self.target);
        }
    }
}

pub(crate) fn add_ssh_control_route(target: Ipv4Addr) -> Result<Option<ControlRouteGuard>> {
    add_ssh_control_route_with(target, SystemControlRouteCommandExecutor)
}

pub(crate) fn add_ssh_control_route_with<E: ControlRouteCommandExecutor + Clone>(
    target: Ipv4Addr,
    executor: E,
) -> Result<Option<ControlRouteGuard<E>>> {
    let route = executor
        .lookup_route_to(target)
        .with_context(|| format!("failed to inspect existing route to SSH server {target}"))?;
    if !route_requires_control_host_route(&route) {
        eprintln!(
            "route: existing route to SSH control connection {target} is already direct via {route:?}"
        );
        return Ok(None);
    }
    let guard = ControlRouteGuard::add(target, route.clone(), executor)
        .with_context(|| format!("failed to add SSH control host route for {target}"))?;
    eprintln!("route: protected SSH control connection to {target} via {route:?}");
    Ok(Some(guard))
}

pub(crate) fn route_requires_control_host_route(route: &ExistingRoute) -> bool {
    route
        .gateway
        .is_some_and(|gateway| !gateway.is_unspecified())
}

pub(crate) trait RouteCommandExecutor {
    fn run_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Net,
        if_name: &str,
        if_index: u32,
        gateway: Ipv4Addr,
    ) -> Result<()>;
}

#[derive(Clone, Copy)]
pub(crate) struct SystemRouteCommandExecutor;

impl RouteCommandExecutor for SystemRouteCommandExecutor {
    fn run_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Net,
        if_name: &str,
        if_index: u32,
        gateway: Ipv4Addr,
    ) -> Result<()> {
        run_route_command(action, target, if_name, if_index, gateway)
    }
}

pub(crate) struct RouteGuard<E: RouteCommandExecutor = SystemRouteCommandExecutor> {
    target: Ipv4Net,
    if_name: String,
    if_index: u32,
    gateway: Ipv4Addr,
    executor: E,
}

impl<E: RouteCommandExecutor> RouteGuard<E> {
    fn add(
        target: Ipv4Net,
        if_name: &str,
        if_index: u32,
        gateway: Ipv4Addr,
        executor: E,
    ) -> Result<Self> {
        executor.run_route_command(RouteAction::Add, target, if_name, if_index, gateway)?;
        Ok(Self {
            target,
            if_name: if_name.to_owned(),
            if_index,
            gateway,
            executor,
        })
    }
}

pub(crate) fn add_target_routes(
    targets: &[Ipv4Net],
    if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
) -> Result<Vec<RouteGuard>> {
    add_target_routes_with(
        targets,
        if_name,
        if_index,
        gateway,
        SystemRouteCommandExecutor,
    )
}

pub(crate) fn add_target_routes_with<E: RouteCommandExecutor + Clone>(
    targets: &[Ipv4Net],
    if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
    executor: E,
) -> Result<Vec<RouteGuard<E>>> {
    let mut routes = Vec::with_capacity(targets.len());
    for target in targets {
        let route = RouteGuard::add(*target, if_name, if_index, gateway, executor.clone())
            .with_context(|| format!("failed to add target route {target}"))?;
        eprintln!("route: added {target} via {if_name}");
        routes.push(route);
    }
    Ok(routes)
}

impl<E: RouteCommandExecutor> Drop for RouteGuard<E> {
    fn drop(&mut self) {
        if let Err(err) = self.executor.run_route_command(
            RouteAction::Delete,
            self.target,
            &self.if_name,
            self.if_index,
            self.gateway,
        ) {
            eprintln!("route: failed to delete {}: {err:#}", self.target);
        } else {
            eprintln!("route: deleted {}", self.target);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteAction {
    Add,
    Delete,
}

pub(crate) fn run_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
) -> Result<()> {
    let (program, args) = route_command(action, target, if_name, if_index, gateway)?;
    let output = Command::new(&program)
        .args(&args)
        .output()
        .with_context(|| format!("failed to execute route command {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "route command failed: {} {}\nstdout: {}\nstderr: {}",
            program,
            args.join(" "),
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(())
}

pub(crate) fn run_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<()> {
    let (program, args) = control_route_command(action, target, route)?;
    let output = Command::new(&program)
        .args(&args)
        .output()
        .with_context(|| format!("failed to execute control route command {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "control route command failed: {} {}\nstdout: {}\nstderr: {}",
            program,
            args.join(" "),
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn lookup_existing_route_to(target: Ipv4Addr) -> Result<ExistingRoute> {
    let output = Command::new("route")
        .args(["-n", "get", &target.to_string()])
        .output()
        .context("failed to execute route -n get")?;
    if !output.status.success() {
        bail!(
            "route -n get {} failed: {}",
            target,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_macos_route_get(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "linux")]
pub(crate) fn lookup_existing_route_to(target: Ipv4Addr) -> Result<ExistingRoute> {
    let output = Command::new("ip")
        .args(["-4", "route", "get", &target.to_string()])
        .output()
        .context("failed to execute ip route get")?;
    if !output.status.success() {
        bail!(
            "ip route get {} failed: {}",
            target,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_linux_route_get(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "windows")]
pub(crate) fn lookup_existing_route_to(target: Ipv4Addr) -> Result<ExistingRoute> {
    let script = format!(
        "$r = Find-NetRoute -RemoteIPAddress '{}' | Select-Object -First 1; if ($null -eq $r) {{ exit 1 }}; '{{0}} {{1}}' -f $r.InterfaceIndex, $r.NextHop",
        target
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .context("failed to execute Find-NetRoute")?;
    if !output.status.success() {
        bail!(
            "Find-NetRoute {} failed: {}",
            target,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_windows_find_net_route(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn lookup_existing_route_to(_target: Ipv4Addr) -> Result<ExistingRoute> {
    bail!(
        "SSH control route protection is not implemented for {}",
        std::env::consts::OS
    );
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn parse_macos_route_get(output: &str) -> Result<ExistingRoute> {
    let mut gateway = None;
    let mut if_name = None;

    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "gateway" => {
                gateway = value.trim().parse::<Ipv4Addr>().ok();
            }
            "interface" => {
                let value = value.trim();
                if !value.is_empty() {
                    if_name = Some(value.to_owned());
                }
            }
            _ => {}
        }
    }

    if gateway.is_none() && if_name.is_none() {
        bail!("route output did not include a gateway or interface");
    }
    Ok(ExistingRoute {
        gateway,
        if_name,
        if_index: None,
    })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_linux_route_get(output: &str) -> Result<ExistingRoute> {
    let mut gateway = None;
    let mut if_name = None;
    let tokens: Vec<_> = output.split_whitespace().collect();
    for pair in tokens.windows(2) {
        match pair[0] {
            "via" => gateway = pair[1].parse::<Ipv4Addr>().ok(),
            "dev" => if_name = Some(pair[1].to_owned()),
            _ => {}
        }
    }

    let Some(if_name) = if_name else {
        bail!("ip route output did not include a dev field");
    };
    Ok(ExistingRoute {
        gateway,
        if_name: Some(if_name),
        if_index: None,
    })
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn parse_windows_find_net_route(output: &str) -> Result<ExistingRoute> {
    let mut fields = output.split_whitespace();
    let if_index = fields
        .next()
        .ok_or_else(|| anyhow!("Find-NetRoute output did not include InterfaceIndex"))?
        .parse::<u32>()
        .context("failed to parse Find-NetRoute InterfaceIndex")?;
    let gateway = fields
        .next()
        .ok_or_else(|| anyhow!("Find-NetRoute output did not include NextHop"))?
        .parse::<Ipv4Addr>()
        .context("failed to parse Find-NetRoute NextHop")?;

    Ok(ExistingRoute {
        gateway: Some(gateway),
        if_name: None,
        if_index: Some(if_index),
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
    _if_index: u32,
    _gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    Ok(linux_route_command(action, target, if_name))
}

#[cfg(target_os = "linux")]
pub(crate) fn control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    linux_control_route_command(action, target, route)
}

#[cfg(target_os = "macos")]
pub(crate) fn route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
    _if_index: u32,
    _gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    Ok(macos_route_command(action, target, if_name))
}

#[cfg(target_os = "macos")]
pub(crate) fn control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    macos_control_route_command(action, target, route)
}

#[cfg(target_os = "windows")]
pub(crate) fn route_command(
    action: RouteAction,
    target: Ipv4Net,
    _if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    Ok(windows_route_command(action, target, if_index, gateway))
}

#[cfg(target_os = "windows")]
pub(crate) fn control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    windows_control_route_command(action, target, route)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
) -> (String, Vec<String>) {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "del",
    };
    (
        "ip".to_owned(),
        vec![
            "route".to_owned(),
            verb.to_owned(),
            target.to_string(),
            "dev".to_owned(),
            if_name.to_owned(),
        ],
    )
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "del",
    };
    let mut args = vec!["route".to_owned(), verb.to_owned(), format!("{target}/32")];
    if matches!(action, RouteAction::Add) {
        if let Some(gateway) = route.gateway.filter(|gateway| !gateway.is_unspecified()) {
            args.extend(["via".to_owned(), gateway.to_string()]);
        }
        let if_name = route
            .if_name
            .as_deref()
            .ok_or_else(|| anyhow!("Linux control route requires an interface name"))?;
        args.extend(["dev".to_owned(), if_name.to_owned()]);
    }

    Ok(("ip".to_owned(), args))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn macos_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
) -> (String, Vec<String>) {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "delete",
    };

    let mut args = if target.prefix_len() == 32 {
        vec![
            verb.to_owned(),
            "-host".to_owned(),
            target.addr().to_string(),
        ]
    } else {
        vec![
            verb.to_owned(),
            "-net".to_owned(),
            target.network().to_string(),
            "-netmask".to_owned(),
            prefix_to_mask(target.prefix_len()).to_string(),
        ]
    };

    if matches!(action, RouteAction::Add) {
        args.extend(["-interface".to_owned(), if_name.to_owned()]);
    }

    ("route".to_owned(), args)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn macos_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "delete",
    };
    let mut args = vec![verb.to_owned(), "-host".to_owned(), target.to_string()];

    if matches!(action, RouteAction::Add) {
        if let Some(gateway) = route.gateway {
            args.push(gateway.to_string());
        } else {
            let if_name = route
                .if_name
                .as_deref()
                .ok_or_else(|| anyhow!("macOS control route requires a gateway or interface"))?;
            args.extend(["-interface".to_owned(), if_name.to_owned()]);
        }
    }

    Ok(("route".to_owned(), args))
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn windows_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_index: u32,
    gateway: Ipv4Addr,
) -> (String, Vec<String>) {
    let verb = match action {
        RouteAction::Add => "ADD",
        RouteAction::Delete => "DELETE",
    };
    let mut args = vec![
        verb.to_owned(),
        target.network().to_string(),
        "MASK".to_owned(),
        prefix_to_mask(target.prefix_len()).to_string(),
        gateway.to_string(),
    ];
    if matches!(action, RouteAction::Add) {
        args.extend([
            "METRIC".to_owned(),
            "1".to_owned(),
            "IF".to_owned(),
            if_index.to_string(),
        ]);
    }

    ("route".to_owned(), args)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn windows_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    let if_index = route
        .if_index
        .ok_or_else(|| anyhow!("Windows control route requires an interface index"))?;
    let gateway = route
        .gateway
        .ok_or_else(|| anyhow!("Windows control route requires a next hop"))?;
    Ok(windows_route_command(
        action,
        Ipv4Net::new(target, 32).expect("host route prefix is valid"),
        if_index,
        gateway,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn route_command(
    _action: RouteAction,
    _target: Ipv4Net,
    _if_name: &str,
    _if_index: u32,
    _gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    bail!("route management is not implemented for this operating system")
}

pub(crate) fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ipv4Addr::from(bits)
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn prefix_to_mask_has_exact_contiguous_prefix_bits() {
        let prefix: u8 = kani::any();
        kani::assume(prefix <= 32);

        let mask = u32::from(prefix_to_mask(prefix));
        assert_eq!(mask.count_ones(), u32::from(prefix));
        assert_eq!(mask.leading_ones(), u32::from(prefix));
        assert_eq!(mask.trailing_zeros(), 32 - u32::from(prefix));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn test_ssh_args(remote: &str) -> SshArgs {
        SshArgs {
            ssh_server: Some(remote.to_owned()),
            ssh_user: None,
            identity: None,
            password: None,
            password_file: None,
            insecure_accept_host_key: true,
            accept_new_host_key: false,
            known_hosts: None,
            ssh_config: None,
            ssh_connect_timeout_secs: crate::ssh_control::DEFAULT_SSH_CONNECT_TIMEOUT_SECS,
        }
    }

    #[test]
    fn prefix_masks_are_big_endian_ipv4_masks() {
        assert_eq!(prefix_to_mask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix_to_mask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn macos_route_delete_omits_interface_operand() {
        let target = "192.168.0.0/16".parse().unwrap();

        let (_, add_args) = macos_route_command(RouteAction::Add, target, "utun7");
        assert_eq!(
            add_args,
            vec![
                "add",
                "-net",
                "192.168.0.0",
                "-netmask",
                "255.255.0.0",
                "-interface",
                "utun7"
            ]
        );

        let (_, delete_args) = macos_route_command(RouteAction::Delete, target, "utun7");
        assert_eq!(
            delete_args,
            vec!["delete", "-net", "192.168.0.0", "-netmask", "255.255.0.0"]
        );
    }

    #[test]
    fn linux_route_commands_use_ip_route_dev_form() {
        let target = "192.168.0.0/16".parse().unwrap();

        assert_eq!(
            linux_route_command(RouteAction::Add, target, "tun0"),
            (
                "ip".to_owned(),
                vec!["route", "add", "192.168.0.0/16", "dev", "tun0"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            )
        );
        assert_eq!(
            linux_route_command(RouteAction::Delete, target, "tun0"),
            (
                "ip".to_owned(),
                vec!["route", "del", "192.168.0.0/16", "dev", "tun0"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            )
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_platform_route_dispatch_uses_linux_builders() {
        let target = "192.168.0.0/16".parse().unwrap();
        let control_target = Ipv4Addr::new(203, 0, 113, 10);
        let route = ExistingRoute {
            gateway: Some(Ipv4Addr::new(192, 168, 1, 254)),
            if_name: Some("eth0".to_owned()),
            if_index: Some(42),
        };

        assert_eq!(
            route_command(
                RouteAction::Add,
                target,
                "tun0",
                42,
                Ipv4Addr::new(10, 255, 255, 1)
            )
            .unwrap(),
            linux_route_command(RouteAction::Add, target, "tun0"),
        );
        assert_eq!(
            control_route_command(RouteAction::Add, control_target, &route).unwrap(),
            linux_control_route_command(RouteAction::Add, control_target, &route).unwrap(),
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_platform_route_dispatch_uses_macos_builders() {
        let target = "192.168.0.0/16".parse().unwrap();
        let control_target = Ipv4Addr::new(203, 0, 113, 10);
        let route = ExistingRoute {
            gateway: Some(Ipv4Addr::new(192, 168, 1, 254)),
            if_name: Some("en0".to_owned()),
            if_index: Some(42),
        };

        assert_eq!(
            route_command(
                RouteAction::Add,
                target,
                "utun7",
                42,
                Ipv4Addr::new(10, 255, 255, 1)
            )
            .unwrap(),
            macos_route_command(RouteAction::Add, target, "utun7"),
        );
        assert_eq!(
            control_route_command(RouteAction::Add, control_target, &route).unwrap(),
            macos_control_route_command(RouteAction::Add, control_target, &route).unwrap(),
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_platform_route_dispatch_uses_windows_builders() {
        let target = "192.168.0.0/16".parse().unwrap();
        let control_target = Ipv4Addr::new(203, 0, 113, 10);
        let gateway = Ipv4Addr::new(10, 255, 255, 1);
        let route = ExistingRoute {
            gateway: Some(gateway),
            if_name: Some("Ethernet".to_owned()),
            if_index: Some(42),
        };

        assert_eq!(
            route_command(RouteAction::Add, target, "ignored", 42, gateway).unwrap(),
            windows_route_command(RouteAction::Add, target, 42, gateway),
        );
        assert_eq!(
            control_route_command(RouteAction::Add, control_target, &route).unwrap(),
            windows_control_route_command(RouteAction::Add, control_target, &route).unwrap(),
        );
    }

    #[test]
    fn windows_route_commands_use_interface_index_on_add() {
        let target = "192.168.0.0/16".parse().unwrap();
        let gateway = Ipv4Addr::new(10, 255, 255, 1);

        assert_eq!(
            windows_route_command(RouteAction::Add, target, 42, gateway),
            (
                "route".to_owned(),
                vec![
                    "ADD",
                    "192.168.0.0",
                    "MASK",
                    "255.255.0.0",
                    "10.255.255.1",
                    "METRIC",
                    "1",
                    "IF",
                    "42"
                ]
                .into_iter()
                .map(str::to_owned)
                .collect()
            )
        );
        assert_eq!(
            windows_route_command(RouteAction::Delete, target, 42, gateway),
            (
                "route".to_owned(),
                vec![
                    "DELETE",
                    "192.168.0.0",
                    "MASK",
                    "255.255.0.0",
                    "10.255.255.1"
                ]
                .into_iter()
                .map(str::to_owned)
                .collect()
            )
        );
    }

    #[test]
    fn windows_full_tunnel_routes_use_split_default_commands() {
        let routes = expand_target_routes(&[parse_target_cidr("0.0.0.0/0").unwrap()])
            .expect("full tunnel route expands");
        let gateway = Ipv4Addr::new(10, 255, 255, 1);

        assert_eq!(
            routes,
            vec![
                "0.0.0.0/1".parse::<Ipv4Net>().unwrap(),
                "128.0.0.0/1".parse::<Ipv4Net>().unwrap(),
            ]
        );
        assert_eq!(
            windows_route_command(RouteAction::Add, routes[0], 42, gateway),
            (
                "route".to_owned(),
                vec![
                    "ADD",
                    "0.0.0.0",
                    "MASK",
                    "128.0.0.0",
                    "10.255.255.1",
                    "METRIC",
                    "1",
                    "IF",
                    "42",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            )
        );
        assert_eq!(
            windows_route_command(RouteAction::Add, routes[1], 42, gateway),
            (
                "route".to_owned(),
                vec![
                    "ADD",
                    "128.0.0.0",
                    "MASK",
                    "128.0.0.0",
                    "10.255.255.1",
                    "METRIC",
                    "1",
                    "IF",
                    "42",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            )
        );
        assert_eq!(
            windows_route_command(RouteAction::Delete, routes[0], 42, gateway),
            (
                "route".to_owned(),
                vec!["DELETE", "0.0.0.0", "MASK", "128.0.0.0", "10.255.255.1"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            )
        );
        assert_eq!(
            windows_route_command(RouteAction::Delete, routes[1], 42, gateway),
            (
                "route".to_owned(),
                vec!["DELETE", "128.0.0.0", "MASK", "128.0.0.0", "10.255.255.1"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            )
        );
    }

    #[test]
    fn control_route_commands_protect_ssh_host_via_existing_route() {
        let target = Ipv4Addr::new(203, 0, 113, 10);
        let route = ExistingRoute {
            gateway: Some(Ipv4Addr::new(192, 168, 1, 254)),
            if_name: Some("en0".to_owned()),
            if_index: Some(42),
        };

        assert_eq!(
            macos_control_route_command(RouteAction::Add, target, &route).unwrap(),
            (
                "route".to_owned(),
                vec!["add", "-host", "203.0.113.10", "192.168.1.254"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            )
        );
        assert_eq!(
            macos_control_route_command(RouteAction::Delete, target, &route).unwrap(),
            (
                "route".to_owned(),
                vec!["delete", "-host", "203.0.113.10"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            )
        );
        assert_eq!(
            linux_control_route_command(RouteAction::Add, target, &route).unwrap(),
            (
                "ip".to_owned(),
                vec![
                    "route",
                    "add",
                    "203.0.113.10/32",
                    "via",
                    "192.168.1.254",
                    "dev",
                    "en0"
                ]
                .into_iter()
                .map(str::to_owned)
                .collect()
            )
        );
        assert_eq!(
            linux_control_route_command(RouteAction::Delete, target, &route).unwrap(),
            (
                "ip".to_owned(),
                vec!["route", "del", "203.0.113.10/32"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            )
        );
        assert_eq!(
            windows_control_route_command(RouteAction::Add, target, &route).unwrap(),
            (
                "route".to_owned(),
                vec![
                    "ADD",
                    "203.0.113.10",
                    "MASK",
                    "255.255.255.255",
                    "192.168.1.254",
                    "METRIC",
                    "1",
                    "IF",
                    "42"
                ]
                .into_iter()
                .map(str::to_owned)
                .collect()
            )
        );
    }

    #[test]
    fn route_setup_rolls_back_added_routes_when_later_add_fails() {
        #[derive(Clone)]
        struct RecordingRouteExecutor {
            calls: Arc<Mutex<Vec<(RouteAction, Ipv4Net)>>>,
            fail_add: Ipv4Net,
        }

        impl RouteCommandExecutor for RecordingRouteExecutor {
            fn run_route_command(
                &self,
                action: RouteAction,
                target: Ipv4Net,
                _if_name: &str,
                _if_index: u32,
                _gateway: Ipv4Addr,
            ) -> Result<()> {
                self.calls.lock().unwrap().push((action, target));
                if action == RouteAction::Add && target == self.fail_add {
                    bail!("injected route add failure");
                }
                Ok(())
            }
        }

        let first = "192.168.0.0/24".parse().unwrap();
        let second = "192.168.1.0/24".parse().unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let executor = RecordingRouteExecutor {
            calls: calls.clone(),
            fail_add: second,
        };

        let result = add_target_routes_with(
            &[first, second],
            "tun-test",
            7,
            Ipv4Addr::new(10, 255, 255, 1),
            executor,
        );
        let err = match result {
            Ok(_) => panic!("second route add must fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("failed to add target route"));
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                (RouteAction::Add, first),
                (RouteAction::Add, second),
                (RouteAction::Delete, first),
            ]
        );
    }

    #[test]
    fn control_route_setup_deletes_added_host_route_on_drop() {
        #[derive(Clone)]
        struct RecordingControlRouteExecutor {
            calls: Arc<Mutex<Vec<(RouteAction, Ipv4Addr)>>>,
            route: ExistingRoute,
        }

        impl ControlRouteCommandExecutor for RecordingControlRouteExecutor {
            fn lookup_route_to(&self, _target: Ipv4Addr) -> Result<ExistingRoute> {
                Ok(self.route.clone())
            }

            fn run_control_route_command(
                &self,
                action: RouteAction,
                target: Ipv4Addr,
                _route: &ExistingRoute,
            ) -> Result<()> {
                self.calls.lock().unwrap().push((action, target));
                Ok(())
            }
        }

        let target = Ipv4Addr::new(203, 0, 113, 10);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let executor = RecordingControlRouteExecutor {
            calls: calls.clone(),
            route: ExistingRoute {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                if_name: Some("en0".to_owned()),
                if_index: Some(7),
            },
        };

        let guard = add_ssh_control_route_with(target, executor)
            .expect("control route guard")
            .expect("gateway route should require a guard");
        assert_eq!(*calls.lock().unwrap(), vec![(RouteAction::Add, target)]);
        drop(guard);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(RouteAction::Add, target), (RouteAction::Delete, target)]
        );
    }

    #[test]
    fn control_route_setup_skips_direct_existing_routes() {
        #[derive(Clone)]
        struct DirectControlRouteExecutor {
            calls: Arc<Mutex<Vec<(RouteAction, Ipv4Addr)>>>,
        }

        impl ControlRouteCommandExecutor for DirectControlRouteExecutor {
            fn lookup_route_to(&self, _target: Ipv4Addr) -> Result<ExistingRoute> {
                Ok(ExistingRoute {
                    gateway: None,
                    if_name: Some("en0".to_owned()),
                    if_index: Some(7),
                })
            }

            fn run_control_route_command(
                &self,
                action: RouteAction,
                target: Ipv4Addr,
                _route: &ExistingRoute,
            ) -> Result<()> {
                self.calls.lock().unwrap().push((action, target));
                Ok(())
            }
        }

        let target = Ipv4Addr::new(192, 168, 1, 47);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let guard = add_ssh_control_route_with(
            target,
            DirectControlRouteExecutor {
                calls: calls.clone(),
            },
        )
        .expect("direct control route lookup should succeed");

        assert!(guard.is_none());
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn target_cidr_parser_accepts_sshuttle_abbreviations() {
        let full = parse_target_cidr("0/0").expect("parse full-tunnel shorthand");
        assert_eq!(full.network(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(full.prefix_len(), 0);

        let host = parse_target_cidr("10.1.2.3/32").expect("parse host route");
        assert_eq!(host.network(), Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(host.prefix_len(), 32);

        let abbreviated_host = parse_target_cidr("10/32").expect("parse abbreviated host route");
        assert_eq!(abbreviated_host.network(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(abbreviated_host.prefix_len(), 32);

        let private = parse_target_cidr("10/8").expect("parse class-A shorthand");
        assert_eq!(private.network(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(private.prefix_len(), 8);

        let partial = parse_target_cidr("172.16/12").expect("parse partial IPv4 shorthand");
        assert_eq!(partial.network(), Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(partial.prefix_len(), 12);

        let canonical = parse_target_cidr("192.168.1.0/24").expect("parse canonical CIDR");
        assert_eq!(canonical.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(canonical.prefix_len(), 24);
    }

    #[test]
    fn target_cidr_parser_rejects_invalid_abbreviations() {
        for input in ["10/33", "300/8", "10..0/8", "10/-1", "example/8"] {
            assert!(
                parse_target_cidr(input).is_err(),
                "{input} should be rejected"
            );
        }
    }

    #[test]
    fn full_tunnel_expands_to_split_default_routes() {
        assert_eq!(
            expand_target_routes(&[parse_target_cidr("0/0").unwrap()]).unwrap(),
            vec![
                "0.0.0.0/1".parse::<Ipv4Net>().unwrap(),
                "128.0.0.0/1".parse::<Ipv4Net>().unwrap()
            ]
        );
    }

    #[test]
    fn target_route_expansion_deduplicates_non_default_routes() {
        let private = parse_target_cidr("10/8").unwrap();
        assert_eq!(
            expand_target_routes(&[private, private]).unwrap(),
            vec![private]
        );
    }

    #[test]
    fn ssh_control_ip_to_protect_detects_captured_server() {
        let targets = expand_target_routes(&["0.0.0.0/0".parse().unwrap()]).unwrap();
        let ssh = test_ssh_args("127.0.0.1:22");
        assert_eq!(
            ssh_control_ip_to_protect(&ssh, &targets).unwrap(),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    fn route_get_parsers_extract_existing_routes() {
        assert_eq!(
            parse_macos_route_get(
                "   route to: 1.1.1.1\n\
                 destination: default\n\
                    gateway: 192.168.1.254\n\
                  interface: en0\n"
            )
            .unwrap(),
            ExistingRoute {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 254)),
                if_name: Some("en0".to_owned()),
                if_index: None,
            }
        );
        assert_eq!(
            parse_macos_route_get(
                "   route to: 1.1.1.1\n\
                 destination: 1.1.1.1\n\
                  interface: utun7\n"
            )
            .unwrap(),
            ExistingRoute {
                gateway: None,
                if_name: Some("utun7".to_owned()),
                if_index: None,
            }
        );
        assert_eq!(
            parse_linux_route_get("1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.10\n").unwrap(),
            ExistingRoute {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                if_name: Some("eth0".to_owned()),
                if_index: None,
            }
        );
        assert_eq!(
            parse_windows_find_net_route("42 192.168.1.1\n").unwrap(),
            ExistingRoute {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                if_name: None,
                if_index: Some(42),
            }
        );
    }
}
