use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::SshArgs;

use super::auth::resolve_ssh_password;
use super::target::{
    default_username, parse_ssh_endpoint, parse_ssh_remote_reference,
    ssh_endpoint_port_is_explicit, ssh_socket_addr_string, SshTarget,
};

pub(crate) const DEFAULT_SSH_CONNECT_TIMEOUT_SECS: u64 = 15;

#[derive(Clone, Debug)]
pub(crate) struct PreparedSshConnection {
    pub(crate) target: SshTarget,
    pub(crate) identity_files: Vec<PathBuf>,
    pub(crate) password: Option<String>,
    pub(crate) known_hosts: Option<PathBuf>,
    pub(crate) insecure_accept_host_key: bool,
    pub(crate) accept_new_host_key: bool,
    pub(crate) connect_timeout: Duration,
}

impl PreparedSshConnection {
    pub(crate) fn remote_host(&self) -> &str {
        &self.target.host
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SshConfigMatch {
    pub(crate) hostname: Option<String>,
    pub(crate) user: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) identity_files: Vec<String>,
    pub(crate) user_known_hosts_file: Option<String>,
}

pub(crate) fn prepare_ssh_connection(args: &SshArgs) -> Result<PreparedSshConnection> {
    let Some(remote) = args.ssh_server.as_deref() else {
        bail!("missing SSH remote; use -r user@host");
    };
    if args.insecure_accept_host_key && args.accept_new_host_key {
        bail!("--accept-new-host-key cannot be combined with --insecure-accept-host-key");
    }
    let (target, ssh_config) = resolve_ssh_target_and_config(args)?;
    let identity_files = match &args.identity {
        Some(identity) => vec![identity.clone()],
        None => ssh_config
            .identity_files
            .iter()
            .map(|path| expand_ssh_config_path(path, &target, remote))
            .collect::<Result<Vec<_>>>()?,
    };
    let known_hosts = match &args.known_hosts {
        Some(path) => Some(path.clone()),
        None => ssh_config
            .user_known_hosts_file
            .as_deref()
            .map(|path| expand_ssh_config_path(path, &target, remote))
            .transpose()?,
    };
    let password = resolve_ssh_password(args)?;

    Ok(PreparedSshConnection {
        target,
        identity_files,
        password,
        known_hosts,
        insecure_accept_host_key: args.insecure_accept_host_key,
        accept_new_host_key: args.accept_new_host_key,
        connect_timeout: ssh_connect_timeout(args.ssh_connect_timeout_secs)?,
    })
}

pub(crate) fn resolve_ssh_target(args: &SshArgs) -> Result<SshTarget> {
    let (target, _) = resolve_ssh_target_and_config(args)?;
    Ok(target)
}

pub(crate) fn resolve_ssh_target_and_config(args: &SshArgs) -> Result<(SshTarget, SshConfigMatch)> {
    let Some(remote) = args.ssh_server.as_deref() else {
        bail!("missing SSH remote; use -r user@host");
    };
    let reference = parse_ssh_remote_reference(remote)?;
    let endpoint = parse_ssh_endpoint(&reference.host)?;
    let config = resolve_ssh_config_for_host(&endpoint.host, args.ssh_config.as_deref())?;

    let user = args
        .ssh_user
        .as_deref()
        .or(reference.user.as_deref())
        .or(config.user.as_deref())
        .map(str::to_owned)
        .or_else(default_username)
        .ok_or_else(|| anyhow!("missing SSH user; use -r user@host, --user, or SSH config User"))?;
    let host = config
        .hostname
        .clone()
        .unwrap_or_else(|| endpoint.host.clone());
    let port = if ssh_endpoint_port_is_explicit(&reference.host) {
        endpoint.port
    } else {
        config.port.unwrap_or(endpoint.port)
    };
    let addr = ssh_socket_addr_string(&host, port);

    Ok((
        SshTarget {
            user,
            addr,
            host,
            port,
        },
        config,
    ))
}

fn resolve_ssh_config_for_host(host: &str, path: Option<&Path>) -> Result<SshConfigMatch> {
    let contents = match path {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read SSH config {}", path.display()))?,
        None => {
            let Some(path) = default_ssh_config_path() else {
                return Ok(SshConfigMatch::default());
            };
            match std::fs::read_to_string(&path) {
                Ok(contents) => contents,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(SshConfigMatch::default());
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("failed to read SSH config {}", path.display()));
                }
            }
        }
    };

    parse_ssh_config_for_host(&contents, host)
}

pub(crate) fn parse_ssh_config_for_host(contents: &str, host: &str) -> Result<SshConfigMatch> {
    let mut matched = SshConfigMatch::default();
    let mut active = true;

    for (line_index, line) in contents.lines().enumerate() {
        let fields = split_ssh_config_line(line);
        let Some((keyword, values)) = fields.split_first() else {
            continue;
        };
        let keyword = keyword.to_ascii_lowercase();
        match keyword.as_str() {
            "host" => {
                active = ssh_config_host_patterns_match(host, values);
                continue;
            }
            "match" => {
                active = false;
                continue;
            }
            _ => {}
        }
        if !active {
            continue;
        }
        let Some(value) = values.first() else {
            continue;
        };
        match keyword.as_str() {
            "hostname" if matched.hostname.is_none() => {
                matched.hostname = Some(value.clone());
            }
            "user" if matched.user.is_none() => {
                matched.user = Some(value.clone());
            }
            "port" if matched.port.is_none() => {
                matched.port = Some(value.parse::<u16>().with_context(|| {
                    format!("invalid Port in SSH config line {}", line_index + 1)
                })?);
            }
            "identityfile" => {
                matched.identity_files.push(value.clone());
            }
            "userknownhostsfile"
                if matched.user_known_hosts_file.is_none()
                    && !value.eq_ignore_ascii_case("none") =>
            {
                matched.user_known_hosts_file = Some(value.clone());
            }
            _ => {}
        }
    }

    Ok(matched)
}

fn split_ssh_config_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(quote_ch) = quote {
            if ch == quote_ch {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '#' => break,
            '\'' | '"' => quote = Some(ch),
            '=' if fields.is_empty() && !current.is_empty() => {
                fields.push(std::mem::take(&mut current));
            }
            ch if ch.is_whitespace() => {
                if !current.is_empty() {
                    fields.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        fields.push(current);
    }
    fields
}

fn ssh_config_host_patterns_match(host: &str, patterns: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    let mut matched = false;
    for pattern in patterns {
        if let Some(pattern) = pattern.strip_prefix('!') {
            if ssh_config_wildcard_match(&host, &pattern.to_ascii_lowercase()) {
                return false;
            }
        } else if ssh_config_wildcard_match(&host, &pattern.to_ascii_lowercase()) {
            matched = true;
        }
    }
    matched
}

fn ssh_config_wildcard_match(value: &str, pattern: &str) -> bool {
    let value = value.as_bytes();
    let pattern = pattern.as_bytes();
    let mut matched = vec![false; value.len() + 1];
    matched[0] = true;

    for &token in pattern {
        let mut next = vec![false; value.len() + 1];
        match token {
            b'*' => {
                let mut reachable = false;
                for index in 0..=value.len() {
                    reachable |= matched[index];
                    next[index] = reachable;
                }
            }
            b'?' => {
                next[1..(value.len() + 1)].copy_from_slice(&matched[..value.len()]);
            }
            literal => {
                for index in 0..value.len() {
                    next[index + 1] = matched[index] && value[index] == literal;
                }
            }
        }
        matched = next;
    }

    matched[value.len()]
}

fn default_ssh_config_path() -> Option<PathBuf> {
    home_dir().map(|home| home.join(".ssh").join("config"))
}

pub(crate) fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("USERPROFILE")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
}

fn expand_ssh_config_path(
    value: &str,
    target: &SshTarget,
    original_remote: &str,
) -> Result<PathBuf> {
    let original_host = parse_ssh_remote_reference(original_remote)
        .and_then(|reference| parse_ssh_endpoint(&reference.host).map(|endpoint| endpoint.host))
        .unwrap_or_else(|_| target.host.clone());
    let expanded = expand_ssh_config_tokens(value, target, &original_host)?;
    Ok(expand_tilde_path(&expanded))
}

fn expand_ssh_config_tokens(
    value: &str,
    target: &SshTarget,
    original_host: &str,
) -> Result<String> {
    let mut expanded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            expanded.push(ch);
            continue;
        }
        let token = chars
            .next()
            .context("SSH config token % must be followed by a character")?;
        match token {
            '%' => expanded.push('%'),
            'h' => expanded.push_str(&target.host),
            'n' => expanded.push_str(original_host),
            'p' => expanded.push_str(&target.port.to_string()),
            'r' => expanded.push_str(&target.user),
            'd' => {
                let home = home_dir().context("SSH config %d token requires a home directory")?;
                expanded.push_str(&home.display().to_string());
            }
            'u' => {
                let user = default_username().context("SSH config %u token requires a username")?;
                expanded.push_str(&user);
            }
            other => {
                expanded.push('%');
                expanded.push(other);
            }
        }
    }
    Ok(expanded)
}

fn expand_tilde_path(value: &str) -> PathBuf {
    if value == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from(value));
    }
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(value)
}

fn ssh_connect_timeout(seconds: u64) -> Result<Duration> {
    if seconds == 0 {
        bail!("--ssh-connect-timeout must be greater than zero");
    }
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;
    use std::time::Instant as StdInstant;

    use super::*;
    use crate::SshArgs;

    fn test_ssh_args(remote: &str) -> SshArgs {
        SshArgs {
            ssh_server: Some(remote.to_owned()),
            ssh_user: Some("alice".to_owned()),
            identity: None,
            password: None,
            password_file: None,
            insecure_accept_host_key: false,
            accept_new_host_key: false,
            known_hosts: None,
            ssh_config: None,
            ssh_connect_timeout_secs: DEFAULT_SSH_CONNECT_TIMEOUT_SECS,
        }
    }

    #[test]
    fn ssh_config_alias_resolves_target_user_port_and_paths() {
        let config_path = write_temp_ssh_config(
            "Host contabo\n\
             HostName 203.0.113.10\n\
             User deploy\n\
             Port 2202\n\
             IdentityFile ~/.ssh/%n-%r-%p\n\
             UserKnownHostsFile ~/.ssh/known_hosts_%h_%p\n",
        );
        let mut args = test_ssh_args("contabo");
        args.ssh_user = None;
        args.ssh_config = Some(config_path.clone());

        let prepared = prepare_ssh_connection(&args).expect("prepare SSH alias");

        assert_eq!(
            prepared.target,
            SshTarget {
                user: "deploy".to_owned(),
                addr: "203.0.113.10:2202".to_owned(),
                host: "203.0.113.10".to_owned(),
                port: 2202,
            }
        );
        let home = home_dir().expect("test requires home directory");
        assert_eq!(
            prepared.identity_files,
            vec![home.join(".ssh").join("contabo-deploy-2202")]
        );
        assert_eq!(
            prepared.known_hosts,
            Some(home.join(".ssh").join("known_hosts_203.0.113.10_2202"))
        );

        std::fs::remove_file(config_path).expect("remove temp SSH config");
    }

    #[test]
    fn ssh_config_alias_respects_cli_user_and_explicit_port_overrides() {
        let config_path = write_temp_ssh_config(
            "Host contabo\n\
             HostName 203.0.113.10\n\
             User deploy\n\
             Port 2202\n",
        );
        let mut args = test_ssh_args("contabo:2222");
        args.ssh_user = Some("root".to_owned());
        args.ssh_config = Some(config_path.clone());

        let target = resolve_ssh_target(&args).expect("resolve SSH alias with overrides");

        assert_eq!(
            target,
            SshTarget {
                user: "root".to_owned(),
                addr: "203.0.113.10:2222".to_owned(),
                host: "203.0.113.10".to_owned(),
                port: 2222,
            }
        );

        std::fs::remove_file(config_path).expect("remove temp SSH config");
    }

    #[test]
    fn ssh_config_host_patterns_support_wildcards_and_negation() {
        let config = "Host * !blocked\n\
                      User fallback\n\
                      Port 2200\n\
                      Host prod-*\n\
                      User deploy\n\
                      IdentityFile ~/.ssh/%h\n\
                      Host blocked\n\
                      HostName 192.0.2.9\n";

        assert_eq!(
            parse_ssh_config_for_host(config, "prod-api").expect("parse wildcard config"),
            SshConfigMatch {
                hostname: None,
                user: Some("fallback".to_owned()),
                port: Some(2200),
                identity_files: vec!["~/.ssh/%h".to_owned()],
                user_known_hosts_file: None,
            }
        );
        assert_eq!(
            parse_ssh_config_for_host(config, "blocked").expect("parse negated config"),
            SshConfigMatch {
                hostname: Some("192.0.2.9".to_owned()),
                user: None,
                port: None,
                identity_files: Vec::new(),
                user_known_hosts_file: None,
            }
        );
    }

    fn write_temp_ssh_config(contents: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "rustle-ssh-config-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        std::fs::write(&path, contents).expect("write temp SSH config");
        path
    }
}
