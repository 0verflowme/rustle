use anyhow::{bail, Context, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SshTarget {
    pub(crate) user: String,
    pub(crate) addr: String,
    pub(crate) host: String,
    pub(crate) port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SshRemoteReference {
    pub(super) user: Option<String>,
    pub(super) host: String,
}

#[cfg(test)]
pub(crate) fn parse_ssh_target(remote: &str, user_override: Option<&str>) -> Result<SshTarget> {
    let reference = parse_ssh_remote_reference(remote)?;

    let user = user_override
        .or(reference.user.as_deref())
        .map(str::to_owned)
        .or_else(default_username)
        .ok_or_else(|| anyhow::anyhow!("missing SSH user; use -r user@host or --user"))?;

    let endpoint = parse_ssh_endpoint(&reference.host)?;

    Ok(SshTarget {
        user,
        addr: endpoint.addr,
        host: endpoint.host,
        port: endpoint.port,
    })
}

pub(super) fn parse_ssh_remote_reference(remote: &str) -> Result<SshRemoteReference> {
    let (user, host) = match remote.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() && !host.is_empty() => {
            (Some(user.to_owned()), host.to_owned())
        }
        Some(_) => bail!("invalid SSH remote {remote}; expected user@host"),
        None => (None, remote.to_owned()),
    };
    Ok(SshRemoteReference { user, host })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SshEndpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) addr: String,
}

pub(crate) fn parse_ssh_endpoint(input: &str) -> Result<SshEndpoint> {
    if input.is_empty() {
        bail!("missing SSH host");
    }

    let (host, port) = if let Some(rest) = input.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            bail!("invalid SSH remote host {input}; missing closing ]");
        };
        if host.is_empty() {
            bail!("invalid SSH remote host {input}; empty bracketed host");
        }
        let port = match suffix.strip_prefix(':') {
            Some(port) if !port.is_empty() => parse_port(port, input)?,
            Some(_) => bail!("invalid SSH remote host {input}; empty port"),
            None if suffix.is_empty() => 22,
            None => bail!("invalid SSH remote host {input}; expected [host]:port"),
        };
        (host.to_owned(), port)
    } else if let Some((host, port)) = input.rsplit_once(':') {
        if host.is_empty() || port.is_empty() {
            bail!("invalid SSH remote host {input}; expected host[:port]");
        }
        (host.to_owned(), parse_port(port, input)?)
    } else {
        (input.to_owned(), 22)
    };

    let addr = ssh_socket_addr_string(&host, port);

    Ok(SshEndpoint { host, port, addr })
}

pub(super) fn ssh_endpoint_port_is_explicit(input: &str) -> bool {
    if let Some(rest) = input.strip_prefix('[') {
        return rest
            .split_once(']')
            .is_some_and(|(_, suffix)| suffix.starts_with(':') && suffix.len() > 1);
    }
    input.rsplit_once(':').is_some()
}

pub(super) fn ssh_socket_addr_string(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn parse_port(port: &str, input: &str) -> Result<u16> {
    port.parse::<u16>()
        .with_context(|| format!("invalid SSH remote port in {input}"))
}

pub(super) fn default_username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("USERNAME")
                .ok()
                .filter(|value| !value.is_empty())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_endpoint_parses_host_and_port_for_known_hosts() {
        assert_eq!(
            parse_ssh_endpoint("example.com").unwrap(),
            SshEndpoint {
                host: "example.com".to_owned(),
                port: 22,
                addr: "example.com:22".to_owned(),
            }
        );
        assert_eq!(
            parse_ssh_endpoint("example.com:2222").unwrap(),
            SshEndpoint {
                host: "example.com".to_owned(),
                port: 2222,
                addr: "example.com:2222".to_owned(),
            }
        );
        assert_eq!(
            parse_ssh_endpoint("[2001:db8::1]:2222").unwrap(),
            SshEndpoint {
                host: "2001:db8::1".to_owned(),
                port: 2222,
                addr: "[2001:db8::1]:2222".to_owned(),
            }
        );
    }

    #[test]
    fn ssh_target_parses_user_at_host_like_sshuttle() {
        assert_eq!(
            parse_ssh_target("alice@example.com:2222", None).unwrap(),
            SshTarget {
                user: "alice".to_owned(),
                addr: "example.com:2222".to_owned(),
                host: "example.com".to_owned(),
                port: 2222,
            }
        );
    }

    #[test]
    fn ssh_target_user_flag_overrides_remote_user() {
        assert_eq!(
            parse_ssh_target("alice@example.com", Some("bob")).unwrap(),
            SshTarget {
                user: "bob".to_owned(),
                addr: "example.com:22".to_owned(),
                host: "example.com".to_owned(),
                port: 22,
            }
        );
    }
}
