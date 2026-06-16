use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ring::hmac;
use russh::client::{self, AuthResult, Config, Handle, Handler};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use ssh_key::known_hosts::{HostPatterns, KnownHosts, Marker};
use tokio::sync::Mutex;

use crate::{ssh_bridge, tcp_core, SshArgs};

pub(crate) const MAX_SSH_SESSIONS: usize = 16;
pub(crate) const AUTO_AGENT_SESSIONS: usize = 0;
pub(crate) const MAX_AUTO_AGENT_SESSIONS: usize = 4;
pub(crate) const DEFAULT_SSH_CONNECT_TIMEOUT_SECS: u64 = 15;
const SSH_PASSWORD_FILE_ENV: &str = "RUSTLE_SSH_PASSWORD_FILE";

#[derive(Clone)]
pub(crate) struct SshSessionPool {
    slots: Arc<Vec<Arc<SshSessionSlot>>>,
    next_background: Arc<AtomicUsize>,
}

impl SshSessionPool {
    fn new(slots: Vec<Arc<SshSessionSlot>>) -> Result<Self> {
        if slots.is_empty() {
            bail!("SSH session pool must contain at least one session");
        }
        Ok(Self {
            slots: Arc::new(slots),
            next_background: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    fn slot_for_flow(&self, id: tcp_core::FlowId) -> Arc<SshSessionSlot> {
        Arc::clone(&self.slots[ssh_session_index_for_flow(id, self.slots.len())])
    }

    fn slot_for_background(&self) -> Arc<SshSessionSlot> {
        let index = self.next_background.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        Arc::clone(&self.slots[index])
    }

    pub(crate) async fn open_direct_tcpip_for_flow(
        &self,
        id: tcp_core::FlowId,
    ) -> Result<ssh_bridge::DirectTcpipChannel> {
        let flow = id.key;
        self.slot_for_flow(id)
            .open_direct_tcpip(
                flow.dst_ip.to_string(),
                u32::from(flow.dst_port),
                flow.src_ip.to_string(),
                u32::from(flow.src_port),
            )
            .await
    }

    pub(crate) async fn open_background_direct_tcpip(
        &self,
        host: String,
        port: u32,
        originator_address: String,
        originator_port: u32,
    ) -> Result<ssh_bridge::DirectTcpipChannel> {
        self.slot_for_background()
            .open_direct_tcpip(host, port, originator_address, originator_port)
            .await
    }
}

struct SshSessionSlot {
    index: usize,
    handle: Mutex<Handle<Client>>,
    reconnect_lock: Mutex<()>,
    prepared: Arc<PreparedSshConnection>,
    reconnects: AtomicUsize,
}

impl SshSessionSlot {
    fn new(index: usize, handle: Handle<Client>, prepared: Arc<PreparedSshConnection>) -> Self {
        Self {
            index,
            handle: Mutex::new(handle),
            reconnect_lock: Mutex::new(()),
            prepared,
            reconnects: AtomicUsize::new(0),
        }
    }

    async fn open_direct_tcpip(
        &self,
        host: String,
        port: u32,
        originator_address: String,
        originator_port: u32,
    ) -> Result<ssh_bridge::DirectTcpipChannel> {
        let observed_reconnects = self.reconnects.load(Ordering::Acquire);
        match self
            .try_open_direct_tcpip(&host, port, &originator_address, originator_port)
            .await
        {
            Ok(channel) => Ok(channel),
            Err(first_err) => {
                eprintln!(
                    "ssh: session {} direct-tcpip open failed: {first_err:#}; reconnecting",
                    self.index
                );
                self.reconnect_if_unchanged(observed_reconnects).await?;
                self.try_open_direct_tcpip(&host, port, &originator_address, originator_port)
                    .await
                    .with_context(|| {
                        format!(
                            "direct-tcpip open still failed after reconnecting SSH session {}",
                            self.index
                        )
                    })
            }
        }
    }

    async fn try_open_direct_tcpip(
        &self,
        host: &str,
        port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ssh_bridge::DirectTcpipChannel> {
        let handle = self.handle.lock().await;
        handle
            .channel_open_direct_tcpip(
                host.to_owned(),
                port,
                originator_address.to_owned(),
                originator_port,
            )
            .await
            .with_context(|| {
                format!(
                    "failed to open SSH direct-tcpip channel on session {}",
                    self.index
                )
            })
    }

    async fn reconnect_if_unchanged(&self, observed_reconnects: usize) -> Result<()> {
        let _guard = self.reconnect_lock.lock().await;
        if self.reconnects.load(Ordering::Acquire) != observed_reconnects {
            eprintln!(
                "ssh: session {} was already reconnected by another flow",
                self.index
            );
            return Ok(());
        }

        let new_handle = connect_prepared_ssh(&self.prepared)
            .await
            .with_context(|| format!("failed to reconnect SSH session {}", self.index))?;
        let mut handle = self.handle.lock().await;
        *handle = new_handle;
        let reconnect_count = self.reconnects.fetch_add(1, Ordering::AcqRel) + 1;
        eprintln!(
            "ssh: session {} reconnected count={reconnect_count}",
            self.index
        );
        Ok(())
    }
}

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

pub(crate) async fn connect_ssh_pool(
    args: &SshArgs,
    desired_sessions: usize,
) -> Result<SshSessionPool> {
    validate_ssh_session_count(desired_sessions)?;
    let prepared = Arc::new(prepare_ssh_connection(args)?);
    let mut slots = Vec::with_capacity(desired_sessions);
    slots.push(Arc::new(SshSessionSlot::new(
        0,
        connect_prepared_ssh(&prepared).await?,
        Arc::clone(&prepared),
    )));

    for index in 1..desired_sessions {
        match connect_prepared_ssh(&prepared).await {
            Ok(handle) => slots.push(Arc::new(SshSessionSlot::new(
                index,
                handle,
                Arc::clone(&prepared),
            ))),
            Err(err) => {
                eprintln!(
                    "ssh: additional session {}/{} failed: {err:#}; continuing with {} session(s)",
                    index + 1,
                    desired_sessions,
                    slots.len()
                );
                break;
            }
        }
    }

    let pool = SshSessionPool::new(slots)?;
    eprintln!("ssh: established {} session(s)", pool.len());
    Ok(pool)
}

pub(crate) fn validate_ssh_session_count(sessions: usize) -> Result<()> {
    if sessions == 0 {
        bail!("--ssh-sessions must be greater than zero");
    }
    if sessions > MAX_SSH_SESSIONS {
        bail!("--ssh-sessions must be <= {MAX_SSH_SESSIONS}");
    }
    Ok(())
}

pub(crate) fn validate_agent_session_count(sessions: usize) -> Result<()> {
    if sessions == 0 {
        bail!("--agent-sessions must be greater than zero");
    }
    if sessions > MAX_SSH_SESSIONS {
        bail!("--agent-sessions must be <= {MAX_SSH_SESSIONS}");
    }
    Ok(())
}

pub(crate) fn validate_agent_session_request_count(sessions: usize) -> Result<()> {
    if sessions > MAX_SSH_SESSIONS {
        bail!("--agent-sessions must be <= {MAX_SSH_SESSIONS}");
    }
    Ok(())
}

pub(crate) fn resolve_agent_session_count(requested: usize) -> usize {
    if requested == AUTO_AGENT_SESSIONS {
        recommended_agent_session_count()
    } else {
        requested
    }
}

fn recommended_agent_session_count() -> usize {
    let parallelism = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(2);
    recommended_agent_session_count_for_parallelism(parallelism)
}

pub(crate) fn recommended_agent_session_count_for_parallelism(parallelism: usize) -> usize {
    let cap = MAX_AUTO_AGENT_SESSIONS.min(MAX_SSH_SESSIONS);
    let parallelism = parallelism.max(1);
    for lanes in 1..=cap {
        if parallelism <= lanes.saturating_mul(lanes) {
            return lanes;
        }
    }
    cap
}

pub(crate) fn ssh_session_index_for_flow(id: tcp_core::FlowId, sessions: usize) -> usize {
    assert!(sessions > 0, "session count must be non-zero");
    (finalize_flow_hash(flow_hash(id)) % sessions as u64) as usize
}

fn flow_hash(id: tcp_core::FlowId) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in id.key.src_ip.octets() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in id.key.src_port.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in id.key.dst_ip.octets() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in id.key.dst_port.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    hash = fnv1a_mix(hash, 6);
    for byte in id.generation.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    hash
}

pub(crate) fn fnv1a_mix(hash: u64, byte: u8) -> u64 {
    (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
}

pub(crate) fn finalize_flow_hash(mut hash: u64) -> u64 {
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 31)
}

pub(crate) async fn connect_ssh(args: &SshArgs) -> Result<Handle<Client>> {
    let prepared = prepare_ssh_connection(args)?;
    connect_prepared_ssh(&prepared).await
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

pub(crate) fn resolve_ssh_password(args: &SshArgs) -> Result<Option<String>> {
    if args.password.is_some() && args.password_file.is_some() {
        bail!("--password-file cannot be combined with --password");
    }
    match (&args.password, &args.password_file) {
        (_, Some(path)) => read_password_file(path).map(Some),
        (Some(Some(value)), None) => {
            eprintln!(
                "ssh: warning: inline --password values may be visible to other local users; prefer --password-file or an interactive prompt"
            );
            Ok(Some(value.clone()))
        }
        (Some(None), None) => {
            let password = match read_password_file_from_env()? {
                Some(value) => value,
                None => rpassword::prompt_password("SSH password: ")
                    .context("failed to read password from terminal")?,
            };
            Ok(Some(password))
        }
        (None, None) => Ok(None),
    }
}

pub(crate) async fn connect_prepared_ssh(
    prepared: &PreparedSshConnection,
) -> Result<Handle<Client>> {
    let target = &prepared.target;
    let verifier = HostKeyVerifier::new(
        target.host.clone(),
        target.port,
        prepared.known_hosts.clone(),
        prepared.insecure_accept_host_key,
        prepared.accept_new_host_key,
    );
    let config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        keepalive_interval: Some(Duration::from_secs(10)),
        keepalive_max: 3,
        nodelay: true,
        ..Config::default()
    });

    eprintln!(
        "ssh: connecting to {} with timeout {}s",
        target.addr,
        prepared.connect_timeout.as_secs()
    );
    let mut handle = tokio::time::timeout(
        prepared.connect_timeout,
        client::connect(config, target.addr.as_str(), Client { verifier }),
    )
    .await
    .with_context(|| {
        format!(
            "timed out after {}s connecting to SSH server {}",
            prepared.connect_timeout.as_secs(),
            target.addr
        )
    })?
    .with_context(|| format!("failed to connect to SSH server {}", target.addr))?;
    eprintln!(
        "ssh: connected to {}; authenticating as {}",
        target.addr, target.user
    );
    authenticate(&mut handle, &target.user, prepared).await?;
    eprintln!("ssh: authenticated to {}", target.addr);
    Ok(handle)
}

fn ssh_connect_timeout(seconds: u64) -> Result<Duration> {
    if seconds == 0 {
        bail!("--ssh-connect-timeout must be greater than zero");
    }
    Ok(Duration::from_secs(seconds))
}

async fn authenticate(
    handle: &mut Handle<Client>,
    user: &str,
    prepared: &PreparedSshConnection,
) -> Result<()> {
    for identity in &prepared.identity_files {
        let key = load_private_key(identity)?;
        let result = handle
            .authenticate_publickey(user.to_owned(), key)
            .await
            .with_context(|| {
                format!(
                    "public-key authentication failed for {}",
                    identity.display()
                )
            })?;
        if matches!(result, AuthResult::Success) {
            return Ok(());
        }
    }

    if let Some(password) = &prepared.password {
        let result = handle
            .authenticate_password(user.to_owned(), password.clone())
            .await
            .context("password authentication failed")?;
        if matches!(result, AuthResult::Success) {
            return Ok(());
        }
    }

    bail!("authentication failed; provide --identity, --password, or both")
}

pub(crate) fn read_password_file_from_env() -> Result<Option<String>> {
    let Some(path) = env::var_os(SSH_PASSWORD_FILE_ENV) else {
        return Ok(None);
    };
    read_password_file(Path::new(&path)).map(Some)
}

pub(crate) fn read_password_file(path: &Path) -> Result<String> {
    let mut password = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read SSH password file {}", path.display()))?;
    while matches!(password.as_bytes().last(), Some(b'\n' | b'\r')) {
        password.pop();
    }
    Ok(password)
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyWithHashAlg> {
    let key_data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read private key {}", path.display()))?;
    let key = PrivateKey::from_openssh(&key_data)
        .with_context(|| format!("failed to parse private key {}", path.display()))?;
    let hash_alg = match key.algorithm() {
        Algorithm::Rsa { .. } => Some(HashAlg::Sha512),
        _ => None,
    };

    Ok(PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SshTarget {
    pub(crate) user: String,
    pub(crate) addr: String,
    pub(crate) host: String,
    pub(crate) port: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SshConfigMatch {
    pub(crate) hostname: Option<String>,
    pub(crate) user: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) identity_files: Vec<String>,
    pub(crate) user_known_hosts_file: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SshRemoteReference {
    user: Option<String>,
    host: String,
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
            "userknownhostsfile" if matched.user_known_hosts_file.is_none() => {
                if !value.eq_ignore_ascii_case("none") {
                    matched.user_known_hosts_file = Some(value.clone());
                }
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

#[cfg(test)]
pub(crate) fn parse_ssh_target(remote: &str, user_override: Option<&str>) -> Result<SshTarget> {
    let reference = parse_ssh_remote_reference(remote)?;

    let user = user_override
        .or(reference.user.as_deref())
        .map(str::to_owned)
        .or_else(default_username)
        .ok_or_else(|| anyhow!("missing SSH user; use -r user@host or --user"))?;

    let endpoint = parse_ssh_endpoint(&reference.host)?;

    Ok(SshTarget {
        user,
        addr: endpoint.addr,
        host: endpoint.host,
        port: endpoint.port,
    })
}

fn parse_ssh_remote_reference(remote: &str) -> Result<SshRemoteReference> {
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

fn ssh_endpoint_port_is_explicit(input: &str) -> bool {
    if let Some(rest) = input.strip_prefix('[') {
        return rest
            .split_once(']')
            .is_some_and(|(_, suffix)| suffix.starts_with(':') && suffix.len() > 1);
    }
    input.rsplit_once(':').is_some()
}

fn ssh_socket_addr_string(host: &str, port: u16) -> String {
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

fn default_username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("USERNAME")
                .ok()
                .filter(|value| !value.is_empty())
        })
}

#[derive(Clone, Debug)]
pub(crate) struct HostKeyVerifier {
    host: String,
    port: u16,
    known_hosts: Option<PathBuf>,
    insecure_accept: bool,
    accept_new: bool,
}

impl HostKeyVerifier {
    pub(crate) fn new(
        host: String,
        port: u16,
        known_hosts: Option<PathBuf>,
        insecure_accept: bool,
        accept_new: bool,
    ) -> Self {
        Self {
            host,
            port,
            known_hosts,
            insecure_accept,
            accept_new,
        }
    }

    pub(crate) fn verify(&self, server_public_key: &PublicKey) -> Result<bool> {
        if self.insecure_accept {
            eprintln!(
                "ssh: insecurely accepting host key for {} ({})",
                self.known_hosts_hostport(),
                server_public_key.fingerprint(Default::default())
            );
            return Ok(true);
        }

        let path = self.known_hosts_path()?;
        let input = match std::fs::read_to_string(&path) {
            Ok(input) => input,
            Err(err) if self.accept_new && err.kind() == std::io::ErrorKind::NotFound => {
                String::new()
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to read known_hosts file {}", path.display()))
            }
        };
        let candidates = self.host_match_candidates();
        let mut host_matched = false;
        let mut key_mismatch = false;

        for entry in KnownHosts::new(&input) {
            let entry = entry.with_context(|| format!("failed to parse {}", path.display()))?;
            if !known_hosts_entry_matches(entry.host_patterns(), &candidates) {
                continue;
            }

            host_matched = true;
            let key_matches = entry.public_key().key_data() == server_public_key.key_data();
            if matches!(entry.marker(), Some(Marker::Revoked)) && key_matches {
                bail!(
                    "SSH host key for {} is marked revoked in {}",
                    self.known_hosts_hostport(),
                    path.display()
                );
            }

            if key_matches && entry.marker().is_none() {
                return Ok(true);
            }
            if key_matches && matches!(entry.marker(), Some(Marker::CertAuthority)) {
                continue;
            }
            key_mismatch = true;
        }

        let fingerprint = server_public_key.fingerprint(Default::default());
        if key_mismatch {
            bail!(
                "SSH host key mismatch for {}; presented fingerprint {}; update {} only if the server key changed intentionally",
                self.known_hosts_hostport(),
                fingerprint,
                path.display()
            );
        }
        if host_matched {
            bail!(
                "SSH host entry for {} exists in {}, but no usable plain host-key entry matched fingerprint {}",
                self.known_hosts_hostport(),
                path.display(),
                fingerprint
            );
        }

        if self.accept_new {
            self.append_known_host(&path, server_public_key)?;
            eprintln!(
                "ssh: recorded new host key for {} in {} ({})",
                self.known_hosts_hostport(),
                path.display(),
                fingerprint
            );
            return Ok(true);
        }

        bail!(
            "SSH host {} is not in {}; verify the fingerprint {}, then add it with ssh-keyscan, use --accept-new-host-key to trust and record this first key, or use --insecure-accept-host-key only for a controlled lab",
            self.known_hosts_hostport(),
            path.display(),
            fingerprint
        )
    }

    fn append_known_host(&self, path: &Path, server_public_key: &PublicKey) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                create_known_hosts_parent_dir(parent)?;
            }
        }

        let key = server_public_key
            .to_openssh()
            .context("failed to encode SSH server public key")?;
        let entry = format!("{} {}\n", self.known_hosts_hostport(), key);
        append_known_hosts_entry(path, &entry)
            .with_context(|| format!("failed to append host key to {}", path.display()))
    }

    fn known_hosts_path(&self) -> Result<PathBuf> {
        if let Some(path) = &self.known_hosts {
            return Ok(path.clone());
        }
        default_known_hosts_path()
            .ok_or_else(|| anyhow!("could not locate home directory for ~/.ssh/known_hosts"))
    }

    fn known_hosts_hostport(&self) -> String {
        if self.port == 22 {
            self.host.clone()
        } else {
            format!("[{}]:{}", self.host, self.port)
        }
    }

    fn host_match_candidates(&self) -> Vec<String> {
        let mut candidates = Vec::new();
        candidates.push(self.known_hosts_hostport());
        if self.port == 22 {
            candidates.push(self.host.clone());
        }
        let lowercase_host = self.host.to_ascii_lowercase();
        if lowercase_host != self.host {
            if self.port == 22 {
                candidates.push(lowercase_host.clone());
            } else {
                candidates.push(format!("[{lowercase_host}]:{}", self.port));
            }
        }
        dedupe_strings(candidates)
    }
}

fn default_known_hosts_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .map(|home| home.join(".ssh").join("known_hosts"))
}

fn create_known_hosts_parent_dir(path: &Path) -> Result<()> {
    let existed = path.exists();
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create known_hosts directory {}", path.display()))?;
    if existed {
        Ok(())
    } else {
        set_known_hosts_parent_permissions(path)
    }
}

#[cfg(unix)]
fn set_known_hosts_parent_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_known_hosts_parent_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn append_known_hosts_entry(path: &Path, entry: &str) -> Result<()> {
    let needs_separator = known_hosts_needs_leading_newline(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    use std::io::Write;
    if needs_separator {
        file.write_all(b"\n")?;
    }
    file.write_all(entry.as_bytes())?;
    file.sync_all()?;
    set_known_hosts_file_permissions(path)
}

fn known_hosts_needs_leading_newline(path: &Path) -> Result<bool> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(false);
    }
    use std::io::{Read, Seek};
    file.seek(std::io::SeekFrom::End(-1))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;
    Ok(byte[0] != b'\n')
}

#[cfg(unix)]
fn set_known_hosts_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_known_hosts_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

pub(crate) fn known_hosts_entry_matches(patterns: &HostPatterns, candidates: &[String]) -> bool {
    match patterns {
        HostPatterns::Patterns(patterns) => patterns_match(patterns, candidates),
        HostPatterns::HashedName { salt, hash } => candidates.iter().any(|candidate| {
            hashed_known_host_matches(salt, hash, candidate)
                || hashed_known_host_matches(salt, hash, &candidate.to_ascii_lowercase())
        }),
    }
}

pub(crate) fn patterns_match(patterns: &[String], candidates: &[String]) -> bool {
    let mut matched_positive = false;
    for pattern in patterns {
        let (negated, pattern) = if let Some(pattern) = pattern.strip_prefix('!') {
            (true, pattern)
        } else {
            (false, pattern.as_str())
        };
        let matched = candidates
            .iter()
            .any(|candidate| glob_match_case_insensitive(pattern, candidate));
        if matched && negated {
            return false;
        }
        matched_positive |= matched;
    }
    matched_positive
}

fn glob_match_case_insensitive(pattern: &str, candidate: &str) -> bool {
    glob_match(
        pattern.to_ascii_lowercase().as_bytes(),
        candidate.to_ascii_lowercase().as_bytes(),
    )
}

fn glob_match(pattern: &[u8], candidate: &[u8]) -> bool {
    let (mut p, mut c) = (0, 0);
    let mut star = None;
    let mut star_candidate = 0;

    while c < candidate.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == candidate[c]) {
            p += 1;
            c += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            star_candidate = c;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            star_candidate += 1;
            c = star_candidate;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn hashed_known_host_matches(salt: &[u8], expected_hash: &[u8; 20], candidate: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let tag = hmac::sign(&key, candidate.as_bytes());
    tag.as_ref() == expected_hash
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.iter().any(|existing| existing == &value) {
            unique.push(value);
        }
    }
    unique
}

#[derive(Clone)]
pub(crate) struct Client {
    pub(crate) verifier: HostKeyVerifier,
}

impl Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool> {
        self.verifier.verify(server_public_key)
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant as StdInstant};

    use clap::Parser;
    use ring::hmac;
    use russh::keys::{PrivateKey, PublicKey};
    use ssh_key::known_hosts::HostPatterns;
    use tokio::sync::mpsc;

    use super::*;
    use crate::cli::Cli;
    use crate::defaults::DEFAULT_SSH_SESSIONS;
    use crate::{tcp_core, SshArgs};

    const TEST_ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
    const OTHER_ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
    const TEST_ED25519_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
        QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n\
        XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n\
        AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n\
        ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==\n\
        -----END OPENSSH PRIVATE KEY-----\n";

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
    fn password_file_reader_strips_shell_newlines_only() {
        let path = env::temp_dir().join(format!(
            "rustle-password-test-{}-{}",
            std::process::id(),
            StdInstant::now().elapsed().as_nanos()
        ));
        std::fs::write(&path, " secret value \r\n").unwrap();

        let password = read_password_file(&path).unwrap();

        std::fs::remove_file(&path).unwrap();
        assert_eq!(password, " secret value ");
    }

    #[test]
    fn ssh_password_file_option_reads_password_without_argv_secret() {
        let path = env::temp_dir().join(format!(
            "rustle-password-file-option-test-{}-{}",
            std::process::id(),
            StdInstant::now().elapsed().as_nanos()
        ));
        std::fs::write(&path, "file secret\r\n").unwrap();

        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--password-file",
            path.to_str().expect("password path is UTF-8"),
            "10.0.0.0/8",
        ])
        .expect("compact CLI with password file");

        assert_eq!(cli.compact.ssh.password, None);
        assert_eq!(
            cli.compact.ssh.password_file.as_deref(),
            Some(path.as_path())
        );
        assert_eq!(
            resolve_ssh_password(&cli.compact.ssh).expect("read password file"),
            Some("file secret".to_owned())
        );

        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn ssh_password_file_authenticates_against_russh_server() {
        struct PasswordAuthServer {
            expected_user: String,
            expected_password: String,
            attempts: mpsc::Sender<(String, String)>,
        }

        impl russh::server::Handler for PasswordAuthServer {
            type Error = anyhow::Error;

            async fn auth_password(
                &mut self,
                user: &str,
                password: &str,
            ) -> Result<russh::server::Auth, Self::Error> {
                let _ = self
                    .attempts
                    .try_send((user.to_owned(), password.to_owned()));
                if user == self.expected_user && password == self.expected_password {
                    Ok(russh::server::Auth::Accept)
                } else {
                    Ok(russh::server::Auth::reject())
                }
            }
        }

        let expected_user = "alice";
        let expected_password = "file secret";
        let password_path = env::temp_dir().join(format!(
            "rustle-password-auth-test-{}-{}",
            std::process::id(),
            StdInstant::now().elapsed().as_nanos()
        ));
        std::fs::write(&password_path, format!("{expected_password}\n")).unwrap();

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test SSH server");
        let server_addr = listener.local_addr().expect("test SSH server address");
        let (attempts_tx, mut attempts_rx) = mpsc::channel(1);
        let config = Arc::new(russh::server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![PrivateKey::from_openssh(TEST_ED25519_PRIVATE_KEY)
                .expect("parse test SSH host key")],
            ..Default::default()
        });
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept SSH client");
            let session = russh::server::run_stream(
                config,
                stream,
                PasswordAuthServer {
                    expected_user: expected_user.to_owned(),
                    expected_password: expected_password.to_owned(),
                    attempts: attempts_tx,
                },
            )
            .await
            .expect("start russh test session");
            let _ = tokio::time::timeout(Duration::from_secs(5), session).await;
        });

        let mut args = test_ssh_args(&format!("127.0.0.1:{}", server_addr.port()));
        args.ssh_user = Some(expected_user.to_owned());
        args.password_file = Some(password_path.clone());
        args.insecure_accept_host_key = true;
        args.ssh_connect_timeout_secs = 2;
        let handle = connect_ssh(&args)
            .await
            .expect("connect with password-file authentication");

        let attempt = tokio::time::timeout(Duration::from_secs(3), attempts_rx.recv())
            .await
            .expect("password auth attempt")
            .expect("password auth attempt recorded");
        assert_eq!(
            attempt,
            (expected_user.to_owned(), expected_password.to_owned())
        );

        drop(handle);
        server.abort();
        std::fs::remove_file(password_path).unwrap();
    }

    #[test]
    fn ssh_session_index_is_stable_for_same_flow_id() {
        let id = tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(10, 255, 255, 2),
                49152,
                Ipv4Addr::new(192, 168, 1, 10),
                443,
            ),
            7,
        );

        let first = ssh_session_index_for_flow(id, 4);
        for _ in 0..16 {
            assert_eq!(ssh_session_index_for_flow(id, 4), first);
        }
    }

    #[test]
    fn ssh_session_index_spreads_many_flows_across_pool() {
        let mut seen = std::collections::BTreeSet::new();
        for offset in 0..256_u16 {
            let id = tcp_core::FlowId::new(
                tcp_core::FlowKey::tcp(
                    Ipv4Addr::new(10, 255, 255, 2),
                    49152 + offset,
                    Ipv4Addr::new(192, 168, 1, 10),
                    443,
                ),
                u64::from(offset) + 1,
            );
            seen.insert(ssh_session_index_for_flow(id, 4));
        }

        assert_eq!(seen, [0_usize, 1, 2, 3].into_iter().collect());
    }

    #[test]
    fn ssh_session_count_validation_bounds_pool_size() {
        assert!(validate_ssh_session_count(1).is_ok());
        assert!(validate_ssh_session_count(DEFAULT_SSH_SESSIONS).is_ok());
        assert!(validate_ssh_session_count(0).is_err());
        assert!(validate_ssh_session_count(MAX_SSH_SESSIONS + 1).is_err());
    }

    #[test]
    fn agent_session_count_validation_bounds_pool_size() {
        assert!(validate_agent_session_count(1).is_ok());
        assert!(validate_agent_session_count(MAX_AUTO_AGENT_SESSIONS).is_ok());
        assert!(validate_agent_session_count(0).is_err());
        assert!(validate_agent_session_count(MAX_SSH_SESSIONS + 1).is_err());
        assert!(validate_agent_session_request_count(AUTO_AGENT_SESSIONS).is_ok());
        assert!(validate_agent_session_request_count(MAX_SSH_SESSIONS + 1).is_err());
    }

    #[test]
    fn auto_agent_session_count_is_conservative_and_nonzero() {
        assert_eq!(resolve_agent_session_count(3), 3);
        assert_eq!(recommended_agent_session_count_for_parallelism(0), 1);
        assert_eq!(recommended_agent_session_count_for_parallelism(1), 1);
        assert_eq!(recommended_agent_session_count_for_parallelism(2), 2);
        assert_eq!(recommended_agent_session_count_for_parallelism(4), 2);
        assert_eq!(recommended_agent_session_count_for_parallelism(5), 3);
        assert_eq!(recommended_agent_session_count_for_parallelism(9), 3);
        assert_eq!(recommended_agent_session_count_for_parallelism(10), 4);
        assert_eq!(
            recommended_agent_session_count_for_parallelism(usize::MAX),
            MAX_AUTO_AGENT_SESSIONS
        );
        let resolved = resolve_agent_session_count(AUTO_AGENT_SESSIONS);
        assert!((1..=MAX_AUTO_AGENT_SESSIONS).contains(&resolved));
    }

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
    fn known_hosts_patterns_support_wildcards_ports_and_negation() {
        assert!(patterns_match(
            &["*.example.com".to_owned()],
            &["api.example.com".to_owned()]
        ));
        assert!(patterns_match(
            &["[*.example.com]:2222".to_owned()],
            &["[api.example.com]:2222".to_owned()]
        ));
        assert!(!patterns_match(
            &["*.example.com".to_owned(), "!bad.example.com".to_owned()],
            &["bad.example.com".to_owned()]
        ));
    }

    #[test]
    fn known_hosts_hashed_name_matches_hmac_sha1_candidate() {
        let salt = b"01234567890123456789";
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
        let tag = hmac::sign(&key, b"example.com");
        let mut hash = [0_u8; 20];
        hash.copy_from_slice(tag.as_ref());

        assert!(known_hosts_entry_matches(
            &HostPatterns::HashedName {
                salt: salt.to_vec(),
                hash,
            },
            &["example.com".to_owned()]
        ));
        assert!(!known_hosts_entry_matches(
            &HostPatterns::HashedName {
                salt: salt.to_vec(),
                hash,
            },
            &["other.example.com".to_owned()]
        ));
    }

    #[test]
    fn host_key_verifier_accepts_matching_known_hosts_entry() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_rejects_mismatched_known_hosts_entry() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = OTHER_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier.verify(&key).expect_err("mismatch must fail");
        assert!(err.to_string().contains("mismatch"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accepts_bracketed_non_default_port() {
        let path = write_temp_known_hosts(&format!("[test.example.com]:2222 {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            2222,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_rejects_revoked_key() {
        let path =
            write_temp_known_hosts(&format!("@revoked test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier.verify(&key).expect_err("revoked key must fail");
        assert!(err.to_string().contains("revoked"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accept_new_records_missing_host_key() {
        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        let root = env::temp_dir().join(format!(
            "rustle-known-hosts-accept-new-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempTree { path: root };
        let path = temp.path.join(".ssh").join("known_hosts");
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        let recorded = std::fs::read_to_string(&path).expect("known_hosts was created");
        assert_eq!(recorded, format!("test.example.com {TEST_ED25519_KEY}\n"));

        let strict = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        assert!(strict.verify(&key).unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .expect("known_hosts parent metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("known_hosts metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn host_key_verifier_accept_new_preserves_existing_line_without_newline() {
        let path = write_temp_known_hosts(&format!("other.example.com {OTHER_ED25519_KEY}"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        let recorded = std::fs::read_to_string(&path).expect("known_hosts was updated");
        assert_eq!(
            recorded,
            format!("other.example.com {OTHER_ED25519_KEY}\ntest.example.com {TEST_ED25519_KEY}\n")
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accept_new_rejects_changed_known_host() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = OTHER_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier
            .verify(&key)
            .expect_err("accept-new must reject changed keys");
        assert!(err.to_string().contains("mismatch"));
        let recorded = std::fs::read_to_string(&path).expect("known_hosts still readable");
        assert!(!recorded.contains(OTHER_ED25519_KEY));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_unknown_host_error_mentions_accept_new() {
        let path = write_temp_known_hosts("");
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier
            .verify(&key)
            .expect_err("unknown host must fail in strict mode");
        let message = err.to_string();
        assert!(message.contains("--accept-new-host-key"));
        assert!(message.contains("--insecure-accept-host-key"));
        assert!(message.contains("SHA256:"));
        std::fs::remove_file(path).ok();
    }

    fn write_temp_known_hosts(contents: &str) -> PathBuf {
        static NEXT_KNOWN_HOSTS_FILE: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT_KNOWN_HOSTS_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustle-known-hosts-{}-{}-{}.tmp",
            std::process::id(),
            sequence,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        path
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
