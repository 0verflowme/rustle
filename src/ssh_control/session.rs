use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use russh::client::{self, Config, Handle, Handler};
use russh::keys::PublicKey;
use tokio::sync::Mutex;

use crate::known_hosts::HostKeyVerifier;
use crate::{ssh_bridge, tcp_core, SshArgs};

use super::auth::authenticate;
use super::config::{prepare_ssh_connection, PreparedSshConnection};

pub(crate) const MAX_SSH_SESSIONS: usize = 16;
pub(crate) const RUSTLE_SSH_CHANNEL_WINDOW_BYTES: u32 = 64 * 1024 * 1024;
pub(crate) const RUSTLE_SSH_MAX_PACKET_BYTES: u32 = 256 * 1024;

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
    let config = Arc::new(rustle_ssh_client_config());

    eprintln!(
        "ssh: channel window={}MiB max_packet={}KiB",
        RUSTLE_SSH_CHANNEL_WINDOW_BYTES / (1024 * 1024),
        RUSTLE_SSH_MAX_PACKET_BYTES / 1024
    );
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

fn rustle_ssh_client_config() -> Config {
    Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        keepalive_interval: Some(Duration::from_secs(10)),
        keepalive_max: 3,
        window_size: RUSTLE_SSH_CHANNEL_WINDOW_BYTES,
        maximum_packet_size: RUSTLE_SSH_MAX_PACKET_BYTES,
        nodelay: true,
        ..Config::default()
    }
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
    use std::sync::Arc;
    use std::time::{Duration, Instant as StdInstant};

    use russh::keys::PrivateKey;
    use tokio::sync::mpsc;

    use super::*;
    use crate::ssh_control::DEFAULT_SSH_CONNECT_TIMEOUT_SECS;
    use crate::{tcp_core, SshArgs};

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
    fn rustle_ssh_client_config_uses_data_plane_sized_channels() {
        let config = rustle_ssh_client_config();

        assert_eq!(config.window_size, RUSTLE_SSH_CHANNEL_WINDOW_BYTES);
        assert_eq!(config.maximum_packet_size, RUSTLE_SSH_MAX_PACKET_BYTES);
        assert_eq!(config.window_size, 64 * 1024 * 1024);
        assert_eq!(
            config.maximum_packet_size,
            crate::agent_proto::AGENT_MAX_FRAME_PAYLOAD as u32
        );
        assert!(config.nodelay);
        assert_eq!(config.keepalive_interval, Some(Duration::from_secs(10)));
        assert_eq!(config.keepalive_max, 3);
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
        assert!(validate_ssh_session_count(crate::defaults::DEFAULT_SSH_SESSIONS).is_ok());
        assert!(validate_ssh_session_count(0).is_err());
        assert!(validate_ssh_session_count(MAX_SSH_SESSIONS + 1).is_err());
    }
}
