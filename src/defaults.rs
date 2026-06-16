use std::net::Ipv4Addr;

pub(crate) const DEFAULT_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);
pub(crate) const DEFAULT_TUN_PREFIX: u8 = 24;
pub(crate) const DEFAULT_MTU: u16 = 1300;
pub(crate) const DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS: u64 = 60_000;
pub(crate) const DEFAULT_SSH_SESSIONS: usize = 4;
pub(crate) const DEFAULT_AGENT_SESSIONS: usize = 1;
