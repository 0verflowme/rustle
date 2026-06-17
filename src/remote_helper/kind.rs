use crate::transport_model::BridgeTransportKind;

pub(crate) const DEFAULT_AGENT_COMMAND: &str = "rustle agent";
pub(crate) const DEFAULT_QUIC_AGENT_COMMAND: &str = "rustle quic-agent";
pub(crate) const DEFAULT_QUIC_BRIDGE_AGENT_COMMAND: &str = "rustle quic-bridge-agent";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HelperKind {
    StdioAgent,
    QuicAgent,
    QuicBridgeNative,
}

impl HelperKind {
    pub(crate) fn subcommand(self) -> &'static str {
        helper_command_labels(self).0
    }

    pub(crate) fn default_command(self) -> &'static str {
        helper_command_labels(self).1
    }

    pub(crate) fn controller_log_prefix(self) -> &'static str {
        match self {
            Self::StdioAgent => "agent",
            Self::QuicAgent => "quic-agent",
            Self::QuicBridgeNative => "quic-native",
        }
    }

    pub(super) fn sidecar_noun(self) -> &'static str {
        match self {
            Self::StdioAgent => "agent",
            Self::QuicAgent | Self::QuicBridgeNative => "helper",
        }
    }

    pub(super) fn platform_probe_context(self) -> &'static str {
        match self {
            Self::StdioAgent => "failed to determine remote platform for Rustle agent bootstrap",
            Self::QuicAgent => {
                "failed to determine remote platform for Rustle QUIC agent bootstrap"
            }
            Self::QuicBridgeNative => {
                "failed to determine remote platform for native QUIC bridge bootstrap"
            }
        }
    }

    pub(crate) fn uploaded_start_context(self, remote_path: &str) -> String {
        match self {
            Self::StdioAgent => {
                format!("uploaded Rustle agent failed to start from {remote_path}")
            }
            Self::QuicAgent => {
                format!("uploaded Rustle QUIC agent failed to start from {remote_path}")
            }
            Self::QuicBridgeNative => {
                format!("uploaded native QUIC bridge helper failed to start from {remote_path}")
            }
        }
    }

    pub(crate) fn for_bridge_transport(transport: BridgeTransportKind) -> Self {
        match transport {
            BridgeTransportKind::QuicAgent => Self::QuicAgent,
            BridgeTransportKind::QuicNative => Self::QuicBridgeNative,
            BridgeTransportKind::Auto
            | BridgeTransportKind::DirectTcpip
            | BridgeTransportKind::Agent => Self::StdioAgent,
        }
    }
}

pub(crate) fn helper_command_labels(kind: HelperKind) -> (&'static str, &'static str) {
    match kind {
        HelperKind::StdioAgent => ("agent", DEFAULT_AGENT_COMMAND),
        HelperKind::QuicAgent => ("quic-agent", DEFAULT_QUIC_AGENT_COMMAND),
        HelperKind::QuicBridgeNative => ("quic-bridge-agent", DEFAULT_QUIC_BRIDGE_AGENT_COMMAND),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_kind_maps_to_subcommands_and_default_commands() {
        let cases = [
            (HelperKind::StdioAgent, "agent", DEFAULT_AGENT_COMMAND),
            (
                HelperKind::QuicAgent,
                "quic-agent",
                DEFAULT_QUIC_AGENT_COMMAND,
            ),
            (
                HelperKind::QuicBridgeNative,
                "quic-bridge-agent",
                DEFAULT_QUIC_BRIDGE_AGENT_COMMAND,
            ),
        ];

        for (kind, subcommand, default_command) in cases {
            assert_eq!(helper_command_labels(kind), (subcommand, default_command));
            assert_eq!(kind.subcommand(), subcommand);
            assert_eq!(kind.default_command(), default_command);
        }
    }

    #[test]
    fn helper_kind_metadata_preserves_controller_labels_and_contexts() {
        let cases = [
            (
                HelperKind::StdioAgent,
                "agent",
                "agent",
                "failed to determine remote platform for Rustle agent bootstrap",
                "uploaded Rustle agent failed to start from /tmp/rustle-agent",
            ),
            (
                HelperKind::QuicAgent,
                "quic-agent",
                "helper",
                "failed to determine remote platform for Rustle QUIC agent bootstrap",
                "uploaded Rustle QUIC agent failed to start from /tmp/rustle-agent",
            ),
            (
                HelperKind::QuicBridgeNative,
                "quic-native",
                "helper",
                "failed to determine remote platform for native QUIC bridge bootstrap",
                "uploaded native QUIC bridge helper failed to start from /tmp/rustle-agent",
            ),
        ];

        for (kind, log_prefix, sidecar_noun, probe_context, start_context) in cases {
            assert_eq!(kind.controller_log_prefix(), log_prefix);
            assert_eq!(kind.sidecar_noun(), sidecar_noun);
            assert_eq!(kind.platform_probe_context(), probe_context);
            assert_eq!(
                kind.uploaded_start_context("/tmp/rustle-agent"),
                start_context
            );
        }
    }

    #[test]
    fn helper_kind_maps_bridge_transports_to_helper_commands() {
        assert_eq!(
            HelperKind::for_bridge_transport(BridgeTransportKind::QuicAgent),
            HelperKind::QuicAgent
        );
        assert_eq!(
            HelperKind::for_bridge_transport(BridgeTransportKind::QuicNative),
            HelperKind::QuicBridgeNative
        );
        assert_eq!(
            HelperKind::for_bridge_transport(BridgeTransportKind::Agent),
            HelperKind::StdioAgent
        );
        assert_eq!(
            HelperKind::for_bridge_transport(BridgeTransportKind::DirectTcpip),
            HelperKind::StdioAgent
        );
        assert_eq!(
            HelperKind::for_bridge_transport(BridgeTransportKind::Auto),
            HelperKind::StdioAgent
        );
    }
}
