use anyhow::{bail, Result};

use crate::remote_helper::{HelperCommandPlan, HelperKind};
use crate::transport_model::BridgeTransportKind;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BridgeHelperCommandPlan {
    Single(HelperCommandPlan),
    AutoQuic {
        agent: HelperCommandPlan,
        quic_native: HelperCommandPlan,
    },
}

pub(crate) fn bridge_runtime_command_plan(
    transport: BridgeTransportKind,
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<BridgeHelperCommandPlan> {
    if transport != BridgeTransportKind::AutoQuic {
        return bridge_agent_command_plan(transport, agent_command, agent_path)
            .map(BridgeHelperCommandPlan::Single);
    }

    if agent_command.is_some() {
        bail!(
            "--agent-command cannot be used with --bridge-transport auto-quic because the QUIC probe and agent fallback need different helper subcommands; use --agent-path instead"
        );
    }

    Ok(BridgeHelperCommandPlan::AutoQuic {
        agent: HelperCommandPlan::from_command_options(HelperKind::StdioAgent, None, agent_path)?,
        quic_native: HelperCommandPlan::from_command_options(
            HelperKind::QuicBridgeNative,
            None,
            agent_path,
        )?,
    })
}

fn bridge_agent_command_plan(
    transport: BridgeTransportKind,
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<HelperCommandPlan> {
    HelperCommandPlan::from_command_options(
        helper_kind_for_bridge_transport(transport),
        agent_command,
        agent_path,
    )
}

fn helper_kind_for_bridge_transport(transport: BridgeTransportKind) -> HelperKind {
    match transport {
        BridgeTransportKind::QuicAgent => HelperKind::QuicAgent,
        BridgeTransportKind::QuicNative => HelperKind::QuicBridgeNative,
        BridgeTransportKind::Auto
        | BridgeTransportKind::AutoQuic
        | BridgeTransportKind::DirectTcpip
        | BridgeTransportKind::Agent => HelperKind::StdioAgent,
    }
}

#[cfg(test)]
fn effective_quic_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    HelperCommandPlan::from_command_options(HelperKind::QuicAgent, agent_command, agent_path)
        .map(|plan| plan.command)
}

#[cfg(test)]
fn effective_quic_bridge_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    HelperCommandPlan::from_command_options(HelperKind::QuicBridgeNative, agent_command, agent_path)
        .map(|plan| plan.command)
}

#[cfg(test)]
pub(crate) fn effective_bridge_agent_command(
    transport: BridgeTransportKind,
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    match helper_kind_for_bridge_transport(transport) {
        HelperKind::QuicAgent => effective_quic_agent_command(agent_command, agent_path),
        HelperKind::QuicBridgeNative => {
            effective_quic_bridge_agent_command(agent_command, agent_path)
        }
        HelperKind::StdioAgent => {
            crate::remote_helper::effective_agent_command(agent_command, agent_path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_kind_maps_bridge_transports_to_helper_commands() {
        assert_eq!(
            helper_kind_for_bridge_transport(BridgeTransportKind::QuicAgent),
            HelperKind::QuicAgent
        );
        assert_eq!(
            helper_kind_for_bridge_transport(BridgeTransportKind::QuicNative),
            HelperKind::QuicBridgeNative
        );
        assert_eq!(
            helper_kind_for_bridge_transport(BridgeTransportKind::Agent),
            HelperKind::StdioAgent
        );
        assert_eq!(
            helper_kind_for_bridge_transport(BridgeTransportKind::DirectTcpip),
            HelperKind::StdioAgent
        );
        assert_eq!(
            helper_kind_for_bridge_transport(BridgeTransportKind::Auto),
            HelperKind::StdioAgent
        );
        assert_eq!(
            helper_kind_for_bridge_transport(BridgeTransportKind::AutoQuic),
            HelperKind::StdioAgent
        );
    }

    #[test]
    fn auto_quic_runtime_plan_uses_distinct_helper_subcommands() {
        let plans =
            bridge_runtime_command_plan(BridgeTransportKind::AutoQuic, None, Some("/tmp/rustle"))
                .expect("auto-quic can derive both commands from a helper path");
        let BridgeHelperCommandPlan::AutoQuic { agent, quic_native } = plans else {
            panic!("expected auto-quic dual plan");
        };

        assert_eq!(agent.kind, HelperKind::StdioAgent);
        assert_eq!(agent.command, "'/tmp/rustle' agent");
        assert_eq!(quic_native.kind, HelperKind::QuicBridgeNative);
        assert_eq!(quic_native.command, "'/tmp/rustle' quic-bridge-agent");
    }

    #[test]
    fn auto_quic_runtime_plan_rejects_single_explicit_command() {
        let err = bridge_runtime_command_plan(
            BridgeTransportKind::AutoQuic,
            Some("/tmp/rustle quic-bridge-agent"),
            None,
        )
        .expect_err("auto-quic cannot split one explicit command into two helper commands");

        assert!(err.to_string().contains("--agent-path"));
    }
}
