use anyhow::{bail, Result};

use crate::transport_model::BridgeTransportKind;

use super::kind::HelperKind;
#[cfg(test)]
use super::kind::{
    DEFAULT_AGENT_COMMAND, DEFAULT_QUIC_AGENT_COMMAND, DEFAULT_QUIC_BRIDGE_AGENT_COMMAND,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum BootstrapPolicy {
    BuiltInCommandWithUploadFallback,
    ExplicitCommandNoFallback,
    ExplicitUploadAllowed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HelperCommandPlan {
    pub(crate) kind: HelperKind,
    pub(crate) command: String,
    policy: BootstrapPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BridgeHelperCommandPlan {
    Single(HelperCommandPlan),
    AutoQuic {
        agent: HelperCommandPlan,
        quic_native: HelperCommandPlan,
    },
}

impl HelperCommandPlan {
    pub(crate) fn from_command_options(
        kind: HelperKind,
        agent_command: Option<&str>,
        agent_path: Option<&str>,
    ) -> Result<Self> {
        let (command, policy) = match (agent_command, agent_path) {
            (Some(_), Some(_)) => {
                bail!("--agent-command cannot be combined with --agent-path");
            }
            (Some(command), None) => {
                if command.trim().is_empty() {
                    bail!("--agent-command must not be empty");
                }
                (
                    command.to_owned(),
                    BootstrapPolicy::ExplicitCommandNoFallback,
                )
            }
            (None, Some(path)) => {
                if path.trim().is_empty() {
                    bail!("--agent-path must not be empty");
                }
                (
                    format!("{} {}", shell_quote(path), kind.subcommand()),
                    BootstrapPolicy::ExplicitCommandNoFallback,
                )
            }
            (None, None) => (
                kind.default_command().to_owned(),
                BootstrapPolicy::BuiltInCommandWithUploadFallback,
            ),
        };

        Ok(Self {
            kind,
            command,
            policy,
        })
    }

    pub(crate) fn allows_upload_fallback(&self) -> bool {
        self.policy.allows_upload()
    }
}

impl BootstrapPolicy {
    pub(crate) fn allows_upload(self) -> bool {
        matches!(
            self,
            Self::BuiltInCommandWithUploadFallback | Self::ExplicitUploadAllowed
        )
    }
}

pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
pub(crate) fn effective_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    agent_command_plan(agent_command, agent_path).map(|plan| plan.command)
}

#[cfg(test)]
fn effective_quic_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    remote_helper_command_plan(agent_command, agent_path, HelperKind::QuicAgent)
        .map(|plan| plan.command)
}

#[cfg(test)]
fn effective_quic_bridge_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    remote_helper_command_plan(agent_command, agent_path, HelperKind::QuicBridgeNative)
        .map(|plan| plan.command)
}

#[cfg(test)]
pub(crate) fn effective_bridge_agent_command(
    transport: BridgeTransportKind,
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    match HelperKind::for_bridge_transport(transport) {
        HelperKind::QuicAgent => effective_quic_agent_command(agent_command, agent_path),
        HelperKind::QuicBridgeNative => {
            effective_quic_bridge_agent_command(agent_command, agent_path)
        }
        HelperKind::StdioAgent => effective_agent_command(agent_command, agent_path),
    }
}

pub(crate) fn agent_command_plan(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<HelperCommandPlan> {
    remote_helper_command_plan(agent_command, agent_path, HelperKind::StdioAgent)
}

pub(crate) fn bridge_agent_command_plan(
    transport: BridgeTransportKind,
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<HelperCommandPlan> {
    remote_helper_command_plan(
        agent_command,
        agent_path,
        HelperKind::for_bridge_transport(transport),
    )
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
        agent: remote_helper_command_plan(None, agent_path, HelperKind::StdioAgent)?,
        quic_native: remote_helper_command_plan(None, agent_path, HelperKind::QuicBridgeNative)?,
    })
}

fn remote_helper_command_plan(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
    helper: HelperKind,
) -> Result<HelperCommandPlan> {
    HelperCommandPlan::from_command_options(helper, agent_command, agent_path)
}

pub(super) fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_command_plan_resolves_effective_commands() {
        let cases = [
            (
                HelperKind::StdioAgent,
                DEFAULT_AGENT_COMMAND,
                "'/tmp/rustle dir/rustle'\\''bin' agent",
            ),
            (
                HelperKind::QuicAgent,
                DEFAULT_QUIC_AGENT_COMMAND,
                "'/tmp/rustle dir/rustle'\\''bin' quic-agent",
            ),
            (
                HelperKind::QuicBridgeNative,
                DEFAULT_QUIC_BRIDGE_AGENT_COMMAND,
                "'/tmp/rustle dir/rustle'\\''bin' quic-bridge-agent",
            ),
        ];

        for (kind, default_command, path_command) in cases {
            assert_eq!(
                HelperCommandPlan::from_command_options(kind, None, None)
                    .expect("default command")
                    .command,
                default_command,
            );
            assert_eq!(
                HelperCommandPlan::from_command_options(
                    kind,
                    None,
                    Some("/tmp/rustle dir/rustle'bin"),
                )
                .expect("explicit path")
                .command,
                path_command,
            );
        }

        assert_eq!(
            HelperCommandPlan::from_command_options(
                HelperKind::StdioAgent,
                Some("/opt/rustle quic-agent"),
                None,
            )
            .expect("explicit command")
            .command,
            "/opt/rustle quic-agent",
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

    #[test]
    fn helper_command_plan_assigns_bootstrap_policy() {
        assert_eq!(
            HelperCommandPlan::from_command_options(HelperKind::StdioAgent, None, None)
                .expect("default policy")
                .policy,
            BootstrapPolicy::BuiltInCommandWithUploadFallback,
        );
        assert_eq!(
            HelperCommandPlan::from_command_options(
                HelperKind::StdioAgent,
                Some("rustle agent"),
                None,
            )
            .expect("explicit command policy")
            .policy,
            BootstrapPolicy::ExplicitCommandNoFallback,
        );
        assert_eq!(
            HelperCommandPlan::from_command_options(
                HelperKind::StdioAgent,
                None,
                Some("/tmp/rustle"),
            )
            .expect("explicit path policy")
            .policy,
            BootstrapPolicy::ExplicitCommandNoFallback,
        );
    }

    #[test]
    fn helper_command_plan_controls_upload_fallback() {
        let built_in = HelperCommandPlan::from_command_options(HelperKind::StdioAgent, None, None)
            .expect("built-in command plan");
        assert!(built_in.allows_upload_fallback());
        assert!(built_in.policy.allows_upload());

        let explicit_command = HelperCommandPlan::from_command_options(
            HelperKind::QuicAgent,
            Some("custom quic-agent"),
            None,
        )
        .expect("explicit command plan");
        assert!(!explicit_command.allows_upload_fallback());
        assert!(!explicit_command.policy.allows_upload());

        let explicit_path = HelperCommandPlan::from_command_options(
            HelperKind::QuicBridgeNative,
            None,
            Some("/tmp/rustle"),
        )
        .expect("explicit path plan");
        assert!(!explicit_path.allows_upload_fallback());
        assert!(!explicit_path.policy.allows_upload());

        let explicit_upload = HelperCommandPlan {
            kind: HelperKind::StdioAgent,
            command: "custom rustle agent".to_owned(),
            policy: BootstrapPolicy::ExplicitUploadAllowed,
        };
        assert!(explicit_upload.allows_upload_fallback());
        assert!(explicit_upload.policy.allows_upload());
    }

    #[test]
    fn helper_command_plan_validates_command_options() {
        assert!(
            HelperCommandPlan::from_command_options(HelperKind::StdioAgent, Some(" "), None)
                .is_err()
        );
        assert!(
            HelperCommandPlan::from_command_options(HelperKind::StdioAgent, None, Some(" "))
                .is_err()
        );
        assert!(HelperCommandPlan::from_command_options(
            HelperKind::StdioAgent,
            Some("rustle agent"),
            Some("/tmp/rustle"),
        )
        .is_err());
    }

    #[test]
    fn shell_quote_uses_single_quote_safe_form() {
        assert_eq!(shell_quote("/tmp/rustle-agent"), "'/tmp/rustle-agent'");
        assert_eq!(shell_quote("/tmp/rustle'agent"), "'/tmp/rustle'\\''agent'");
    }

    #[test]
    fn effective_agent_command_quotes_literal_agent_path() {
        assert_eq!(
            effective_agent_command(None, None).expect("default agent command"),
            DEFAULT_AGENT_COMMAND
        );
        assert_eq!(
            effective_agent_command(Some("/tmp/rustle agent"), None)
                .expect("raw command stays raw"),
            "/tmp/rustle agent"
        );
        assert_eq!(
            effective_agent_command(None, Some("/tmp/rustle dir/rustle'bin"))
                .expect("path command is quoted"),
            "'/tmp/rustle dir/rustle'\\''bin' agent"
        );
        assert!(effective_agent_command(Some(" "), None).is_err());
        assert!(effective_agent_command(None, Some(" ")).is_err());
        assert!(effective_agent_command(Some("rustle agent"), Some("/tmp/rustle")).is_err());
    }

    #[test]
    fn powershell_quote_uses_single_quote_safe_form() {
        assert_eq!(
            powershell_quote("C:\\Temp\\rustle.exe"),
            "'C:\\Temp\\rustle.exe'"
        );
        assert_eq!(
            powershell_quote("C:\\Temp\\rustle'agent.exe"),
            "'C:\\Temp\\rustle''agent.exe'"
        );
    }
}
