use anyhow::{bail, Result};
use russh::client::Handle;

use crate::ssh_control::{connect_prepared_ssh, Client, PreparedSshConnection};
use crate::transport_model::BridgeTransportKind;

mod upload;

use upload::stage_uploaded_helper_command;
pub(crate) use upload::UploadedHelperCommand;

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

    fn sidecar_noun(self) -> &'static str {
        match self {
            Self::StdioAgent => "agent",
            Self::QuicAgent | Self::QuicBridgeNative => "helper",
        }
    }

    fn platform_probe_context(self) -> &'static str {
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
    pub(crate) policy: BootstrapPolicy,
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

pub(crate) struct BootstrappedHelper {
    pub(crate) handle: Handle<Client>,
    pub(crate) helper: UploadedHelperCommand,
}

pub(crate) async fn bootstrap_helper(
    prepared: &PreparedSshConnection,
    plan: &HelperCommandPlan,
) -> Result<BootstrappedHelper> {
    if !plan.policy.allows_upload() {
        bail!(
            "{}: upload bootstrap is not allowed for this helper startup policy",
            plan.kind.controller_log_prefix()
        );
    }
    let handle = connect_prepared_ssh(prepared).await?;
    let helper = stage_uploaded_helper_command(&handle, plan.kind).await?;
    Ok(BootstrappedHelper { handle, helper })
}

pub(crate) fn shell_quote(value: &str) -> String {
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

fn remote_helper_command_plan(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
    helper: HelperKind,
) -> Result<HelperCommandPlan> {
    HelperCommandPlan::from_command_options(helper, agent_command, agent_path)
}

pub(crate) fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
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
