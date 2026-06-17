use anyhow::{Context, Result};

use crate::cli::{AgentArgs, QuicAgentArgs, QuicBridgeAgentArgs};
use crate::{agent_runtime, quic_agent, quic_agent_runtime};

#[derive(Clone, Copy)]
struct QuicHelperRuntimeRole {
    encode_bootstrap: fn(&quic_agent::QuicAgentBootstrap) -> String,
    write_context: &'static str,
    flush_context: &'static str,
    listening_log_prefix: &'static str,
}

const QUIC_AGENT_RUNTIME_ROLE: QuicHelperRuntimeRole = QuicHelperRuntimeRole {
    encode_bootstrap: quic_agent::QuicAgentBootstrap::encode_line,
    write_context: "failed to write QUIC agent bootstrap line",
    flush_context: "failed to flush QUIC agent bootstrap line",
    listening_log_prefix: "quic-agent: listening on",
};

const QUIC_BRIDGE_RUNTIME_ROLE: QuicHelperRuntimeRole = QuicHelperRuntimeRole {
    encode_bootstrap: quic_agent::QuicAgentBootstrap::encode_bridge_line,
    write_context: "failed to write native QUIC bridge bootstrap line",
    flush_context: "failed to flush native QUIC bridge bootstrap line",
    listening_log_prefix: "quic-bridge-agent: listening on",
};

pub(crate) async fn run_agent(args: AgentArgs) -> Result<()> {
    agent_runtime::run_stdio(agent_runtime::AgentRuntimeConfig::new(args.mtu)).await
}

pub(crate) async fn run_quic_agent(args: QuicAgentArgs) -> Result<()> {
    let server = quic_agent::start_quic_agent_server(args.bind)?;
    write_quic_helper_bootstrap_to_stdout(server.bootstrap(), QUIC_AGENT_RUNTIME_ROLE)?;
    eprintln!(
        "{} {}",
        QUIC_AGENT_RUNTIME_ROLE.listening_log_prefix,
        server.local_addr()?
    );
    quic_agent_runtime::run_one(server, agent_runtime::AgentRuntimeConfig::new(args.mtu)).await
}

pub(crate) async fn run_quic_bridge_agent(args: QuicBridgeAgentArgs) -> Result<()> {
    let server = quic_agent::start_quic_bridge_server(args.bind)?;
    write_quic_helper_bootstrap_to_stdout(server.bootstrap(), QUIC_BRIDGE_RUNTIME_ROLE)?;
    eprintln!(
        "{} {}",
        QUIC_BRIDGE_RUNTIME_ROLE.listening_log_prefix,
        server.local_addr()?
    );
    server.run().await
}

fn write_quic_helper_bootstrap_to_stdout(
    bootstrap: &quic_agent::QuicAgentBootstrap,
    role: QuicHelperRuntimeRole,
) -> Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    write_quic_helper_bootstrap(&mut stdout, bootstrap, role)
}

fn write_quic_helper_bootstrap<W>(
    writer: &mut W,
    bootstrap: &quic_agent::QuicAgentBootstrap,
    role: QuicHelperRuntimeRole,
) -> Result<()>
where
    W: std::io::Write,
{
    writeln!(writer, "{}", (role.encode_bootstrap)(bootstrap)).context(role.write_context)?;
    writer.flush().context(role.flush_context)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    fn test_bootstrap(port: u16) -> quic_agent::QuicAgentBootstrap {
        let cert_der = vec![0, 1, 2, 0xfe, 0xff];
        quic_agent::QuicAgentBootstrap {
            port,
            cert_sha256: "103597c5abb6113da596c18e9d1da69364eafe00a2bfaa8b12e53c44bd6b0429"
                .to_owned(),
            cert_der,
            auth_token: vec![0x5a; 32],
        }
    }

    fn written_line(buffer: &[u8]) -> &str {
        std::str::from_utf8(buffer)
            .expect("bootstrap output is UTF-8")
            .trim_end_matches('\n')
    }

    #[test]
    fn quic_agent_runtime_bootstrap_writes_agent_magic() {
        let bootstrap = test_bootstrap(4433);
        let mut output = Vec::new();

        write_quic_helper_bootstrap(&mut output, &bootstrap, QUIC_AGENT_RUNTIME_ROLE)
            .expect("write agent bootstrap");
        let decoded = quic_agent::QuicAgentBootstrap::decode_line(written_line(&output))
            .expect("decode agent bootstrap line");

        assert_eq!(decoded, bootstrap);
        assert!(quic_agent::QuicAgentBootstrap::decode_bridge_line(written_line(&output)).is_err());
    }

    #[test]
    fn quic_bridge_runtime_bootstrap_writes_bridge_magic() {
        let bootstrap = test_bootstrap(4434);
        let mut output = Vec::new();

        write_quic_helper_bootstrap(&mut output, &bootstrap, QUIC_BRIDGE_RUNTIME_ROLE)
            .expect("write bridge bootstrap");
        let decoded = quic_agent::QuicAgentBootstrap::decode_bridge_line(written_line(&output))
            .expect("decode bridge bootstrap line");

        assert_eq!(decoded, bootstrap);
        assert!(quic_agent::QuicAgentBootstrap::decode_line(written_line(&output)).is_err());
    }

    #[test]
    fn bootstrap_writer_reports_role_specific_write_context() {
        let bootstrap = test_bootstrap(4433);
        let mut writer = FailingWriter { fail_flush: false };

        let err = write_quic_helper_bootstrap(&mut writer, &bootstrap, QUIC_AGENT_RUNTIME_ROLE)
            .expect_err("write failure should be reported");
        let detail = format!("{err:#}");

        assert!(detail.contains("failed to write QUIC agent bootstrap line"));
        assert!(detail.contains("injected write failure"));
    }

    #[test]
    fn bootstrap_writer_reports_role_specific_flush_context() {
        let bootstrap = test_bootstrap(4434);
        let mut writer = FailingWriter { fail_flush: true };

        let err = write_quic_helper_bootstrap(&mut writer, &bootstrap, QUIC_BRIDGE_RUNTIME_ROLE)
            .expect_err("flush failure should be reported");
        let detail = format!("{err:#}");

        assert!(detail.contains("failed to flush native QUIC bridge bootstrap line"));
        assert!(detail.contains("injected flush failure"));
    }

    struct FailingWriter {
        fail_flush: bool,
    }

    impl io::Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_flush {
                Ok(buf.len())
            } else {
                Err(io::Error::other("injected write failure"))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("injected flush failure"))
            } else {
                Ok(())
            }
        }
    }
}
