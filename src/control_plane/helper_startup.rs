use std::future::Future;

use anyhow::{bail, Context, Result};
use russh::client::Handle;

use crate::remote_helper::{bootstrap_helper, HelperCommandPlan, HelperKind};
use crate::ssh_control::{Client, PreparedSshConnection};

pub(super) async fn connect_helper_with_upload_fallback<T, PrimaryFut, UploadFn, UploadFut>(
    helper_plan: &HelperCommandPlan,
    primary: PrimaryFut,
    upload: UploadFn,
    helper_name: &str,
    upload_success_log: Option<&str>,
) -> Result<T>
where
    PrimaryFut: Future<Output = Result<T>>,
    UploadFn: FnOnce() -> UploadFut,
    UploadFut: Future<Output = Result<T>>,
{
    match primary.await {
        Ok(started) => Ok(started),
        Err(initial_err) => {
            if !helper_plan.allows_upload_fallback() {
                return Err(initial_err).with_context(|| {
                    format!(
                        "failed to start {helper_name} via explicit command: {}",
                        helper_plan.command
                    )
                });
            }

            let initial_err_detail = format!("{initial_err:#}");
            eprintln!(
                "{}: remote command failed ({initial_err_detail}); trying upload bootstrap",
                helper_plan.kind.controller_log_prefix()
            );
            match upload().await {
                Ok(started) => {
                    if let Some(message) = upload_success_log {
                        eprintln!("{message}");
                    }
                    Ok(started)
                }
                Err(bootstrap_err) => Err(bootstrap_err).with_context(|| {
                    format!(
                        "failed to start {helper_name} via command ({initial_err_detail}) or upload bootstrap"
                    )
                }),
            }
        }
    }
}

pub(super) async fn connect_uploaded_helper<T, ConnectFn, ConnectFut>(
    prepared: &PreparedSshConnection,
    helper_plan: &HelperCommandPlan,
    expected: HelperKind,
    connect: ConnectFn,
) -> Result<(T, String)>
where
    ConnectFn: FnOnce(Handle<Client>, String) -> ConnectFut,
    ConnectFut: Future<Output = Result<T>>,
{
    ensure_helper_plan_kind(helper_plan, expected)?;
    let started = bootstrap_helper(prepared, helper_plan).await?;
    let command = started.helper.command;
    let remote_path = started.helper.remote_path;
    let connected = connect(started.handle, command.clone())
        .await
        .with_context(|| expected.uploaded_start_context(&remote_path))?;
    Ok((connected, command))
}

fn ensure_helper_plan_kind(plan: &HelperCommandPlan, expected: HelperKind) -> Result<()> {
    if plan.kind != expected {
        bail!(
            "helper startup plan kind mismatch: expected {:?}, got {:?}",
            expected,
            plan.kind
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use anyhow::{anyhow, Result};

    use super::{connect_helper_with_upload_fallback, ensure_helper_plan_kind};
    use crate::remote_helper::{HelperCommandPlan, HelperKind};

    #[tokio::test]
    async fn primary_success_does_not_try_upload_fallback() {
        let plan = HelperCommandPlan::from_command_options(HelperKind::StdioAgent, None, None)
            .expect("built-in command plan");
        let upload_attempts = Arc::new(AtomicUsize::new(0));
        let upload_attempts_for_closure = Arc::clone(&upload_attempts);

        let result = connect_helper_with_upload_fallback(
            &plan,
            async { Ok::<_, anyhow::Error>("primary") },
            move || {
                upload_attempts_for_closure.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, anyhow::Error>("uploaded") }
            },
            "Rustle agent",
            None,
        )
        .await
        .expect("primary command success should return directly");

        assert_eq!(result, "primary");
        assert_eq!(upload_attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn explicit_command_failure_does_not_try_upload_fallback() {
        let plan = HelperCommandPlan::from_command_options(
            HelperKind::StdioAgent,
            Some("custom rustle agent"),
            None,
        )
        .expect("explicit command plan");
        let upload_attempts = Arc::new(AtomicUsize::new(0));
        let upload_attempts_for_closure = Arc::clone(&upload_attempts);

        let err = connect_helper_with_upload_fallback(
            &plan,
            async { Err::<(), _>(anyhow!("primary failed")) },
            move || {
                upload_attempts_for_closure.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, anyhow::Error>(()) }
            },
            "Rustle agent",
            None,
        )
        .await
        .expect_err("explicit command should fail closed");
        let detail = format!("{err:#}");

        assert_eq!(upload_attempts.load(Ordering::SeqCst), 0);
        assert!(detail
            .contains("failed to start Rustle agent via explicit command: custom rustle agent"));
        assert!(detail.contains("primary failed"));
    }

    #[tokio::test]
    async fn explicit_path_failure_does_not_try_upload_fallback() {
        let plan = HelperCommandPlan::from_command_options(
            HelperKind::StdioAgent,
            None,
            Some("/tmp/custom-rustle"),
        )
        .expect("explicit path plan");
        let upload_attempts = Arc::new(AtomicUsize::new(0));
        let upload_attempts_for_closure = Arc::clone(&upload_attempts);

        let err = connect_helper_with_upload_fallback(
            &plan,
            async { Err::<(), _>(anyhow!("primary failed")) },
            move || {
                upload_attempts_for_closure.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, anyhow::Error>(()) }
            },
            "Rustle agent",
            None,
        )
        .await
        .expect_err("explicit path should fail closed");
        let detail = format!("{err:#}");

        assert_eq!(upload_attempts.load(Ordering::SeqCst), 0);
        assert!(detail.contains("failed to start Rustle agent via explicit command: "));
        assert!(detail.contains("/tmp/custom-rustle"));
        assert!(detail.contains("primary failed"));
    }

    #[tokio::test]
    async fn built_in_command_uses_upload_fallback_after_primary_failure() {
        let plan = HelperCommandPlan::from_command_options(HelperKind::StdioAgent, None, None)
            .expect("built-in command plan");

        let result = connect_helper_with_upload_fallback(
            &plan,
            async { Err::<&'static str, _>(anyhow!("primary failed")) },
            || async { Ok::<_, anyhow::Error>("uploaded") },
            "Rustle agent",
            None,
        )
        .await
        .expect("built-in command should use upload fallback");

        assert_eq!(result, "uploaded");
    }

    #[tokio::test]
    async fn upload_failure_preserves_primary_error_context() {
        let plan = HelperCommandPlan::from_command_options(HelperKind::StdioAgent, None, None)
            .expect("built-in command plan");

        let err = connect_helper_with_upload_fallback(
            &plan,
            async { Err::<(), _>(anyhow!("primary failed")) },
            || async { Err::<(), _>(anyhow!("upload failed")) },
            "Rustle agent",
            None,
        )
        .await
        .expect_err("fallback failure should include both attempts");
        let detail = format!("{err:#}");

        assert!(detail.contains(
            "failed to start Rustle agent via command (primary failed) or upload bootstrap"
        ));
        assert!(detail.contains("upload failed"));
    }

    #[test]
    fn helper_plan_kind_mismatch_is_reported() -> Result<()> {
        let plan = HelperCommandPlan::from_command_options(HelperKind::QuicAgent, None, None)?;
        let err = ensure_helper_plan_kind(&plan, HelperKind::StdioAgent)
            .expect_err("mismatched helper kind should fail");
        let detail = format!("{err:#}");

        assert!(detail
            .contains("helper startup plan kind mismatch: expected StdioAgent, got QuicAgent"));
        Ok(())
    }
}
