use anyhow::{bail, Result};
use russh::client::Handle;

use crate::ssh_control::{connect_prepared_ssh, Client, PreparedSshConnection};

use super::command::HelperCommandPlan;
use super::upload::{stage_uploaded_helper_command, UploadedHelperCommand};

pub(crate) struct BootstrappedHelper {
    handle: Handle<Client>,
    helper: UploadedHelperCommand,
}

impl BootstrappedHelper {
    pub(crate) fn into_connect_parts(self) -> (Handle<Client>, String, String) {
        let command = self.helper.command;
        let remote_path = self.helper.remote_path;
        (self.handle, command, remote_path)
    }
}

pub(crate) async fn bootstrap_helper(
    prepared: &PreparedSshConnection,
    plan: &HelperCommandPlan,
) -> Result<BootstrappedHelper> {
    if !plan.allows_upload_fallback() {
        bail!(
            "{}: upload bootstrap is not allowed for this helper startup policy",
            plan.kind.controller_log_prefix()
        );
    }
    let handle = connect_prepared_ssh(prepared).await?;
    let helper = stage_uploaded_helper_command(&handle, plan.kind).await?;
    Ok(BootstrappedHelper { handle, helper })
}
