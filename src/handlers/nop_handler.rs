use anyhow::{Result, bail};

use crate::{
    client::client::{Connection, PduResponse},
    models::nop::request_response::{NopInOut, NopOutRequestBuilder},
};

/// Send a NOP-Out to the target (with optional “ping”) and await the
/// corresponding NOP-In.
pub async fn send_nop(
    conn: &Connection,
    lun: [u8; 8],
    initiator_task_tag: u32,
    target_task_tag: u32,
    cmd_sn: u32,
    exp_stat_sn: u32,
    ping: bool, // if true, set the I bit in NOP-Out
) -> Result<(NopInOut, Vec<u8>, Option<u32>)> {
    let mut builder =
        NopOutRequestBuilder::new(lun, initiator_task_tag, target_task_tag, exp_stat_sn)
            .cmd_sn(cmd_sn)
            .exp_stat_sn(exp_stat_sn);

    if ping {
        builder = builder.ping();
    }

    match conn.call::<_, NopInOut>(builder).await? {
        PduResponse::Normal((hdr, data, _dig)) => Ok((hdr, data, _dig)),
        PduResponse::Reject((hdr, data, _dig)) => {
            bail!("Error_resp: {:?}\n Data: {:?}", hdr, data)
        },
    }
}
