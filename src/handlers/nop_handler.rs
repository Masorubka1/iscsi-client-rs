use anyhow::Result;

use crate::{
    client::client::Connection,
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
) -> Result<(NopInOut, Vec<u8>, Option<usize>)> {
    let mut builder =
        NopOutRequestBuilder::new(lun, initiator_task_tag, target_task_tag, exp_stat_sn)
            .cmd_sn(cmd_sn)
            .exp_stat_sn(exp_stat_sn);

    if ping {
        builder = builder.ping();
    }

    conn.call::<_, NopInOut>(builder).await
}
