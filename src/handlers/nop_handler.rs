use anyhow::{Result, bail};
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::info;

use crate::{
    client::client::{Connection, PduResponse},
    models::nop::{
        request::{NopOutRequest, NopOutRequestBuilder},
        response::NopInResponse,
    },
};

/// Send a NOP-Out to the target (with optional “ping”) and await the
/// corresponding NOP-In, driving the cmd_sn / exp_stat_sn / itt from atomics.
pub async fn send_nop(
    conn: &Connection,
    lun: [u8; 8],
    initiator_task_tag: &AtomicU32,
    target_task_tag: u32,
    cmd_sn: &AtomicU32,
    exp_stat_sn: &AtomicU32,
) -> Result<(NopInResponse, String, Option<u32>)> {
    let sn = cmd_sn.fetch_add(1, Ordering::SeqCst);
    let esn = exp_stat_sn.load(Ordering::SeqCst);
    let itt = initiator_task_tag.fetch_add(1, Ordering::SeqCst);

    let builder = NopOutRequestBuilder::new()
        .cmd_sn(sn)
        .lun(&lun)
        .initiator_task_tag(itt)
        .target_task_tag(target_task_tag)
        .exp_stat_sn(esn)
        .ping();

    info!(
        "NOP-Out hdr={:?} data={}",
        builder.header,
        hex::encode(&builder.data)
    );

    match conn
        .call::<{ NopOutRequest::HEADER_LEN }, NopInResponse>(builder)
        .await?
    {
        PduResponse::Normal((hdr, data, _dig)) => {
            exp_stat_sn.store(hdr.stat_sn.wrapping_add(1), Ordering::SeqCst);
            Ok((hdr, String::from_utf8(data)?, _dig))
        },
        PduResponse::Reject((hdr, data, _dig)) => {
            bail!("NOP-Out rejected: {:?}\n  data: {:x?}", hdr, data)
        },
    }
}
