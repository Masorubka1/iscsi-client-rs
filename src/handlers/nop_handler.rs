use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Result, bail};
use tracing::info;

use crate::{
    client::client::Connection,
    models::{
        common::BasicHeaderSegment,
        nop::{request::NopOutRequestBuilder, response::NopInResponse},
        parse::Pdu,
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
) -> Result<NopInResponse> {
    let sn = cmd_sn.load(Ordering::SeqCst);
    let esn = exp_stat_sn.fetch_add(1, Ordering::SeqCst);
    let itt = initiator_task_tag.fetch_add(1, Ordering::SeqCst);

    let builder = NopOutRequestBuilder::new()
        .cmd_sn(sn)
        .lun(&lun)
        .initiator_task_tag(itt)
        .target_task_tag(target_task_tag)
        .exp_stat_sn(esn)
        .ping();

    info!("NOP-Out hdr={:?}", builder.header);

    let itt = builder.header.get_initiator_task_tag();

    conn.send_request(itt, builder).await?;

    match conn.read_response(itt).await? {
        Pdu::NopInResponse(rsp) => {
            exp_stat_sn.store(rsp.stat_sn.wrapping_add(1), Ordering::SeqCst);
            Ok(rsp)
        },
        other => bail!("got unexpected PDU: {:?}", other.get_opcode()),
    }
}
