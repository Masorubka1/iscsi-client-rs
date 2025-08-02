use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Result, bail};
use tracing::info;

use crate::{
    client::client::Connection,
    models::{
        common::{BasicHeaderSegment, Builder},
        parse::Pdu,
        text::{request::TextRequestBuilder, response::TextResponse},
    },
};

/// Send one or more key=value pairs in a Text Request PDU,
/// driving cmd_sn and exp_stat_sn from atomics, and await a Text Response.
pub async fn send_text(
    conn: &Connection,
    lun: [u8; 8],
    initiator_task_tag: &AtomicU32,
    target_task_tag: u32,
    cmd_sn: &AtomicU32,
    exp_stat_sn: &AtomicU32,
) -> Result<TextResponse> {
    let sn = cmd_sn.fetch_add(1, Ordering::SeqCst);
    let esn = exp_stat_sn.load(Ordering::SeqCst);
    let itt = initiator_task_tag.fetch_add(1, Ordering::SeqCst);

    let builder = TextRequestBuilder::new()
        .final_bit()
        .lun(&lun)
        .initiator_task_tag(itt)
        .target_task_tag(target_task_tag)
        .cmd_sn(sn)
        .exp_stat_sn(esn)
        .append_data(b"ErrorRecoveryLevel=0".to_vec());

    info!(
        "TextRequest hdr={:?} data={}",
        builder.header,
        hex::encode(&builder.header.data)
    );

    let itt = builder.header.get_initiator_task_tag();

    conn.send_request(itt, builder).await?;

    match conn.read_response(itt).await? {
        Pdu::TextResponse(rsp) => {
            exp_stat_sn.store(rsp.stat_sn.wrapping_add(1), Ordering::SeqCst);
            Ok(rsp)
        },
        other => bail!("got unexpected PDU: {:?}", other.get_opcode()),
    }
}
