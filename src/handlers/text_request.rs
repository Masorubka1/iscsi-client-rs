use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Result, bail};
use tracing::info;

use crate::{
    client::client::{Connection, PduResponse},
    models::{
        common::Builder,
        text::{
            request::{TextRequest, TextRequestBuilder},
            response::TextResponse,
        },
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
) -> Result<(TextResponse, String, Option<u32>)> {
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
        hex::encode(&builder.data)
    );

    let response = conn
        .call::<{ TextRequest::HEADER_LEN }, TextResponse>(builder)
        .await?;

    match response {
        PduResponse::Normal((hdr, data, dig)) => {
            exp_stat_sn.store(hdr.stat_sn.wrapping_add(1), Ordering::SeqCst);

            Ok((hdr, String::from_utf8(data)?, dig))
        },
        PduResponse::Reject((rej, data, _dig)) => {
            bail!("Text request rejected: {:?}\n  data: {:x?}", rej, data)
        },
    }
}
