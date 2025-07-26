use anyhow::{Result, bail};

use crate::{
    cfg::config::Config,
    client::client::{Connection, PduResponse},
    models::{
        common::Builder,
        text::{
            request::{TextRequest, TextRequestBuilder},
            response::TextResponse,
        },
    },
};

/// Отправляет один или несколько ключ=значение в виде Text Request PDU
/// и ждёт Text Response. В случае Reject вернёт ошибку.
pub async fn text_request(
    conn: &Connection,
    _cfg: &Config,
    lun: [u8; 8],
    initiator_task_tag: u32,
    target_task_tag: u32,
    exp_stat_sn: u32,
) -> Result<TextResponse> {
    let builder =
        TextRequestBuilder::new(lun, initiator_task_tag, target_task_tag, exp_stat_sn)
            .final_bit()
            .append_data("SendTargets=All".as_bytes().to_vec());

    println!("  left: {:?}", builder.header);

    let response = conn
        .call::<{ TextRequest::HEADER_LEN }, TextResponse>(builder)
        .await?;

    match response {
        PduResponse::Normal((hdr, _data, _dig)) => Ok(hdr),
        PduResponse::Reject((rej, _data, _dig)) => {
            bail!("Text request was rejected by target: {:?}", rej.reason)
        },
    }
}
