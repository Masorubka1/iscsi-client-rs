// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Result, bail};

use crate::{
    client::client::ClientConnection,
    models::{
        common::{BasicHeaderSegment, Builder, HEADER_LEN},
        data_fromat::PDUWithData,
        text::{
            request::{TextRequest, TextRequestBuilder},
            response::TextResponse,
        },
    },
};

/// Send one or more key=value pairs in a Text Request PDU,
/// driving cmd_sn and exp_stat_sn from atomics, and await a Text Response.
pub async fn send_text(
    conn: &ClientConnection,
    lun: u64,
    initiator_task_tag: &AtomicU32,
    target_task_tag: u32,
    cmd_sn: &AtomicU32,
    exp_stat_sn: &AtomicU32,
) -> Result<PDUWithData<TextResponse>> {
    let sn = cmd_sn.load(Ordering::SeqCst);
    let esn = exp_stat_sn.load(Ordering::SeqCst);
    let itt = initiator_task_tag.fetch_add(1, Ordering::SeqCst);

    let header = TextRequestBuilder::new()
        .immediate()
        .lun(lun)
        .initiator_task_tag(itt)
        .target_task_tag(target_task_tag)
        .cmd_sn(sn)
        .exp_stat_sn(esn);
    let mut buf = [0u8; HEADER_LEN];
    header.header.to_bhs_bytes(&mut buf)?;

    let mut builder: PDUWithData<TextRequest> =
        PDUWithData::from_header_slice(buf, &conn.cfg);

    builder.append_data(b"X-Ping=1\0".as_slice());

    /*info!(
        "TextRequest hdr={:?} data={}",
        builder.header,
        hex::encode(&builder.data)
    );*/

    let header = builder.header_view()?;
    let itt = header.get_initiator_task_tag();

    conn.send_request(itt, builder).await?;

    match conn.read_response::<TextResponse>(itt).await {
        Ok(rsp) => {
            let header = rsp.header_view()?;
            exp_stat_sn.store(header.stat_sn.get().wrapping_add(1), Ordering::SeqCst);
            Ok(rsp)
        },
        Err(other) => bail!("got unexpected PDU: {:?}", other.to_string()),
    }
}
