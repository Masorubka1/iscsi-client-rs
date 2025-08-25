// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Result, bail};

use crate::{
    client::client::Connection,
    models::{
        data_fromat::PDUWithData,
        nop::{
            request::{NopOutRequest, NopOutRequestBuilder},
            response::NopInResponse,
        },
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
) -> Result<PDUWithData<NopInResponse>> {
    let sn = cmd_sn.load(Ordering::SeqCst);
    let esn = exp_stat_sn.fetch_add(1, Ordering::SeqCst);
    let itt = initiator_task_tag.fetch_add(1, Ordering::SeqCst);

    let header = NopOutRequestBuilder::new()
        .cmd_sn(sn)
        .lun(&lun)
        .initiator_task_tag(itt)
        .target_task_tag(target_task_tag)
        .exp_stat_sn(esn)
        .immediate();

    let builder: PDUWithData<NopOutRequest> = PDUWithData::from_header(header.header);

    conn.send_request(itt, builder).await?;

    match conn.read_response::<NopInResponse>(itt).await {
        Ok(rsp) => Ok(rsp),
        Err(other) => bail!("got unexpected PDU: {:?}", other.to_string()),
    }
}
