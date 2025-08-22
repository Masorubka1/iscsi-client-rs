// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};

use crate::{
    cfg::config::{Config, ToLoginKeys},
    client::client::Connection,
    models::{
        common::{BasicHeaderSegment, Builder},
        data_fromat::PDUWithData,
        login::{
            common::Stage,
            request::{LoginRequest, LoginRequestBuilder},
            response::LoginResponse,
        },
    },
};

/// Performs a plain-text login to the target by sending the initiator name and
/// requesting no authentication.
pub async fn login_plain(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
) -> Result<PDUWithData<LoginResponse>> {
    // 1) Full-Feature transition: CSG=Operational(1) → NSG=FullFeature(3)
    let header = LoginRequestBuilder::new(isid, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(
            cfg.login.negotiation.version_min,
            cfg.login.negotiation.version_max,
        );

    let mut builder: PDUWithData<LoginRequest> = PDUWithData::from_header(header.header);

    for key in cfg.to_login_keys().into_iter() {
        builder.append_data(key.into_bytes());
    }

    //info!("{:?}", builder.header);

    let itt = builder.header.get_initiator_task_tag();

    conn.send_request(itt, builder).await?;

    match conn.read_response::<LoginResponse>(itt).await {
        Ok(rsp) => Ok(rsp),
        Err(other) => bail!("got unexpected PDU: {:?}", other.to_string()),
    }
}
