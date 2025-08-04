use anyhow::{Result, bail};
use tracing::info;

use crate::{
    cfg::config::{Config, ToLoginKeys},
    client::client::Connection,
    models::{
        common::{BasicHeaderSegment, Builder},
        login::{common::Stage, request::LoginRequestBuilder, response::LoginResponse},
        parse::Pdu,
    },
};

/// Performs a plain-text login to the target by sending the initiator name and
/// requesting no authentication.
pub async fn login_plain(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
) -> Result<LoginResponse> {
    // 1) Full-Feature transition: CSG=Operational(1) → NSG=FullFeature(3)
    let mut builder = LoginRequestBuilder::new(isid, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(
            cfg.login.negotiation.version_min,
            cfg.login.negotiation.version_max,
        );

    for key in cfg.to_login_keys().into_iter() {
        builder = builder.append_data(key.into_bytes());
    }

    info!("{:?}", builder.header);

    let itt = builder.header.get_initiator_task_tag();

    conn.send_request(itt, builder).await?;

    match conn.read_response(itt).await? {
        Pdu::LoginResponse(rsp) => Ok(rsp),
        other => bail!("got unexpected PDU: {:?}", other.get_opcode()),
    }
}
