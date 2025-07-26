use anyhow::{Result, bail};

use crate::{
    cfg::config::{Config, ToLoginKeys},
    client::client::{Connection, PduResponse},
    models::{
        common::Builder,
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
) -> Result<LoginResponse> {
    // 1) Full-Feature transition: CSG=Operational(1) → NSG=FullFeature(3)
    let mut req1 = LoginRequestBuilder::new(isid, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .connection_id(1)
        .versions(
            cfg.login.negotiation.version_min,
            cfg.login.negotiation.version_max,
        );

    for key in cfg
        .login
        .to_login_keys()
        .into_iter()
        .chain(cfg.extra_data.to_login_keys())
    {
        req1 = req1.append_data(key.into_bytes());
    }

    let (hdr, _data, _dig) = match conn
        .call::<{ LoginRequest::HEADER_LEN }, LoginResponse>(req1)
        .await?
    {
        PduResponse::Normal((hdr, data, _dig)) => (hdr, data, _dig),
        PduResponse::Reject((hdr, data, _dig)) => {
            bail!("Error_resp: {:?}\n Data: {:?}", hdr, data)
        },
    };

    Ok(hdr)
}
