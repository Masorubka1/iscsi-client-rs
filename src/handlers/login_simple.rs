use anyhow::{Result, bail};

use crate::{
    cfg::config::{Config, ToLoginKeys},
    client::client::{Connection, PduResponse},
    models::{
        common::Builder,
        login::{common::Stage, request::LoginRequestBuilder, response::LoginResponse},
    },
};

/// Performs a plain-text login to the target by sending the initiator name and
/// requesting no authentication.
pub async fn login_plain(conn: &Connection, cfg: &Config) -> Result<LoginResponse> {
    // 1) Full-Feature transition: CSG=Operational(1) → NSG=FullFeature(3)
    let mut req1 = LoginRequestBuilder::new(cfg.initiator.isid, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .connection_id(1)
        .versions(cfg.negotiation.version_min, cfg.negotiation.version_max);

    for key in cfg
        .initiator
        .to_login_keys()
        .into_iter()
        .chain(cfg.target.to_login_keys())
        .chain(cfg.negotiation.to_login_keys())
        .chain(cfg.auth.to_login_keys())
        .chain(cfg.performance.to_login_keys())
    {
        req1 = req1.append_data(key.into_bytes());
    }
    req1 = req1.append_data(cfg.extra_text.clone().into_bytes());

    let (hdr, _data, _dig) = match conn.call::<_, LoginResponse>(req1).await? {
        PduResponse::Normal((hdr, data, _dig)) => (hdr, data, _dig),
        PduResponse::Reject((hdr, data, _dig)) => {
            bail!("Error_resp: {:?}\n Data: {:?}", hdr, data)
        },
    };

    Ok(hdr)
}
