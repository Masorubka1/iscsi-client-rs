use anyhow::Result;

use crate::{
    cfg::config::{Config, ToLoginKeys},
    client::client::Connection,
    models::login::{
        common::Stage, request::LoginRequestBuilder, response::LoginResponse,
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

    //println!("Req1: {req1:?}");

    for key in cfg
        .initiator
        .to_login_keys()
        .into_iter()
        .chain(cfg.target.to_login_keys())
        .chain(cfg.negotiation.to_login_keys())
        .chain(cfg.auth.to_login_keys())
        .chain(cfg.performance.to_login_keys())
    {
        req1 = req1.with_data(key.into_bytes());
    }
    req1 = req1.with_data(cfg.extra_text.clone().into_bytes());

    let (hdr1, _data1, _dig1): (LoginResponse, _, _) =
        conn.call::<_, LoginResponse>(req1).await?;

    //println!("Res1: {hdr1:?}");

    // 2) Full-Feature transition: CSG=Operational(1) → NSG=FullFeature(3)
    /*let req2 = LoginRequestBuilder::new(cfg.initiator.isid, hdr1.tsih)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(hdr1.version_max, hdr1.version_active)
        .connection_id(1)
        .task_tag(hdr1.initiator_task_tag)
        .cmd_sn(hdr1.exp_cmd_sn)
        .exp_stat_sn(hdr1.max_cmd_sn);

    let (hdr2, _data2, _dig2): (LoginResponse, _, _) =
        conn.call::<_, LoginResponse>(req2).await?;

    Ok(hdr2)*/
    Ok(hdr1)
}
