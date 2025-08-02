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

    /*for key in [
        format!("InitiatorName={}\0", cfg.login.security.initiator_name),
        format!("InitiatorAlias={}\0", cfg.login.security.initiator_alias),
        format!("TargetName={}\0", cfg.login.security.target_name),
        format!("SessionType={}\0", cfg.login.security.session_type),
        format!("HeaderDigest={}\0", cfg.login.negotiation.header_digest),
        format!("DataDigest={}\0", cfg.login.negotiation.data_digest),
        format!(
            "DefaultTime2Wait={}\0",
            cfg.extra_data.r2t.default_time2wait
        ),
        format!(
            "DefaultTime2Retain={}\0",
            cfg.extra_data.r2t.default_time2retain
        ),
        format!("IFMarker={}\0", cfg.extra_data.markers.if_marker),
        format!("OFMarker={}\0", cfg.extra_data.markers.of_marker),
        format!(
            "ErrorRecoveryLevel={}\0",
            cfg.login.negotiation.error_recovery_level
        ),
        format!("InitialR2T={}\0", cfg.extra_data.r2t.initial_r2t),
        format!("ImmediateData={}\0", cfg.extra_data.r2t.immediate_data),
        format!(
            "MaxBurstLength={}\0",
            cfg.login.negotiation.max_burst_length
        ),
        format!(
            "FirstBurstLength={}\0",
            cfg.login.negotiation.first_burst_length
        ),
        format!(
            "MaxOutstandingR2T={}\0",
            cfg.extra_data.r2t.max_outstanding_r2t
        ),
        format!(
            "MaxConnections={}\0",
            cfg.extra_data.connections.max_connections
        ),
        format!(
            "DataPDUInOrder={}\0",
            cfg.login.negotiation.data_pdu_in_order
        ),
        format!(
            "DataSequenceInOrder={}\0",
            cfg.login.negotiation.data_sequence_in_order
        ),
        format!(
            "MaxRecvDataSegmentLength={}\0",
            cfg.login.negotiation.max_recv_data_segment_length
        ),
    ] {
        builder = builder.append_data(key.into_bytes());
    }*/

    info!("{:?}", builder.header);

    let itt = builder.header.get_initiator_task_tag();

    conn.send_request(itt, builder).await?;

    match conn.read_response(itt).await? {
        Pdu::LoginResponse(rsp) => Ok(rsp),
        other => bail!("got unexpected PDU: {:?}", other.get_opcode()),
    }
}
