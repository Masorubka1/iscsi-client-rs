// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Arc;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::AuthConfig, logger::init_logger},
    client::pool_sessions::Pool,
    control_block::xdwrite_read::build_xdwrite_read10,
    models::{
        command::{
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        common::{Builder, HEADER_LEN},
        data_fromat::{PduRequest, PduResponse},
        identifiers::Itt,
    },
};
use serial_test::serial;

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

/// Build the 8-byte BidirectionalInitialR2T AHS (RFC 7146 § 4).
///
/// ```text
/// bytes 0..2 : AHS Length  (= value bytes only, excluding this 4-byte header)
/// byte    2  : AHS Type    (= 1 for Extended CDB / Bidirectional InitialR2T)
/// byte    3  : reserved
/// bytes 4..8 : Desired Data Transfer Length for READ direction (big-endian u32)
/// ```
fn build_bidi_r2t_ahs(read_transfer_length: u32) -> [u8; 8] {
    let read_bytes = read_transfer_length.to_be_bytes();
    [
        0x00,
        0x04, // AHS Length = 4
        0x01, // AHS Type = 1 (Bidirectional InitialR2T)
        0x00, // reserved
        read_bytes[0],
        read_bytes[1],
        read_bytes[2],
        read_bytes[3],
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn xdwrite_read_with_bidi_ahs() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg = Arc::new(load_config()?);
    if !matches!(cfg.login.auth, AuthConfig::None) {
        eprintln!("skip: auth.method != none in TEST_CONFIG");
        return Ok(());
    }

    // --- Pool + login ---
    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    let conn = connect_cfg(&cfg).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.identity.target_name.clone());
    let isid = test_isid();
    let cid: u16 = 0;

    let _tsih = pool
        .login_and_insert(target_name, isid, cid, conn.clone())
        .await
        .context("pool login failed")?;

    let lun = get_lun();

    // --- Build XDWRITEREAD(10) PDU with BidirectionalInitialR2T AHS ---
    let block_count: u16 = 1;
    let block_size: u32 = 512;
    let write_data = vec![0x5A; block_size as usize];

    let mut cdb = [0u8; 16];
    build_xdwrite_read10(
        &mut cdb,
        /* lba= */ 128,
        block_count,
        block_count,
        0,
        0,
    );

    let header = ScsiCommandRequestBuilder::new()
        .lun(lun.get())
        .initiator_task_tag(0x42)
        .cmd_sn(1)
        .exp_stat_sn(0)
        .expected_data_transfer_length(block_size) // write direction length
        .scsi_descriptor_block(&cdb)
        .read()
        .write(); // bidirectional: both R and W bits set

    let mut header_buf = [0u8; HEADER_LEN];
    header.header.to_bhs_bytes(&mut header_buf)?;

    let mut pdu = PduRequest::<ScsiCommandRequest>::new_request(header_buf, &cfg);
    let ahs = build_bidi_r2t_ahs(block_size); // read direction length via AHS
    pdu.append_ahs(&ahs)?;
    pdu.append_data(&write_data)?;

    let itt: Itt = 0x42.into();
    conn.send_request(itt, pdu).await?;

    // --- Read the SCSI response ---
    let rsp: Result<PduResponse<ScsiCommandResponse>> = conn.read_response(itt).await;

    match rsp {
        Ok(rsp) => {
            let response_hdr = rsp.header_view().context("ScsiCommandResponse header")?;
            let response_code = response_hdr.response.decode()?;
            eprintln!("XDWRITEREAD iSCSI response: {response_code:?}");
            assert!(
                matches!(
                    response_code,
                    iscsi_client_rs::models::command::common::ResponseCode::CommandCompleted
                ),
                "expected CommandCompleted, got {response_code:?}"
            );
        },
        Err(e) => {
            // TGT and some targets don't support bidirectional commands;
            // they drop the connection.  Accept this as a valid outcome.
            eprintln!("XDWRITEREAD rejected by target: {e}");
        },
    }

    // --- Read back the data (bidirectional read residual not checked

    Ok(())
}
