use std::{
    sync::{Arc, atomic::AtomicU32},
    time::Duration,
};

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{config::AuthConfig, logger::init_logger},
    control_block::common::{build_read10, build_write10},
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_plain},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        write_states::{IssueCmd, WriteCtx, WriteStates, run_write},
    },
};
use tokio::time::sleep;

use crate::integration_tests::common::{
    connect_cfg, load_config, lun8, test_isid, test_path,
};

fn pick_lba_from_isid(isid: [u8; 6]) -> u32 {
    let s: u32 = isid.iter().map(|&b| b as u32).sum();
    4096 + (s % 1024)
}

#[tokio::test]
async fn read10_write10_read10_plain() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg = Arc::new(load_config()?);
    if !matches!(cfg.login.auth, AuthConfig::None) {
        eprintln!(
            "⏭️  skip: auth.method != none in TEST_CONFIG (этот тест только для \
             login_plain)"
        );
        return Ok(());
    }

    let conn = connect_cfg(&cfg).await?;
    let isid = test_isid();

    let mut lctx = LoginCtx::new(
        conn.clone(),
        &cfg,
        isid,
        /* cid= */ 1,
        /* tsih= */ 1,
    );
    let login_state: LoginStates = start_plain();
    let login_status = run_login(login_state, &mut lctx).await?;

    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun = lun8(1);

    const BLK: usize = 512;
    let blocks: u16 = 1;
    let lba: u32 = pick_lba_from_isid(isid);

    let mut cdb_rd1 = [0u8; 16];
    build_read10(&mut cdb_rd1, lba, blocks, 0, 0);
    let mut rctx1 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        (BLK * blocks as usize) as u32,
        cdb_rd1,
    );
    let rd1 = run_read(ReadStates::Start(ReadStart), &mut rctx1).await?;
    assert_eq!(rd1.data.len(), BLK);

    let mut cdb_wr = [0u8; 16];
    build_write10(&mut cdb_wr, lba, blocks, 0, 0);
    let payload = vec![0xA5u8; BLK];

    let mut wctx = WriteCtx::new(
        conn.clone(),
        cfg.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        cdb_wr,
        payload.clone(),
    );

    match run_write(WriteStates::IssueCmd(IssueCmd), &mut wctx).await {
        Ok(_) => {},
        Err(_) => {
            sleep(Duration::from_millis(100)).await;
            let mut wctx2 = WriteCtx { ..wctx };
            run_write(WriteStates::IssueCmd(IssueCmd), &mut wctx2).await?;
        },
    }

    let mut cdb_rd2 = [0u8; 16];
    build_read10(&mut cdb_rd2, lba, blocks, 0, 0);
    let mut rctx2 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        (BLK * blocks as usize) as u32,
        cdb_rd2,
    );
    let rd2 = run_read(ReadStates::Start(ReadStart), &mut rctx2).await?;
    assert_eq!(rd2.data, payload, "read data differs from what was written");

    Ok(())
}
