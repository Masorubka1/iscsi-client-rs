// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    models::{
        common::{BasicHeaderSegment, Builder, HEADER_LEN},
        data_fromat::PduRequest,
        nop::request::{NopOutRequest, NopOutRequestBuilder},
    },
};

const AHS_DATA: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];

fn make_request(cfg: &Config) -> PduRequest<NopOutRequest> {
    let header = NopOutRequestBuilder::new().initiator_task_tag(42);
    let mut header_buf = [0u8; HEADER_LEN];
    header
        .header
        .to_bhs_bytes(&mut header_buf)
        .expect("valid NOP header");
    PduRequest::<NopOutRequest>::new_request(header_buf, cfg)
}

#[test]
fn append_ahs_sets_length_in_bhs() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;
    let mut pdu = make_request(&cfg);

    pdu.append_ahs(AHS_DATA)?;

    let ahs_len = pdu.header_view()?.get_ahs_length_bytes();
    assert_eq!(ahs_len, AHS_DATA.len());
    Ok(())
}

#[test]
fn append_ahs_empty_is_noop() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;
    let mut pdu = make_request(&cfg);

    pdu.append_ahs(&[])?;

    let ahs_len = pdu.header_view()?.get_ahs_length_bytes();
    assert_eq!(ahs_len, 0);
    Ok(())
}

#[test]
fn append_ahs_multiple_calls_accumulate() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;
    let mut pdu = make_request(&cfg);

    pdu.append_ahs(&AHS_DATA[..4])?;
    pdu.append_ahs(&AHS_DATA[4..])?;

    let ahs_len = pdu.header_view()?.get_ahs_length_bytes();
    assert_eq!(ahs_len, AHS_DATA.len());
    Ok(())
}

#[test]
fn cannot_append_ahs_after_data() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;
    let mut pdu = make_request(&cfg);

    pdu.append_data(b"payload")?;

    let err = pdu
        .append_ahs(AHS_DATA)
        .expect_err("AHS after data must fail");
    assert!(
        err.to_string().contains("cannot append AHS"),
        "expected AHS rejection, got: {err}"
    );
    Ok(())
}

#[test]
fn build_respects_ahs_layout() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;
    let mut pdu = make_request(&cfg);

    pdu.append_ahs(AHS_DATA)?;
    pdu.append_data(b"hello")?;

    let mrdsl = cfg.login.flow.max_recv_data_segment_length as usize;
    let (_hdr, body) = pdu.build(mrdsl)?;

    // Layout: [AHS][padAHS][DATA][padDATA]
    let ahs_pad = (4 - (AHS_DATA.len() % 4)) % 4;
    let data_pad = (4 - (b"hello".len() % 4)) % 4;

    assert_eq!(&body[..AHS_DATA.len()], AHS_DATA);
    assert_eq!(
        &body[AHS_DATA.len()..AHS_DATA.len() + ahs_pad],
        &[0u8; 3][..ahs_pad]
    );
    assert_eq!(
        &body[AHS_DATA.len() + ahs_pad..AHS_DATA.len() + ahs_pad + 5],
        b"hello"
    );
    assert_eq!(body.len(), AHS_DATA.len() + ahs_pad + 5 + data_pad);
    Ok(())
}

#[test]
fn ahs_can_be_written_after_data_if_data_was_empty() -> Result<()> {
    // append_data(&[]) transitions to Data phase, which blocks AHS.
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;
    let mut pdu = make_request(&cfg);

    pdu.append_data(&[])?;

    let err = pdu
        .append_ahs(AHS_DATA)
        .expect_err("AHS after empty data must fail");
    assert!(err.to_string().contains("cannot append AHS"));
    Ok(())
}
